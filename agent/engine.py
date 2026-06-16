"""
agent/engine.py — the v2 security engine.

Pipeline:
  discover (OpenAPI -> structured Surface)
    -> plan  (LLM brain picks sample values + priority per endpoint)
    -> attack (per-vuln-class plugins with EFFECT oracles, identity-aware)
    -> explain (LLM turns findings into plain language)
    -> report (founder-grade markdown + A-F grade)

Bounded by a request budget and scoped to the target host. Replaces the old
linear AgentLoop as the primary analysis path.
"""
from __future__ import annotations

import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from typing import List, Optional
from urllib.parse import urlparse

from extractors.parser import OpenAPIParser
from core.models import Identity, Endpoint, Request, Finding, Evidence, VulnClass, Severity, Confidence, Response
from core.context import RunContext
from core.surface import build_surface, baseline_body
from core.http import HttpClient
import attacks  # noqa: F401  (import registers all plugins)
from attacks.base import all_plugins, AttackContext
from agent.planner import Planner
from detection.explainer import Explainer
from agent.llm import brain_status
from reports.founder_report import FounderReport

_PRIORITY_RANK = {"high": 0, "medium": 1, "low": 2}


def _canon_key(key: str) -> str:
    """Normalise an endpoint key so {user_id}, {id} and /123 all compare equal."""
    parts = key.split(" ", 1)
    if len(parts) != 2:
        return key
    path = re.sub(r"\{[^}]+\}", "*", parts[1])
    path = re.sub(r"/\d+", "/*", path)
    return f"{parts[0]} {path}"


def _identities_from_config(cfg: Optional[list]) -> List[Identity]:
    ids = [Identity(name="anon", role="anonymous")]
    for c in (cfg or []):
        if not isinstance(c, dict):
            continue
        ids.append(Identity(
            name=c.get("name", "user"),
            role=c.get("role", "user"),
            headers=c.get("headers", {}) or {},
            cookies=c.get("cookies", {}) or {},
            owned_resource_ids=c.get("owned_resource_ids", {}) or {},
            description=c.get("description", ""),
        ))
    return ids


class SecurityEngine:
    def __init__(self, spec_url: str = "", description: str = "", base_url: str = "",
                 identities: Optional[list] = None, max_requests: int = 400,
                 crawl_ui: bool = False, max_pages: int = 20,
                 auth: Optional[dict] = None, auth_identities: Optional[list] = None,
                 cross_browser: Optional[list] = None,
                 resume_context: Optional[dict] = None,
                 allow_writes: bool = False, extra_hosts: Optional[list] = None,
                 max_llm_calls: int = 60, output_dir: str = ".", log=print):
        self.output_dir = output_dir or "."
        self.spec_url = spec_url or ""
        self.description = description or ""
        self.base_url = (base_url or "").rstrip("/")
        self.identities = _identities_from_config(identities)
        self.max_requests = max_requests
        self.crawl_ui = crawl_ui
        self.max_pages = max_pages
        self.auth = auth
        self.auth_identities = auth_identities or []
        self.cross_browser = cross_browser or []
        self.allow_writes = bool(allow_writes)
        self._artifacts = ""
        self.context = RunContext.from_dict(resume_context) if resume_context else RunContext()
        self.context.target = self.base_url
        self.context.description = self.description
        self.log = log
        # Scope = the target host plus any operator-declared extra hosts (e.g. a split api.* domain).
        host = urlparse(self.base_url).hostname
        hosts = {h for h in ([host] + list(extra_hosts or [])) if h}
        self.http = HttpClient(allowed_hosts=hosts or None)
        # Spec fetch is host-allowlisted too (SSRF guard) and may carry the primary identity's auth.
        spec_headers = {}
        for c in (identities or []):
            if isinstance(c, dict) and c.get("headers"):
                spec_headers = c["headers"]
                break
        self.parser = OpenAPIParser(allowed_hosts=hosts or None, headers=spec_headers)
        self.planner = Planner()
        self.explainer = Explainer()
        self._req_count = 0
        self._req_lock = threading.Lock()
        self._spec: dict = {}
        self._degraded: list = []   # human-readable notes on what could NOT be tested
        self._brain_ok = True       # LLM brain reachable? (probed at run start)
        self.auth_scheme = None     # AuthScheme: how the target authenticates (set during run)
        self._plan_canon: dict = {}  # canonical-key index of the planner output

    def _send(self, req, identity=None):
        # Hard budget enforced at the point of spend (atomic reserve-before-send), so a
        # single fan-out plugin can't blow past max_requests on a third-party target.
        with self._req_lock:
            if self._req_count >= self.max_requests:
                return Response(status=0, error="request budget exhausted")
            self._req_count += 1
        return self.http.send(req, identity)

    def _attack_endpoint(self, ep, plan, actors, plugins) -> list:
        """Run all applicable plugins on one endpoint, as each identity. Thread-safe."""
        out = []
        already = set()   # plugin names that already found a vuln here (skip for later identities)
        # Canonical-key fallback: the LLM may return a key that differs by trailing
        # slash / method case / templating — don't silently drop its sample_values.
        pinfo = plan.get(ep.key) or self._plan_canon.get(_canon_key(ep.key)) or {}
        # Consume the brain's targeting hint: run focused vuln classes first (still run all).
        focus = pinfo.get("focus") or []
        if focus:
            plugins = sorted(plugins, key=lambda p: 0 if p.name in focus else 1)
        sample_body = baseline_body(self._spec, ep)
        for actor in actors:
            if self._req_count >= self.max_requests:
                break
            ctx = AttackContext(
                endpoint=ep, identities=self.identities, send=self._send,
                sample_values=pinfo.get("sample_values", {}) or {},
                sample_body=sample_body, log=self.log, actor=actor,
                surface=getattr(self, "_endpoints", []),
                allow_writes=self.allow_writes, memory=self.context,
                auth_scheme=self.auth_scheme, foreign_ids=getattr(self, "_foreign_ids", {}))
            for plugin in plugins:
                if self._req_count >= self.max_requests:
                    break
                if not plugin.applies_to(ep) or plugin.name in already:
                    continue
                # identity-agnostic plugins (e.g. broken_auth) run once, as anon.
                if getattr(plugin, "identity_agnostic", False) and not actor.is_anonymous:
                    continue
                try:
                    res = plugin.run(ctx) or []
                except Exception as e:
                    self.log(f"   ⚠️ plugin '{plugin.name}' errored on {ep.key}: {e}")
                    res = []
                if res:
                    already.add(plugin.name)
                out.extend(res)
        return out

    # Well-known locations a spec is commonly served from.
    _SPEC_CANDIDATES = (
        "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
        "/v3/api-docs", "/v2/api-docs", "/api-docs", "/api/schema/", "/api/schema",
        "/swagger/v1/swagger.json", "/api/openapi.json", "/docs/openapi.json",
    )

    def _discover_spec(self) -> dict:
        """Probe well-known spec locations on the target (within scope). First valid wins."""
        for cand in self._SPEC_CANDIDATES:
            url = self.base_url + cand
            try:
                spec = self.parser.load_spec(url)
                if spec and spec.get("paths"):
                    self.spec_url = url
                    self.log(f"   auto-discovered spec at {cand}")
                    return spec
            except Exception:
                continue
        return {}

    def _probe_graphql(self, endpoints) -> None:
        """Detect a GraphQL endpoint (common on spec-less apps) and add it to the surface."""
        if any("graphql" in e.path_template.lower() for e in endpoints):
            return
        for path in ("/graphql", "/api/graphql", "/v1/graphql"):
            try:
                r = self._send(Request("POST", self.base_url + path,
                                       body={"query": "{__typename}"}, content_type="json",
                                       label="graphql-detect"))
            except Exception:
                continue
            if isinstance(r.body, dict) and ("data" in r.body or "errors" in r.body):
                endpoints.append(Endpoint(method="POST", path_template=path,
                                          base_url=self.base_url, source="shadow"))
                self.log(f"   detected GraphQL endpoint at {path}")
                return

    def run(self) -> dict:
        # 0. Brain liveness — surface (loudly) when the LLM is unreachable, so a
        #    deterministic-only run is never silently mistaken for a full one. This
        #    is the exact failure mode of a hardened systemd service whose user
        #    can't reach the machine's logged-in `claude` session.
        self._brain_ok, brain_reason = brain_status()
        if self._brain_ok:
            self.log(f"🧠 LLM brain online ({brain_reason}).")
        else:
            self.log(f"⚠️ LLM brain UNAVAILABLE ({brain_reason}) — running the 16 deterministic "
                     "detectors only: no AI target-planning, no plain-language explanations.")
            self._degraded.append(
                f"AI brain unavailable ({brain_reason}); ran the deterministic detectors only "
                "(no LLM target-planning, no plain-language explanations).")

        # 1. Discover the full surface from the OpenAPI spec.
        self.log(f"🔍 Discovering surface for {self.base_url} ...")
        if self.spec_url:
            try:
                self._spec = self.parser.load_spec(self.spec_url) or {}
            except Exception as e:
                self.log(f"⚠️ Spec load failed ({e}); continuing with empty surface.")
                self._degraded.append(f"OpenAPI spec could not be loaded ({e}); "
                                      "only UI-discovered endpoints (if any) were tested.")
                self._spec = {}
        else:
            # No spec given — try to auto-discover one before falling back to crawl-only.
            self._spec = self._discover_spec()
            if not self._spec:
                self._degraded.append("No OpenAPI spec was provided or auto-discovered; the API "
                                      "surface relies entirely on what the UI crawl observed.")
        endpoints = build_surface(self._spec, self.base_url)
        self.log(f"✅ {len(endpoints)} endpoint(s) discovered.")

        # 1b. QA crawl (optional): explore the UI like a human tester, find
        #     functional/UI bugs, and capture a shadow spec that grows the surface.
        qa_findings = self._run_qa(endpoints) if self.crawl_ui else []

        # 1b'. Detect a GraphQL endpoint even without a spec (single POST surface).
        self._probe_graphql(endpoints)

        # 1c. Build authenticated identities for the attack matrix (multi-role aware).
        #     Non-form schemes (bearer / api_key / header / session / token_exchange) resolve
        #     WITHOUT a browser — so JWT/API-key/mobile backends are testable behind login.
        #     Only true form logins fall back to the Playwright path.
        from core.auth_adapters import resolve_identity, needs_browser, scheme_for_identity, scheme_from_spec
        browser_cfgs = []
        for cfg in self.auth_identities:
            if not isinstance(cfg, dict):
                continue
            if needs_browser(cfg):
                browser_cfgs.append(cfg)
                continue
            idn = resolve_identity(cfg, self.base_url, http=self.http, log=self.log)
            if idn:
                self.identities.append(idn)
        if browser_cfgs:
            from qa.auth import capture_identities
            for idn in capture_identities(browser_cfgs, self.base_url, self.log):
                self.identities.append(idn)
        if not any(not i.is_anonymous for i in self.identities) and self.context.auth_cookies:
            self.identities.append(Identity(
                name="authenticated", role=self.context.auth_role or "user",
                cookies=dict(self.context.auth_cookies)))

        # Target auth scheme: prefer the spec's declared scheme, else infer from a live identity.
        self.auth_scheme = scheme_from_spec(self._spec)
        if self.auth_scheme is None:
            for i in self.identities:
                if not i.is_anonymous:
                    self.auth_scheme = scheme_for_identity(i)
                    break
        _authed = [f"{i.name}({i.role})" for i in self.identities if not i.is_anonymous]
        if _authed:
            self.log(f"🔑 Attacks will also run as: {', '.join(_authed)}")

        # 1d. Harvest real resource ids (additive) so IDOR/authz use concrete foreign ids
        #     and horizontal authz works without hand-supplied owned_resource_ids.
        self._foreign_ids = {}
        try:
            from core.discovery import harvest_resources
            self._foreign_ids = harvest_resources(endpoints, self.identities, self._send, self.log)
            # Memory write-back (single-threaded, pre-matrix): feed discovered ids to the planner
            # and into the resumable run context.
            for rtype, ids in self._foreign_ids.items():
                for rid in ids:
                    self.context.add_entity(rtype, rid)
        except Exception as e:
            self.log(f"   resource harvest skipped: {e}")

        # 2. Plan (LLM brain): sample values + priority — informed by QA-crawl memory.
        plan = self.planner.plan(self.description, endpoints, memory=self.context.brief())
        self._plan_canon = {_canon_key(k): v for k, v in (plan or {}).items()}
        endpoints.sort(key=lambda e: _PRIORITY_RANK.get(
            (plan.get(e.key) or self._plan_canon.get(_canon_key(e.key)) or {}).get("priority", "medium"), 1))

        # 3. Run the attack matrix — each endpoint × identity; endpoints in parallel.
        self._endpoints = endpoints
        plugins = all_plugins()
        actors = list(self.identities)
        workers = max(1, min(8, len(endpoints)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            per_endpoint = list(pool.map(
                lambda ep: self._attack_endpoint(ep, plan, actors, plugins), endpoints))

        findings: List[Finding] = []
        seen = set()
        for ep_findings in per_endpoint:
            for f in (ep_findings or []):
                dk = (f.vuln_class.value, f.endpoint_key)   # dedup by class+endpoint (any identity)
                if dk in seen:
                    continue
                seen.add(dk)
                findings.append(f)
                self.log(f"   🚩 [{f.severity.value}] {f.title}")

        # 4. Merge QA findings, explain (LLM brain), report.
        for f in findings:
            self.context.add_finding(f)
        findings.extend(qa_findings)
        self.log(f"✨ {len(findings)} finding(s) ({len(qa_findings)} from QA crawl). Writing explanations + report ...")
        try:
            self.explainer.enrich(findings, self.description)
        except Exception as e:
            self.log(f"⚠️ explainer failed ({e}); using technical detail.")

        authed = [i for i in self.identities if not i.is_anonymous]
        spec_loaded = isinstance(self._spec, dict) and bool(self._spec.get("paths"))
        # An endpoint is meaningfully testable only if there's something to probe
        # (a path/query param, a body, or a non-GET method). A bare "GET /" is not.
        def _testable(e) -> bool:
            return bool(e.path_params or e.query_params or e.body_schema) or e.method.upper() != "GET"
        testable = [e for e in endpoints if _testable(e)]

        # Behind-login coverage was requested but not achieved?
        if (self.auth or self.auth_identities) and not authed:
            self._degraded.append("Login was configured but no authenticated session could be "
                                  "captured — everything behind the login is UNTESTED.")
        if not endpoints:
            self._degraded.append("No testable API endpoints were discovered.")
        elif not testable:
            self._degraded.append("Only opaque endpoints with no parameters or body were found — "
                                  "there was effectively nothing to probe.")
        if not spec_loaded and not self.crawl_ui:
            self._degraded.append("No API spec was found and the UI crawl was OFF, so the app's real "
                                  "surface (forms, routes, the API calls the UI makes) was never "
                                  "discovered. Enable 'Crawl the UI' and/or provide an OpenAPI spec.")

        # Low coverage = we couldn't meaningfully exercise the app. A clean result here means
        # "not enough was tested", never "secure" — so withhold a passing grade.
        low_coverage = bool(
            len(testable) == 0
            or (not spec_loaded and not self.crawl_ui)
            or ((self.auth or self.auth_identities) and not authed)
        )
        coverage = {
            "endpoints_total": len(endpoints),
            "endpoints_attacked": len(endpoints),
            "endpoints_testable": len(testable),
            "requests_sent": self._req_count,
            "attack_classes": [p.name for p in plugins],
            "identities": [f"{i.name} ({i.role})" for i in self.identities],
            "authed_identities": len(authed),
            "allow_writes": self.allow_writes,
            "qa_crawl": self.crawl_ui,
            "brain_available": self._brain_ok,
            "screenshots_dir": self._artifacts,
            "degraded": list(self._degraded),
            "low_coverage": low_coverage,
        }
        report = FounderReport(findings, self.base_url, coverage)
        try:
            if self.output_dir and self.output_dir != ".":
                os.makedirs(self.output_dir, exist_ok=True)
            report.save(os.path.join(self.output_dir, "latest_report.md"))
        except Exception as e:
            self.log(f"⚠️ could not save report: {e}")
        self.http.close()

        return {
            "findings": [self._finding_dict(f) for f in findings],
            "coverage": coverage,
            "grade": report.grade(),
            "score": report.score(),
            "report_markdown": report.markdown(),
            "context": self.context.to_dict(),
        }

    def _run_qa(self, endpoints) -> list:
        """Run the QA crawler; merge its shadow spec into the attack surface."""
        from qa.crawler import run_qa_crawl, _NOISE_QS   # lazy: imports playwright only when used
        self.log("🧭 QA crawl: exploring the UI like a human tester ...")
        try:
            findings, shadow, artifacts = run_qa_crawl(
                self.base_url, description=self.description, llm=None,
                max_pages=self.max_pages, context=self.context, auth=self.auth,
                artifacts_dir=os.path.join(self.output_dir, ".qa_artifacts"), log=self.log)
        except Exception as e:
            self.log(f"⚠️ QA crawl failed ({e}); continuing with API tests only.")
            return []
        self._artifacts = artifacts
        infra = ("/openapi.json", "/docs", "/redoc", "/favicon.ico")
        known = {_canon_key(e.key) for e in endpoints}
        # shadow is {key: meta}; tolerate a bare set/list for back-compat.
        shadow_items = shadow.items() if isinstance(shadow, dict) else [(k, {}) for k in shadow]
        for sk, meta in shadow_items:
            parts = sk.split(" ", 1)
            if len(parts) != 2:
                continue
            method, path = parts[0].upper(), parts[1]
            key = f"{method} {path}"
            ckey = _canon_key(key)
            if ckey in known or any(path.startswith(x) for x in infra):
                known.add(ckey)
                continue
            meta = meta or {}
            # Build a FIRST-CLASS endpoint from the captured request so the attack
            # matrix can actually test it (params, body, content-type, auth inferred).
            params = []
            for seg in re.findall(r"\{([^}]+)\}", path):
                params.append({"name": seg, "in": "path", "type": "string", "required": True})
            for qk in (meta.get("query_keys") or []):
                if qk.lower() in _NOISE_QS:
                    continue   # framework navigation marker, not a real input
                params.append({"name": qk, "in": "query", "type": "string", "required": False})
            body_schema = None
            if meta.get("body_keys"):
                body_schema = {"type": "object",
                               "properties": {k: {"type": "string"} for k in meta["body_keys"]}}
            endpoints.append(Endpoint(
                method=method, path_template=path, base_url=self.base_url, source="shadow",
                params=params, body_schema=body_schema,
                auth_required=bool(meta.get("auth")),
                request_content_type=meta.get("content_type", "json")))
            known.add(ckey)
            findings.append(Finding(
                vuln_class=VulnClass.UNDOCUMENTED_ENDPOINT, severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                title=f"Undocumented endpoint used by the UI: {key}",
                endpoint_key=key,
                evidence=Evidence(note="seen in browser network traffic, absent from the API spec"),
                detail="The UI calls this endpoint but it is not declared in the OpenAPI spec.",
                source="qa.shadow"))
        self.log(f"   shadow spec: {len(shadow)} endpoint(s) seen in the UI.")

        # Cross-browser smoke on the discovered UI pages (Firefox / WebKit).
        if self.cross_browser:
            from qa.cross_browser import cross_browser_smoke
            import asyncio as _aio
            pages = self.context.entities.get("pages", []) or [self.base_url + "/"]
            for eng in self.cross_browser:
                self.log(f"🌐 cross-browser smoke: {eng} ...")
                try:
                    findings.extend(_aio.run(cross_browser_smoke(
                        eng, pages[:6], self._artifacts, auth=self.auth,
                        base_url=self.base_url, log=self.log)))
                except Exception as e:
                    self.log(f"   ⚠️ {eng} smoke failed: {e}")

        return findings

    @staticmethod
    def _finding_dict(f: Finding) -> dict:
        d = asdict(f)
        d["vuln_class"] = f.vuln_class.value
        d["severity"] = f.severity.value
        d["confidence"] = f.confidence.value
        return d
