"""
qa/crawler.py — the smart QA crawler.

A frontier (BFS) crawl of the app that, on every page, behaves like a human QA
engineer: understands the screen (LLM), generates + runs test cases, captures
evidence (screenshots, console/JS/network errors, native dialogs), checks links,
and records the real API calls the UI makes (a "shadow spec"). Safe by default:
destructive controls (logout/delete/pay…) are skipped.
"""
from __future__ import annotations

import asyncio
import os
import re
from urllib.parse import urlparse, urldefrag, parse_qs

from playwright.async_api import async_playwright

from core.models import Finding, Evidence, VulnClass, Severity, Confidence
from core.context import RunContext
from agent.llm import LLMClient
from qa.page_model import extract_page_model
from qa.qa_planner import QAPlanner
from qa.executor import execute_case, steps_for
from qa.oracle import QAJudge, deterministic_findings, broken_link_finding

DESTRUCTIVE = re.compile(
    r"\b(logout|log out|sign ?out|delete|remove|deactivate|close account|"
    r"pay|checkout|buy|purchase|withdraw|cancel account)\b", re.I)

# Infra/tooling endpoints — captured for shadow spec but not QA-crawled as pages.
INFRA = re.compile(r"/(openapi\.json|docs|redoc|favicon\.ico|swagger)", re.I)

# Framework/navigation query params that are NOT real app inputs. Modern SPA
# frameworks fetch their own page payloads via fetch() (so they look like API
# calls), tagged with markers like Next.js's `?_rsc=<hash>`. Recording these as
# endpoints inflates coverage and can mask a near-empty crawl as "tested".
_NOISE_QS = {"_rsc", "__nextdatareq", "__flight__", "_next", "__n", "rsc"}
# Request headers that mark a request as a framework page-navigation/prefetch
# rather than a genuine XHR/fetch to the app's API.
_NAV_HEADERS = ("rsc", "next-router-prefetch", "next-router-state-tree", "next-url",
                "purpose", "x-nextjs-data")


def _norm(u: str) -> str:
    return urldefrag(u or "")[0]


def _same_host(u: str, host: str) -> bool:
    try:
        return (urlparse(u).hostname or "") == host
    except Exception:
        return False


_UUID_RE = re.compile(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_LONGHEX_RE = re.compile(r"/[0-9a-f]{16,}", re.I)


def _templ(path: str) -> str:
    p = _UUID_RE.sub("/{id}", path or "/")
    p = _LONGHEX_RE.sub("/{id}", p)
    p = re.sub(r"/\d+", "/{id}", p)
    return p


class EventRecorder:
    """Collects console errors, JS exceptions, failed responses and dialogs."""
    def __init__(self):
        self.console, self.pageerrors, self.responses, self.dialogs = [], [], [], []

    def attach(self, page) -> None:
        page.on("console", lambda m: self.console.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: self.pageerrors.append(str(e)))
        page.on("response", lambda r: self.responses.append((r.status, r.url)) if r.status >= 400 else None)
        page.on("dialog", self._on_dialog)

    def _on_dialog(self, d) -> None:
        try:
            self.dialogs.append(d.message)
        except Exception:
            self.dialogs.append("(dialog)")
        asyncio.ensure_future(self._dismiss(d))

    async def _dismiss(self, d) -> None:
        try:
            await d.dismiss()
        except Exception:
            pass

    def checkpoint(self):
        return (len(self.console), len(self.pageerrors), len(self.responses), len(self.dialogs))

    def since(self, cp) -> dict:
        c, p, r, d = cp
        return {
            "console_errors": self.console[c:],
            "js_exceptions": self.pageerrors[p:],
            "failed_responses": [{"status": s, "url": u} for s, u in self.responses[r:]],
            "dialogs": self.dialogs[d:],
        }


class QACrawler:
    def __init__(self, base_url: str, description: str = "", llm: LLMClient | None = None,
                 max_pages: int = 25, max_cases_per_page: int = 12,
                 storage_state=None, artifacts_dir: str = ".qa_artifacts",
                 context: RunContext | None = None, auth: dict | None = None,
                 responsive: bool = True, engine: str = "chromium", log=print):
        self.base_url = (base_url or "").rstrip("/")
        self.description = description
        self.llm = llm or LLMClient()
        self.context = context or RunContext(target=self.base_url, description=description)
        self.auth = auth
        self.responsive = responsive
        self.engine = engine
        self.planner = QAPlanner(self.llm)
        self.judge = QAJudge(self.llm)
        self.max_pages = max_pages
        self.max_cases = max_cases_per_page
        self.storage_state = storage_state
        self.host = urlparse(self.base_url).hostname
        self.artifacts = artifacts_dir
        self.log = log
        self.findings: list[Finding] = []
        self.shadow: dict[str, dict] = {}   # "METHOD /templated/path" -> {content_type, auth, body_keys, query_keys}
        self.sitemap: list = []
        self._enqueued: set[str] = set()
        self._links_checked: set[str] = set()
        self._finding_keys: set[str] = set()

    async def run(self):
        os.makedirs(self.artifacts, exist_ok=True)
        async with async_playwright() as p:
            engine = getattr(p, self.engine, p.chromium)
            browser = await engine.launch(headless=True)
            ctx_args = {"storage_state": self.storage_state} if self.storage_state else {}
            context = await browser.new_context(**ctx_args)
            page = await context.new_page()
            rec = EventRecorder()
            rec.attach(page)
            page.on("request", self._on_request)

            # Phased crawl: explore + TEST the public / login surface anonymously
            # first, THEN log in, THEN crawl the authenticated surface — so the
            # login form itself gets fuzzed before we're ever past it.
            logged_in = not bool(self.auth)
            anon_budget = max(2, self.max_pages // 3) if self.auth else self.max_pages

            frontier = [self.base_url + "/"]
            visited: set[str] = set()
            n = 0
            while n < self.max_pages:
                # Cross into the authenticated phase once the public budget is spent
                # (or the public frontier runs dry).
                if not logged_in and (n >= anon_budget or not frontier):
                    logged_in = True
                    if await self._do_login(context):
                        self.log("🔓 authenticated — now crawling behind the login.")
                        seed = _norm(self.base_url + "/")
                        visited.discard(seed)
                        self._enqueued.discard(seed)
                        if seed not in frontier:
                            frontier.insert(0, seed)
                    else:
                        self.log("   login did not succeed — continuing as anonymous.")
                if not frontier:
                    break
                url = _norm(frontier.pop(0))
                if url in visited or not _same_host(url, self.host):
                    continue
                visited.add(url)
                n += 1
                tag = " (auth)" if (self.auth and logged_in) else ""
                self.log(f"🔎 QA page {n}/{self.max_pages}{tag}: {url}")
                cp = rec.checkpoint()
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    # SPA hydration: wait for the network to settle and real content to
                    # appear, else a React/Next shell is snapshotted empty (false 'clean').
                    try:
                        await page.wait_for_load_state("networkidle", timeout=6000)
                    except Exception:
                        pass
                    try:
                        await page.wait_for_selector(
                            "form,button,[role=button],input,main,h1,h2,[data-testid]", timeout=4000)
                    except Exception:
                        await page.wait_for_timeout(1000)
                except Exception as e:
                    self.log(f"   ⚠️ could not open: {e}")
                    continue

                shot = os.path.join(self.artifacts, f"page_{n}.png")
                try:
                    await page.screenshot(path=shot, full_page=True)
                except Exception:
                    shot = ""

                for js in rec.since(cp)["js_exceptions"]:
                    self._add(self._js_load_finding(url, js, shot))

                model = await extract_page_model(page)
                # SPA may still be hydrating — one retry if nothing interactive showed up.
                if not (model.get("forms") or model.get("buttons")):
                    try:
                        await page.wait_for_timeout(1200)
                        model = await extract_page_model(page)
                    except Exception:
                        pass
                await self._check_links(context, url, model)

                # Record real UI pages (for E2E flows + cross-browser); run responsive checks.
                if (model.get("forms") or model.get("buttons")
                        or model.get("links") or model.get("headings")):
                    self.context.add_entity("pages", url)
                    if self.responsive:
                        from qa.responsive import check_responsive
                        for f in await check_responsive(page, url, self.artifacts, n, self.log):
                            self._add(f)

                # Only QA-test pages that actually have interactive UI. JSON/API
                # responses (no forms/buttons) are captured for shadow spec + links
                # only — running test cases on them just invites hallucinated bugs.
                if model.get("forms") or model.get("buttons"):
                    plan = self.planner.plan(model, self.description, memory=self.context.brief())
                    intent = plan.get("page_intent", "")
                    if intent:
                        self.context.remember_fact(f"{url} — {intent}")
                    if model.get("forms"):
                        self.sitemap.append({
                            "url": url, "intent": intent,
                            "forms": [{
                                "submit_selector": fm.get("submit_selector") or "button[type=submit]",
                                "fields": [{"ref": fld.get("ref"), "selector": fld.get("selector"),
                                            "type": fld.get("type"), "placeholder": fld.get("placeholder")}
                                           for fld in fm.get("fields", [])],
                            } for fm in model["forms"]],
                        })
                    items = []
                    for case in (plan.get("test_cases") or [])[:self.max_cases]:
                        if self._destructive(case):
                            continue
                        obs = await execute_case(page, rec, model, case)
                        for f in deterministic_findings(url, case, obs, shot):
                            self._add(f)
                        items.append({"case": case, "obs": obs, "screenshot": shot})
                        if page.url != url:  # return home after a navigation/submit
                            try:
                                await page.goto(url, wait_until="domcontentloaded", timeout=10000)
                            except Exception:
                                pass
                    for f in self.judge.judge(url, intent, items, self.description,
                                              memory=self.context.brief()):
                        self._add(f)
                else:
                    self.log("   (no interactive UI — links/shadow captured only)")

                for ex in (plan.get("explore") or []):
                    self._maybe_enqueue(frontier, ex.get("href", ""))
                for lk in model.get("links", []):
                    if not DESTRUCTIVE.search(lk.get("text", "")):
                        self._maybe_enqueue(frontier, lk.get("href", ""))
                # Button/JS-driven nav targets (often relative — resolve against this page).
                from urllib.parse import urljoin
                for hint in model.get("nav_hints", []):
                    if hint and not DESTRUCTIVE.search(hint):
                        self._maybe_enqueue(frontier, urljoin(url, hint))

            # Multi-step E2E journeys — reuse the (authenticated) context + discovered site map.
            if self.sitemap:
                from qa.flows import FlowPlanner, run_journey
                journeys = FlowPlanner(self.llm).plan(self.description, self.sitemap, self.context.brief())
                for j in journeys[:3]:
                    self.log(f"🧪 E2E journey: {j.get('name', 'journey')}")
                    finding = await run_journey(context, j, self.base_url, self.log)
                    if finding:
                        self._add(finding)
                    else:
                        self.context.remember_fact(f"E2E journey '{j.get('name')}' passed")

            await context.close()
            await browser.close()
        return self.findings, self.shadow, self.artifacts

    async def _do_login(self, context) -> bool:
        """Log the crawl context in (mid-crawl, after the public pass). Captures
        session cookies so the API attack matrix can also run as this user."""
        from qa.auth import login
        ok, state, msg = await login(context, self.auth, self.base_url, self.log)
        self.log(f"🔐 login: {'OK' if ok else 'FAILED'} — {msg}")
        if ok:
            self.context.remember_fact(
                f"Authenticated as '{self.auth.get('username')}' (role: {self.auth.get('role', 'user')})")
            if self.auth.get("username") and self.auth.get("password"):
                # Do NOT persist the raw password into run-memory (it flows into LLM
                # prompts + the returned context). Record only that creds exist.
                self.context.remember_fact(
                    f"Working login credentials are available for '{self.auth.get('username')}' — "
                    "use them for login happy-path tests.")
            try:
                for ck in (state or {}).get("cookies", []):
                    if ck.get("name"):
                        self.context.auth_cookies[ck["name"]] = ck.get("value", "")
                self.context.auth_role = self.auth.get("role", "user")
            except Exception:
                pass
        return ok

    # --- helpers ---------------------------------------------------------
    def _maybe_enqueue(self, frontier: list, href: str) -> None:
        href = _norm(href)
        if (href and href not in self._enqueued and _same_host(href, self.host)
                and not INFRA.search(href)):
            self._enqueued.add(href)
            frontier.append(href)

    def _destructive(self, case: dict) -> bool:
        return bool(DESTRUCTIVE.search(f"{case.get('title', '')} {case.get('target', '')}"))

    def _on_request(self, req) -> None:
        """Record the real API calls the UI makes — including server-rendered form
        POSTs (document navigations), not just fetch/XHR — with enough metadata
        (content-type, auth, body/query keys) to make them first-class attack targets."""
        try:
            m = req.method.upper()
            rt = req.resource_type
            pu = urlparse(req.url)
            if pu.hostname != self.host:
                return
            is_api = rt in ("fetch", "xhr")
            is_form_post = m in ("POST", "PUT", "PATCH", "DELETE")
            if not (is_api or is_form_post):
                return   # plain GET page navigations aren't API endpoints
            hdrs = {k.lower(): v for k, v in (req.headers or {}).items()}
            # Drop framework page-navigation/prefetch fetches (e.g. Next.js RSC):
            # they ride on fetch() but are just the SPA loading its own pages, not
            # real API surface. Recording them inflates coverage with phantom GETs.
            query_keys = [k for k in parse_qs(pu.query)] if pu.query else []
            meaningful_qs = [k for k in query_keys if k.lower() not in _NOISE_QS]
            looks_nav = (m == "GET" and not is_form_post and (
                any(h in hdrs for h in _NAV_HEADERS)
                or (query_keys and not meaningful_qs)))
            if looks_nav:
                return
            key = f"{m} {_templ(pu.path)}"
            meta = self.shadow.setdefault(
                key, {"content_type": "json", "auth": False, "body_keys": [], "query_keys": []})
            ct = hdrs.get("content-type", "")
            if "x-www-form-urlencoded" in ct or "multipart" in ct:
                meta["content_type"] = "form"
            if any(h in hdrs for h in ("authorization", "cookie", "x-api-key", "x-csrf-token")):
                meta["auth"] = True
            for k in meaningful_qs:
                if k not in meta["query_keys"]:
                    meta["query_keys"].append(k)
            post = None
            try:
                post = req.post_data
            except Exception:
                post = None
            if post:
                self._merge_body_keys(meta, post, meta["content_type"])
        except Exception:
            pass

    @staticmethod
    def _merge_body_keys(meta: dict, post: str, content_type: str) -> None:
        import json as _json
        keys = []
        try:
            if content_type == "form":
                keys = list(parse_qs(post).keys())
            else:
                data = _json.loads(post)
                if isinstance(data, dict):
                    keys = list(data.keys())
        except Exception:
            keys = []
        for k in keys:
            if k not in meta["body_keys"]:
                meta["body_keys"].append(k)

    async def _check_links(self, context, page_url: str, model: dict) -> None:
        checked = 0
        for lk in model.get("links", []):
            if checked >= 25:
                break
            href = _norm(lk.get("href", ""))
            if not _same_host(href, self.host) or href in self._links_checked:
                continue
            if DESTRUCTIVE.search(lk.get("text", "")):
                continue
            self._links_checked.add(href)
            checked += 1
            try:
                resp = await context.request.get(href, timeout=10000)
                if resp.status >= 400:
                    self._add(broken_link_finding(page_url, href, resp.status))
            except Exception:
                pass

    def _add(self, f: Finding) -> None:
        if f and f.dedup_key() not in self._finding_keys:
            self._finding_keys.add(f.dedup_key())
            self.findings.append(f)
            self.context.add_finding(f)
            self.log(f"   🚩 [{f.severity.value}] {f.title}")

    @staticmethod
    def _js_load_finding(url: str, js: str, shot: str) -> Finding:
        return Finding(
            vuln_class=VulnClass.JS_ERROR, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            title="JavaScript error on page load", endpoint_key=url,
            evidence=Evidence(page_url=url, steps=[f"Open {url}"], expected="No console/JS errors",
                              actual=js[:400], screenshot=shot, note="uncaught JS exception on load"),
            detail=js[:400], source="qa.crawler")


def run_qa_crawl(base_url: str, description: str = "", llm: LLMClient | None = None,
                 max_pages: int = 25, storage_state=None, context: RunContext | None = None,
                 auth: dict | None = None, artifacts_dir: str = ".qa_artifacts", log=print):
    """Sync wrapper — runs the async crawler to completion. Returns (findings, shadow, artifacts_dir)."""
    crawler = QACrawler(base_url, description=description, llm=llm, max_pages=max_pages,
                        storage_state=storage_state, context=context, auth=auth,
                        artifacts_dir=artifacts_dir, log=log)
    return asyncio.run(crawler.run())
