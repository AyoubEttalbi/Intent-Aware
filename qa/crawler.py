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
import time
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

# Pages to spend on the anonymous pass when the crawl is UNCAPPED and we hold
# credentials: enough to cover the public surface (landing, login, marketing,
# legal) without draining the frontier before we ever log in.
_UNCAPPED_ANON_PAGES = 8

# --- modal / consent overlays ------------------------------------------------
# A welcome modal or cookie bar sits ABOVE the page and swallows every click
# behind it (Angular Material renders a full-viewport `.cdk-overlay-backdrop`).
# The click then never reaches its target, the expected effect never happens,
# and the judge — correctly reporting what it observed — calls a perfectly good
# control broken. Phase 7 against OWASP Juice Shop produced three such false
# positives ("Add to Basket does not add", "search shows no empty state",
# "cookie banner does not dismiss") from one welcome modal. Real apps almost all
# have a consent banner, so this dismissal is what keeps landing-page findings
# honest. Dismiss the overlay the way a human does, before touching anything.
#
# Scoped deliberately: we only click inside an overlay/dialog/consent container,
# and only controls whose label is unambiguously "make this go away" — never a
# generic "Accept"/"Continue" that could be a real form's submit button.
_OVERLAY_ROOTS = (
    ".cdk-overlay-container", "[role=dialog]", "[aria-modal=true]", "dialog[open]",
    ".cc-window", "#cookieconsent", "[class*=cookie-banner]", "[id*=cookie-banner]",
    "[class*=consent]", "[id*=onetrust]", ".modal.show",
)
_OVERLAY_DISMISS_SELECTORS = (
    "[aria-label*='close welcome' i]", "[aria-label*='dismiss cookie' i]",
    "button[aria-label*='close' i]", "button[aria-label*='dismiss' i]",
    ".close-dialog", ".cc-dismiss", ".cc-btn.cc-dismiss",
    "#onetrust-accept-btn-handler", "[data-testid*='accept-cookie' i]",
    "[data-testid*='close-modal' i]",
)
# Visible-text fallback, matched ONLY inside an overlay root above.
_OVERLAY_DISMISS_TEXT = re.compile(
    r"^\s*(ok(ay)?|got it|understood|i agree|agree|accept( all| cookies)?|"
    r"allow all|dismiss|close|no thanks|me want it!?|x)\s*$", re.I)

# A backdrop this large is blocking the page rather than decorating it.
_BACKDROP_SELECTOR = ".cdk-overlay-backdrop, .modal-backdrop, [class*=overlay-backdrop]"


async def _dismiss_overlays(page, log=None) -> bool:
    """Close blocking modals / consent banners so later clicks reach the real UI.

    Best-effort and non-fatal: any failure leaves the page exactly as it was.
    Returns True if something was dismissed.
    """
    dismissed = False
    for _ in range(4):                      # modal, then the consent bar behind it
        try:
            target = None
            for sel in _OVERLAY_DISMISS_SELECTORS:
                el = await page.query_selector(sel)
                if el and await el.is_visible():
                    target = el
                    break
            if target is None:
                # Text fallback, scoped to an overlay container so we never hit
                # an ordinary page button that happens to say "OK".
                for root in _OVERLAY_ROOTS:
                    container = await page.query_selector(root)
                    if not container:
                        continue
                    for el in await container.query_selector_all("button, a, [role=button]"):
                        try:
                            if not await el.is_visible():
                                continue
                            if _OVERLAY_DISMISS_TEXT.match((await el.inner_text()) or ""):
                                target = el
                                break
                        except Exception:
                            continue
                    if target is not None:
                        break
            if target is None:
                break
            # force=True: the backdrop we are trying to remove is itself what
            # intercepts a normal click on the dismiss control.
            await target.click(timeout=3000, force=True)
            await page.wait_for_timeout(400)
            dismissed = True
            # Keep going: clearing the modal's backdrop often reveals a SECOND
            # overlay (Juice Shop's welcome modal sits on top of its cookie bar).
            # Stopping at the first dismissal left the bar up, and the judge then
            # reported "cookie banner does not dismiss" — a false positive.
        except Exception:
            break
    if dismissed and log:
        log("   ↩︎ dismissed a modal/consent overlay before interacting")
    return dismissed


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
                 responsive: bool = True, engine: str = "chromium", log=print,
                 deadline: float | None = None, concurrency: int = 4):
        self.base_url = (base_url or "").rstrip("/")
        self.description = description
        self.deadline = deadline   # time.monotonic() ceiling — crawl stops past it (opt-in)
        self.concurrency = max(1, concurrency)   # parallel page workers
        self.llm = llm or LLMClient()
        self.context = context or RunContext(target=self.base_url, description=description)
        self.auth = auth
        self.responsive = responsive
        self.engine = engine
        self.planner = QAPlanner(self.llm)
        self.judge = QAJudge(self.llm)
        # max_pages <= 0 (or unset) ⇒ "uncapped": crawl until the link frontier
        # is exhausted. That needs a BACKSTOP, because the frontier is not
        # guaranteed to drain: `_maybe_enqueue` dedups by exact URL only, so an
        # app with paginated or filtered listings (/customers?page=1..N, date
        # ranges, per-row detail links) produces an effectively infinite
        # same-host frontier. The other budgets do not save us — max_requests
        # bounds the attack matrix, not crawl pages, and an exhausted LLM budget
        # is swallowed by the planner/judge so the crawl just keeps walking.
        # Without this the job never finishes: the row stays `pending` and the
        # UI polls forever. Set CRAWL_MAX_PAGES=0 to genuinely remove the bound.
        self._uncapped = not max_pages or max_pages <= 0
        if self._uncapped:
            backstop = int(os.getenv("CRAWL_MAX_PAGES", "500"))
            self.max_pages = float("inf") if backstop <= 0 else backstop
        else:
            self.max_pages = max_pages
        self._cap_str = "∞" if self.max_pages == float("inf") else str(self.max_pages)
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

            # --- Parallel crawl state (shared across worker pages) -------------
            self._frontier = [_norm(self.base_url + "/")]
            self._visited: set[str] = set()
            self._n = 0
            self._lock = asyncio.Lock()
            # Bound concurrent claude subprocesses (~250 MB each) so the pool can't OOM.
            self._llm_sema = asyncio.Semaphore(max(1, min(self.concurrency, 4)))

            # One page + recorder per worker; ALL share the (authenticated) context,
            # so cookies/session set by login apply to every worker.
            n_workers = max(1, min(self.concurrency, self.max_pages))
            pages, recs = [], []
            for _ in range(n_workers):
                pg = await context.new_page()
                rc = EventRecorder()
                rc.attach(pg)
                pg.on("request", self._on_request)
                pages.append(pg)
                recs.append(rc)
            self.log(f"🧭 QA crawl: {n_workers} parallel worker(s) exploring the UI ...")

            # Seed the frontier from a fast link-harvest of the homepage (NO LLM) so
            # every worker starts in parallel from t=0, instead of idling while page 1
            # does its slow full LLM pass. The homepage is still fully processed below.
            if n_workers > 1:
                try:
                    sp = pages[0]
                    await sp.goto(_norm(self.base_url + "/"), wait_until="domcontentloaded", timeout=15000)
                    try:
                        await sp.wait_for_load_state("networkidle", timeout=4000)
                    except Exception:
                        pass
                    seed_model = await extract_page_model(sp)
                    from urllib.parse import urljoin as _urljoin
                    for lk in seed_model.get("links", []):
                        if not DESTRUCTIVE.search(lk.get("text", "")):
                            self._maybe_enqueue(lk.get("href", ""))
                    for hint in seed_model.get("nav_hints", []):
                        if hint and not DESTRUCTIVE.search(hint):
                            self._maybe_enqueue(_urljoin(self.base_url + "/", hint))
                except Exception:
                    pass

            # Phase 1 — crawl + fuzz the PUBLIC / login surface anonymously first.
            # Branch on `_uncapped` (the user's intent), NOT on max_pages: with a
            # backstop applied, an "uncapped" run carries a large finite cap, and
            # a third of that would burn the whole budget before we ever log in.
            # The old one-liner `max(2, max_pages // 3)` was also a nan trap —
            # `inf // 3` is nan and `max(2, nan)` returns 2, so "no cap" used to
            # SHRINK the public pass to 2 pages.
            if not self.auth:
                anon_cap = self.max_pages
            elif self._uncapped:
                anon_cap = _UNCAPPED_ANON_PAGES   # short public pass, then log in
            else:
                anon_cap = max(2, self.max_pages // 3)
            await self._crawl_phase(pages, recs, cap=anon_cap, authed=False)

            # Log in once on the shared context, then re-seed for the authed pass.
            logged_in = not bool(self.auth)
            if self.auth and not logged_in:
                if await self._do_login(context):
                    logged_in = True
                    self.log("🔓 authenticated — now crawling behind the login.")
                    seed = _norm(self.base_url + "/")
                    self._visited.discard(seed)
                    self._enqueued.discard(seed)
                    self._frontier.insert(0, seed)
                else:
                    self.log("   login did not succeed — continuing as anonymous.")

            # Phase 2 — crawl the authenticated surface (up to max_pages total).
            await self._crawl_phase(pages, recs, cap=self.max_pages,
                                    authed=bool(self.auth) and logged_in)

            # Multi-step E2E journeys — reuse the (authenticated) context + site map.
            if self.sitemap:
                from qa.flows import FlowPlanner, run_journey
                journeys = await asyncio.to_thread(
                    FlowPlanner(self.llm).plan, self.description, self.sitemap, self.context.brief())
                for j in (journeys or [])[:3]:
                    self.log(f"🧪 E2E journey: {j.get('name', 'journey')}")
                    finding = await run_journey(context, j, self.base_url, self.log)
                    if finding:
                        self._add(finding)
                    else:
                        self.context.remember_fact(f"E2E journey '{j.get('name')}' passed")

            await context.close()
            await browser.close()
        return self.findings, self.shadow, self.artifacts

    async def _crawl_phase(self, pages, recs, cap: int, authed: bool):
        """Run the worker pool until `cap` pages are done (or the frontier is truly
        exhausted). A worker that finds the frontier momentarily empty must WAIT
        while other workers are still processing — they may enqueue new links — and
        only exit once the frontier is empty AND nothing is in flight."""
        self._active = 0
        async def worker(page, rec):
            while True:
                url = n = None
                async with self._lock:
                    if self._n >= cap or (self.deadline and time.monotonic() > self.deadline):
                        return
                    while self._frontier:
                        cand = _norm(self._frontier.pop(0))
                        if cand in self._visited or not _same_host(cand, self.host):
                            continue
                        url = cand
                        break
                    if url is None:
                        # Nothing queued right now. If no worker is mid-page, no more
                        # links are coming → done. Otherwise wait for one to enqueue.
                        if self._active == 0:
                            return
                    else:
                        self._visited.add(url)
                        self._n += 1
                        n = self._n
                        self._active += 1
                if url is None:
                    await asyncio.sleep(0.15)
                    continue
                tag = " (auth)" if authed else ""
                self.log(f"🔎 QA page {n}/{self._cap_str}{tag}: {url}")
                try:
                    await self._process_url(page, rec, url, n)
                except Exception as e:
                    self.log(f"   ⚠️ page error on {url}: {e}")
                finally:
                    async with self._lock:
                        self._active -= 1
        await asyncio.gather(*[worker(pg, rc) for pg, rc in zip(pages, recs)])

    async def _process_url(self, page, rec, url: str, n: int):
        """Process one page: open, snapshot, check links + responsive + the LLM
        'understand this page' plan CONCURRENTLY, run test cases, enqueue links."""
        cp = rec.checkpoint()
        await page.goto(url, wait_until="domcontentloaded", timeout=15000)
        # SPA hydration: settle the network + wait for real content to appear.
        try:
            await page.wait_for_load_state("networkidle", timeout=6000)
        except Exception:
            pass
        try:
            await page.wait_for_selector(
                "form,button,[role=button],input,main,h1,h2,[data-testid]", timeout=4000)
        except Exception:
            await page.wait_for_timeout(1000)

        # Clear blocking modals/consent banners BEFORE the screenshot and the page
        # model, so evidence and test cases both reflect the app, not the overlay.
        await _dismiss_overlays(page, self.log)

        shot = os.path.join(self.artifacts, f"page_{n}.png")
        try:
            await page.screenshot(path=shot, full_page=True)
        except Exception:
            shot = ""

        for js in rec.since(cp)["js_exceptions"]:
            self._add(self._js_load_finding(url, js, shot))

        model = await extract_page_model(page)
        if not (model.get("forms") or model.get("buttons")):
            try:
                await page.wait_for_timeout(1200)
                model = await extract_page_model(page)
            except Exception:
                pass

        interactive = bool(model.get("forms") or model.get("buttons"))
        # Kick off the slow LLM "understand this page" call NOW, off the event loop,
        # so it overlaps with the (also-slow) link-check + responsive screenshots.
        plan_task = None
        if interactive:
            async def _plan():
                async with self._llm_sema:
                    return await asyncio.to_thread(
                        self.planner.plan, model, self.description, self.context.brief())
            plan_task = asyncio.create_task(_plan())

        await self._check_links(page.context, url, model)

        if (model.get("forms") or model.get("buttons")
                or model.get("links") or model.get("headings")):
            self.context.add_entity("pages", url)
            if self.responsive:
                from qa.responsive import check_responsive
                for f in await check_responsive(page, url, self.artifacts, n, self.log):
                    self._add(f)

        plan = {}
        if interactive:
            try:
                plan = await plan_task or {}
            except Exception:
                plan = {}
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
            async with self._llm_sema:
                judged = await asyncio.to_thread(
                    self.judge.judge, url, intent, items, self.description, self.context.brief())
            for f in (judged or []):
                self._add(f)
        else:
            self.log("   (no interactive UI — links/shadow captured only)")

        for ex in (plan.get("explore") or []):
            self._maybe_enqueue(ex.get("href", ""))
        for lk in model.get("links", []):
            if not DESTRUCTIVE.search(lk.get("text", "")):
                self._maybe_enqueue(lk.get("href", ""))
        from urllib.parse import urljoin
        for hint in model.get("nav_hints", []):
            if hint and not DESTRUCTIVE.search(hint):
                self._maybe_enqueue(urljoin(url, hint))

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
    def _maybe_enqueue(self, href: str) -> None:
        # Shared frontier — only mutated on the event loop (no await), so atomic.
        href = _norm(href)
        if (href and href not in self._enqueued and href not in self._visited
                and _same_host(href, self.host) and not INFRA.search(href)):
            self._enqueued.add(href)
            self._frontier.append(href)

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
        import asyncio
        targets = []
        for lk in model.get("links", []):
            if len(targets) >= 12:
                break
            href = _norm(lk.get("href", ""))
            if not _same_host(href, self.host) or href in self._links_checked:
                continue
            if DESTRUCTIVE.search(lk.get("text", "")):
                continue
            self._links_checked.add(href)
            targets.append(href)

        async def _one(href):
            try:
                resp = await context.request.get(href, timeout=5000)
                if resp.status >= 400:
                    self._add(broken_link_finding(page_url, href, resp.status))
            except Exception:
                pass

        # Check links in PARALLEL — sequential 1-at-a-time GETs (25 × up to 10s)
        # were the single slowest part of each page.
        if targets:
            await asyncio.gather(*[_one(h) for h in targets])

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
                 auth: dict | None = None, artifacts_dir: str = ".qa_artifacts", log=print,
                 deadline: float | None = None, concurrency: int = 4):
    """Sync wrapper — runs the async crawler to completion. Returns (findings, shadow, artifacts_dir)."""
    crawler = QACrawler(base_url, description=description, llm=llm, max_pages=max_pages,
                        storage_state=storage_state, context=context, auth=auth,
                        artifacts_dir=artifacts_dir, log=log, deadline=deadline,
                        concurrency=concurrency)
    return asyncio.run(crawler.run())
