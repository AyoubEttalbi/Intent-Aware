import asyncio
import json
import re
import aiohttp
from playwright.async_api import async_playwright
from typing import Set, Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
from datetime import datetime
from agent.llm import LLMClient
from agent.models import AppContext, PageContext, FormField


# URL query params that are noise — strip these during normalization
NOISE_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
                "session_id", "sid", "fbclid", "gclid", "_ga", "ref", "source",
                "timestamp", "t", "nonce", "csrf_token"}

# URL path patterns that indicate high-value pages — visit these first
HIGH_PRIORITY_PATTERNS = ["admin", "login", "register", "checkout", "payment",
                           "profile", "settings", "users", "orders", "dashboard",
                           "api", "auth", "config", "manage", "upload"]

# Static asset extensions — skip entirely
STATIC_EXTENSIONS = {".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff",
                     ".woff2", ".ttf", ".gif", ".ico", ".webp", ".map", ".ts"}

GLOBAL_CRAWL_TIMEOUT = 300   # 5 minutes total
MAX_URLS = 75                 # Hard limit on unique normalized URLs


class WebCrawler:
    def __init__(self, base_url: str, app_context: Optional[AppContext] = None,
                 include_subdomains: bool = False):
        self.base_url = base_url.rstrip("/")
        self.app_context = app_context or AppContext()
        self.include_subdomains = include_subdomains

        parsed = urlparse(base_url)
        self.domain = parsed.netloc  # e.g. "localhost:8080"
        self.scheme = parsed.scheme

        # Discovery state
        self.discovered_endpoints: Set[str] = set()
        self.openapi_endpoints: Set[str] = set()
        self.visited_urls: Set[str] = set()        # Normalized URLs
        self.ui_errors: Set[str] = set()
        self.ui_context: Dict[str, PageContext] = {}  # normalized_url -> PageContext

        # Priority queue: list of (priority_score, url)
        # Lower score = higher priority
        self._url_queue: List[tuple] = []

        self.llm = LLMClient()

        with open("crawler_log.txt", "w") as f:
            f.write(f"--- Crawler Log for {base_url} ---\n")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def crawl(self, depth: int = 2) -> dict:
        """
        Crawl the target app. Returns dict with:
          - endpoints: list of discovered endpoint strings
          - ui_context: dict of PageContext objects keyed by normalized URL
        """
        try:
            return await asyncio.wait_for(
                self._crawl_internal(depth),
                timeout=GLOBAL_CRAWL_TIMEOUT
            )
        except asyncio.TimeoutError:
            self._log(f"⏱️ Global crawl timeout ({GLOBAL_CRAWL_TIMEOUT}s) reached. "
                      f"Visited {len(self.visited_urls)} URLs.")
            return self._build_result()

    # ------------------------------------------------------------------
    # Internal crawl
    # ------------------------------------------------------------------

    async def _crawl_internal(self, depth: int) -> dict:
        async with async_playwright() as p:
            self._log("🚀 Launching browser (Headed Mode)...")
            # Added slow_mo and sandbox flags for better visibility and compatibility
            browser = await p.chromium.launch(
                headless=False,
                slow_mo=800,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            )

            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 800}
            )
            page = await context.new_page()
            self._attach_listeners(page)

            # Create visual overlay
            await self._create_overlay(page)

            # Step 1: Fetch OpenAPI spec
            spec = await self._fetch_openapi_spec()
            self._parse_openapi_endpoints(spec)

            # Step 2: Authenticate if app_context has auth info
            authed = await self._handle_auth(page)
            self._log(f"{'✅ Authenticated' if authed else '⚠️ Running unauthenticated'}")

            # Step 3: Seed the queue
            self._seed_queue(depth)

            # Step 4: Process queue
            while self._url_queue and len(self.visited_urls) < MAX_URLS:
                _, current_depth, url = self._pop_queue()
                
                # Update overlay before visiting
                await self._update_overlay(page, url, len(self.visited_urls))
                
                await self._visit_url(page, url, current_depth)

            await browser.close()

        self._print_summary()
        return self._build_result()

    # ------------------------------------------------------------------
    # Visual Overlay Logic
    # ------------------------------------------------------------------

    async def _create_overlay(self, page):
        """Inject a floating status overlay into the page."""
        overlay_html = """
        <div id="agent-overlay" style="
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 320px;
            background: rgba(15, 23, 42, 0.95);
            color: white;
            padding: 20px;
            border-radius: 12px;
            font-family: 'Inter', sans-serif;
            z-index: 10000;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            border: 1px solid rgba(255,255,255,0.1);
            backdrop-filter: blur(8px);
            pointer-events: none;
        ">
            <div style="display: flex; align-items: center; margin-bottom: 12px;">
                <div style="width: 10px; height: 10px; background: #10b981; border-radius: 50%; margin-right: 10px; animation: pulse 1.5s infinite;"></div>
                <strong style="font-size: 14px; color: #94a3b8;">INTENT-AWARE AUDITOR</strong>
            </div>
            <div id="overlay-status" style="font-size: 13px; line-height: 1.5; color: #f8fafc;">Initializing...</div>
            <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.1); margin: 12px 0;">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 12px;">
                <div>Pages: <span id="overlay-visited" style="color: #60a5fa;">0</span></div>
                <div>Queue: <span id="overlay-queue" style="color: #60a5fa;">0</span></div>
                <div>Errors: <span id="overlay-errors" style="color: #ef4444;">0</span></div>
                <div>Shadow: <span id="overlay-shadow" style="color: #fbbf24;">0</span></div>
            </div>
            <style>
                @keyframes pulse {
                    0% { opacity: 1; }
                    50% { opacity: 0.4; }
                    100% { opacity: 1; }
                }
            </style>
        </div>
        """
        try:
            await page.add_init_script(f"""
                const div = document.createElement('div');
                div.innerHTML = `{overlay_html}`;
                document.body.appendChild(div.firstChild);
            """)
        except Exception:
            pass

    async def _update_overlay(self, page, current_url: str, visited_count: int):
        """Update the visual overlay text."""
        try:
            short_url = current_url.replace(self.base_url, "") or "/"
            if len(short_url) > 30:
                short_url = short_url[:27] + "..."
            
            script = f"""
                const status = document.getElementById('overlay-status');
                const visited = document.getElementById('overlay-visited');
                const queue = document.getElementById('overlay-queue');
                const errors = document.getElementById('overlay-errors');
                const shadow = document.getElementById('overlay-shadow');
                
                if (status) status.innerText = "Analyzing: {short_url}";
                if (visited) visited.innerText = "{visited_count}";
                if (queue) queue.innerText = "{len(self._url_queue)}";
                if (errors) errors.innerText = "{len(self.ui_errors)}";
                if (shadow) shadow.innerText = "{len(self.discovered_endpoints)}";
            """
            await page.evaluate(script)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # URL queue management
    # ------------------------------------------------------------------

    def _seed_queue(self, depth: int):
        self._enqueue(self.base_url, depth)
        for route in self.app_context.routes:
            path = route.get("path", "")
            if "{" in path:
                continue
            url = f"{self.base_url}{path}"
            self._enqueue(url, 1)

    def _enqueue(self, url: str, depth: int):
        norm = self._normalize_url(url)
        if not norm or norm in self.visited_urls:
            return
        parsed = urlparse(norm)
        if not self._in_scope(parsed):
            return
        priority = self._priority_score(norm)
        existing = [item for item in self._url_queue if item[2] == norm]
        if not existing:
            self._url_queue.append((priority, depth, norm))
            self._url_queue.sort(key=lambda x: x[0])

    def _pop_queue(self) -> tuple:
        return self._url_queue.pop(0)

    def _priority_score(self, url: str) -> int:
        score = 50
        path = urlparse(url).path.lower()
        for i, pattern in enumerate(HIGH_PRIORITY_PATTERNS):
            if pattern in path:
                score -= (len(HIGH_PRIORITY_PATTERNS) - i)
                break
        return max(0, score)

    # ------------------------------------------------------------------
    # Visit Logic
    # ------------------------------------------------------------------

    async def _visit_url(self, page, url: str, depth: int):
        norm = self._normalize_url(url)
        if not norm or norm in self.visited_urls:
            return
        self.visited_urls.add(norm)
        self._log(f"📍 [{len(self.visited_urls)}/{MAX_URLS}] {norm} (depth={depth})")

        try:
            # Use longer timeout for the first page
            timeout = 30000 if len(self.visited_urls) == 1 else 15000
            await page.goto(norm, wait_until="domcontentloaded", timeout=timeout)
            await self._wait_for_dom_settle(page)

            # Re-inject overlay if it was lost (e.g. navigation to new domain/reload)
            await self._create_overlay(page)
            await self._update_overlay(page, norm, len(self.visited_urls))

            # Extraction
            page_ctx = await self._extract_ui_context(page, norm)
            self.ui_context[norm] = page_ctx

            if depth > 0:
                links = await page.eval_on_selector_all("a[href]", "nodes => nodes.map(n => n.href)")
                
                # Intent-driven prioritization: Ask LLM which links are most "interesting"
                priority_links = await self._get_llm_priority_links(page, links, page_ctx)
                
                for link in priority_links + links:
                    self._enqueue(link, depth - 1)

        except Exception as e:
            self._log(f"⚠️ Failed to visit {norm}: {e}")

    async def _get_llm_priority_links(self, page, links: List[str], ctx: PageContext) -> List[str]:
        """Ask LLM which links are most likely to lead to high-value areas."""
        if not links: return []
        
        # Take a sample of unique link texts/paths
        sample = list(set([urlparse(l).path for l in links if l.startswith(self.base_url)]))[:15]
        
        prompt = (f"I am on a '{ctx.page_role}' page about '{ctx.entity_type}'. "
                  f"Which of these paths are most likely to lead to administrative settings, "
                  f"user management, or sensitive data? List only the paths: {sample}")
        
        raw = self.llm.ask_json(
            system_prompt="Return JSON: {priority_paths: string[]}",
            user_prompt=prompt
        )
        
        priority_paths = raw.get("priority_paths", []) if raw else []
        
        # Map back to full URLs
        result = []
        for l in links:
            if any(p in l for p in priority_paths if p and p != "/"):
                result.append(l)
        return result

    # ------------------------------------------------------------------
    # Context Extraction
    # ------------------------------------------------------------------

    async def _extract_ui_context(self, page, url: str) -> PageContext:
        """Analyze page to build structured PageContext."""
        # Simple extraction of title and url params
        title = await page.title()
        parsed = urlparse(url)
        path_parts = parsed.path.strip("/").split("/")
        url_params = [p for p in path_parts if re.match(r'^\d+$', p)] # Guess numeric IDs

        # Form extraction
        forms = await page.evaluate("""() => {
            const results = [];
            document.querySelectorAll('form').forEach(f => {
                const fields = [];
                f.querySelectorAll('input, select, textarea').forEach(el => {
                    if (el.type === 'submit' || el.type === 'button') return;
                    fields.push({
                        name: el.name || el.id || 'unnamed',
                        field_type: el.type || el.tagName.toLowerCase(),
                        label: el.labels?.[0]?.innerText || el.placeholder || '',
                        placeholder: el.placeholder || '',
                        required: el.required || false,
                        options: el.tagName === 'SELECT' ? Array.from(el.options).map(o => o.value) : [],
                        validation_hint: el.pattern || el.getAttribute('min') || el.getAttribute('max') || ''
                    });
                });
                results.push({
                    action: f.action || '',
                    method: f.method.toUpperCase() || 'GET',
                    submit_label: f.querySelector('button[type="submit"], input[type="submit"]')?.innerText || 'Submit',
                    fields: fields
                });
            });
            return results;
        }""")

        # Convert simple field dicts to FormField objects
        for form in forms:
            form["fields"] = [FormField(**f) for f in form["fields"]]

        # LLM Role inference
        prompt = f"Analyze this page: URL={url}, Title={title}. Forms: {len(forms)}. What is its role (login, dashboard, etc) and entity (user, order)?"
        role_data = self.llm.ask_json(
            system_prompt="Return JSON: {role: string, entity: string}",
            user_prompt=prompt
        ) or {"role": "generic", "entity": "none"}

        return PageContext(
            url=url,
            title=title,
            page_role=role_data.get("role", "generic"),
            forms=forms,
            auth_required=False, # Hard to detect reliably without comparison
            entity_type=role_data.get("entity", "none"),
            url_params=url_params
        )

    # ------------------------------------------------------------------
    # Auth Logic
    # ------------------------------------------------------------------

    async def _handle_auth(self, page) -> bool:
        flow = self.app_context.auth_flow
        if not flow or not (flow.get("login_path") or flow.get("login_url")):
            return False

        login_path = flow.get("login_path") or flow.get("login_url")
        # Fix the "None" issue: if login_path is a full URL, use it. If not, join.
        if login_path.startswith("http"):
            login_url = login_path
        else:
            login_url = f"{self.base_url}/{login_path.lstrip('/')}"

        creds = flow.get("default_credentials", {})
        admin_creds = creds.get("admin") or next(iter(creds.values()), None)
        if not admin_creds:
            return False

        self._log(f"🔑 Authenticating at {login_url}")
        try:
            await page.goto(login_url, wait_until="domcontentloaded", timeout=15000)
            await self._wait_for_dom_settle(page)
            await self._create_overlay(page)

            username_field = flow.get("username_field", "email")
            password_field = flow.get("password_field", "password")

            for sel in [f'[name="{username_field}"]', f'[id="{username_field}"]',
                        '[type="email"]', '[name="username"]', 'input:first-of-type']:
                try:
                    await page.fill(sel, admin_creds.get("username", ""))
                    break
                except Exception:
                    continue

            for sel in [f'[name="{password_field}"]', '[type="password"]']:
                try:
                    await page.fill(sel, admin_creds.get("password", ""))
                    break
                except Exception:
                    continue

            await page.keyboard.press("Enter")
            await self._wait_for_dom_settle(page)

            current = page.url
            success = (login_url not in current) and ("error" not in current.lower())
            self._log(f"{'✅ Auth OK' if success else '❌ Auth failed'} — now at {current}")
            return success

        except Exception as e:
            self._log(f"⚠️ Auth error: {e}")
            return False

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    async def _wait_for_dom_settle(self, page, quiet_ms: int = 400, timeout: int = 6000):
        try:
            await page.wait_for_function(
                f"""() => new Promise(resolve => {{
                    let timer = setTimeout(() => resolve(true), {quiet_ms});
                    const obs = new MutationObserver(() => {{
                        clearTimeout(timer);
                        timer = setTimeout(() => {{ obs.disconnect(); resolve(true); }}, {quiet_ms});
                    }});
                    obs.observe(document.body || document.documentElement,
                                {{childList: true, subtree: true, attributes: true}});
                }})""",
                timeout=timeout
            )
        except Exception:
            pass

    def _normalize_url(self, url: str) -> Optional[str]:
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            filtered_qs = {k: v for k, v in qs.items() if k not in NOISE_PARAMS}
            new_query = urlencode(filtered_qs, doseq=True)
            normalized = urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path.rstrip("/") or "/",
                parsed.params,
                new_query,
                ""
            ))
            return normalized
        except Exception:
            return None

    def _in_scope(self, parsed) -> bool:
        if self.include_subdomains:
            base_domain = self.domain.split(":", 1)[0]
            netloc_host = parsed.netloc.split(":", 1)[0]
            return netloc_host == base_domain or netloc_host.endswith(f".{base_domain}")
        return parsed.netloc == self.domain

    def _attach_listeners(self, page):
        def handle_request(request):
            url = request.url
            parsed = urlparse(url)
            if not self._in_scope(parsed):
                return
            if any(parsed.path.lower().endswith(ext) for ext in STATIC_EXTENSIONS):
                return
            if request.resource_type in ("fetch", "xhr", "document"):
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                self.discovered_endpoints.add(f"{request.method} {clean}")

        def handle_console(msg):
            if msg.type == "error":
                self.ui_errors.add(f"Console error: {msg.text}")

        def handle_response(response):
            if response.status >= 400:
                self.ui_errors.add(f"HTTP {response.status}: {response.url}")

        page.on("request", handle_request)
        page.on("console", handle_console)
        page.on("response", handle_response)

    async def _fetch_openapi_spec(self) -> dict:
        self._log(f"📖 OpenAPI spec at {self.base_url}/openapi.json")
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"{self.base_url}/openapi.json") as resp:
                    if resp.status == 200:
                        return await resp.json()
            except Exception:
                pass
        return {}

    def _parse_openapi_endpoints(self, spec: dict):
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method in methods.keys():
                self.openapi_endpoints.add(f"{method.upper()} {path}")

    def _log(self, msg: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {msg}"
        print(line)
        with open("crawler_log.txt", "a") as f:
            f.write(line + "\n")

    def _print_summary(self):
        self._log("\n" + "="*50)
        self._log(f"📖 OpenAPI endpoints: {len(self.openapi_endpoints)}")
        self._log(f"📂 Shadow endpoints: {len(self.discovered_endpoints)}")
        self._log(f"🖥️  Pages with UIContext: {len(self.ui_context)}")
        self._log(f"🚩 UI errors: {len(self.ui_errors)}")
        for err in self.ui_errors:
            self._log(f"   - {err}")
        self._log("="*50 + "\n")

    def _build_result(self) -> dict:
        return {
            "endpoints": list(self.discovered_endpoints),
            "ui_context": self.ui_context
        }
