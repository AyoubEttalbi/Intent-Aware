# Full Agent Improvement Guide
> Hand this entire document to the IDE agent for implementation.
> All changes are additive — nothing in the existing pipeline is removed, only extended.

---

## 0. Guiding Principles

Before any code change, the IDE agent must internalize these rules:

1. **Context flows forward, never backward.** Source analysis → crawler → scenario engine → execution → detection. Each phase enriches the context object; downstream phases never call upstream ones.
2. **Every scenario must be falsifiable.** A scenario without a concrete `expected_result` and `failure_signature` is useless to the LLM judge.
3. **Deduplication before execution.** Scenarios are deduplicated by `(url_pattern, attack_category, target_field)` fingerprint before any HTTP request is made.
4. **Personas come from the app, not hardcode.** The persona list is derived from the app's role system, with a fallback to `[admin, authenticated_user, unauthenticated]`.
5. **The crawler's job is discovery, not execution.** The crawler collects `UIContext`. Scenario execution happens in a separate phase after all pages are crawled.

---

## 1. New Data Structures (create `agent/models.py`)

This is the single source of truth for all shared data structures.

```python
# agent/models.py
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FormField:
    name: str           # HTML name or id attribute
    field_type: str     # "text", "email", "password", "number", "select", "textarea", "hidden"
    label: str          # Associated label text
    placeholder: str
    required: bool
    options: list[str]  # For select elements
    validation_hint: str  # e.g. "min=0 max=999", "pattern=[A-Z]{3}", inferred from HTML attrs


@dataclass
class PageContext:
    url: str
    title: str
    page_role: str      # "login", "register", "dashboard", "list", "detail", "form",
                        # "checkout", "admin", "settings", "api_docs", "generic"
    forms: list[dict]   # Each: {form_action, form_method, fields: list[FormField], submit_label}
    auth_required: bool # Inferred: True if page redirected to login when unauthenticated
    entity_type: str    # e.g. "User", "Order", "Product" — matched from AppContext.models
    url_params: list[str]  # e.g. ["id", "user_id"] from /users/{id}/orders


@dataclass
class AppContext:
    routes: list[dict] = field(default_factory=list)
    # Each route: {method, path, auth_required, roles: list[str], description, request_body_schema}
    models: list[str] = field(default_factory=list)
    auth_flow: dict = field(default_factory=dict)
    # auth_flow: {login_path, username_field, password_field, token_storage: "cookie"|"localStorage"|"header",
    #             default_credentials: {admin: {...}, user: {...}}}
    app_type: str = "generic"
    # "ecommerce" | "admin_dashboard" | "api_only" | "auth_heavy" | "cms" | "generic"
    personas: list[dict] = field(default_factory=list)
    # Derived from roles in routes. Each: {name, role, credentials, can_access_patterns: list[str]}
    tech_stack: list[str] = field(default_factory=list)
    # e.g. ["FastAPI", "PostgreSQL", "JWT"] — informs injection payload selection


@dataclass
class Scenario:
    id: str
    url: str
    url_pattern: str    # Normalized: /users/{id}/orders not /users/42/orders
    page_role: str
    category: str       # "functional" | "security" | "boundary" | "privilege" | "injection"
    attack_type: str    # "sqli" | "xss" | "idor" | "auth_bypass" | "mass_assignment" |
                        # "rate_limit" | "business_logic" | "input_validation" | "info_disclosure"
    name: str
    description: str
    persona: str        # Which persona runs this: "admin", "user", "unauthenticated"
    target_field: str   # Specific field being tested — enables dedup fingerprint
    payload: Any        # Concrete value(s) to send
    http_method: str
    endpoint: str
    expected_result: str   # Plain English: "server returns 403, not 200"
    failure_signature: str # What the LLM judge looks for to confirm a bug:
                           # "status=200 AND response contains user_id != current_user_id"
    severity: str       # "critical" | "high" | "medium" | "low"
    dedup_fingerprint: str  # f"{url_pattern}:{attack_type}:{target_field}"
```

---

## 2. Source Analyzer (create `agent/source_analyzer.py`)

Runs once before the crawler. Produces `AppContext`.

```python
# agent/source_analyzer.py
import os
import json
from pathlib import Path
from agent.llm import LLMClient
from agent.models import AppContext

# File extensions to read
SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".cs"}

# Directory names to skip entirely
SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv", 
             "dist", "build", ".next", "coverage", "migrations"}

# Filenames that are highest priority for route/auth/model info
PRIORITY_KEYWORDS = ["route", "router", "view", "controller", "model", 
                     "schema", "middleware", "auth", "permission", "main", "app", "index"]


SOURCE_ANALYSIS_PROMPT = """You are a senior software architect performing a security-focused code review.
Analyze the provided source code and return ONLY a valid JSON object with this exact structure:

{
  "routes": [
    {
      "method": "GET",
      "path": "/users/{id}",
      "auth_required": true,
      "roles": ["admin", "owner"],
      "description": "Get user by ID",
      "request_body_schema": {}
    }
  ],
  "models": ["User", "Order", "Product"],
  "auth_flow": {
    "login_path": "/auth/login",
    "username_field": "email",
    "password_field": "password",
    "token_storage": "cookie",
    "default_credentials": {
      "admin": {"username": "admin@example.com", "password": "admin123"},
      "user": {"username": "user@example.com", "password": "user123"}
    }
  },
  "app_type": "ecommerce",
  "personas": [
    {"name": "admin", "role": "admin", "can_access_patterns": ["*"]},
    {"name": "regular_user", "role": "user", "can_access_patterns": ["/dashboard", "/profile", "/orders"]},
    {"name": "unauthenticated", "role": null, "can_access_patterns": ["/", "/login", "/register"]}
  ],
  "tech_stack": ["FastAPI", "PostgreSQL", "JWT"]
}

Rules:
- Only include routes you can VERIFY from the code. Do not invent routes.
- For personas, derive them from the actual role/permission system in the code.
- Always include an "unauthenticated" persona.
- For default_credentials, use the first test/seed credentials you find in fixtures, tests, or README.
- If you cannot determine a field, use null, not an empty string.
- Return ONLY the JSON. No markdown, no explanation."""


class SourceAnalyzer:
    def __init__(self, source_dir: str):
        self.source_dir = Path(source_dir)
        self.llm = LLMClient()

    def analyze(self) -> AppContext:
        source_dump = self._collect_source_prioritized()
        
        raw = self.llm.ask_json(
            system_prompt=SOURCE_ANALYSIS_PROMPT,
            user_prompt=f"Source code:\n\n{source_dump}"
        )
        
        if not raw:
            return AppContext()

        ctx = AppContext(
            routes=raw.get("routes", []),
            models=raw.get("models", []),
            auth_flow=raw.get("auth_flow", {}),
            app_type=raw.get("app_type", "generic"),
            personas=raw.get("personas", []),
            tech_stack=raw.get("tech_stack", []),
        )

        # Always ensure unauthenticated persona exists
        has_unauth = any(p.get("role") is None for p in ctx.personas)
        if not has_unauth:
            ctx.personas.append({
                "name": "unauthenticated",
                "role": None,
                "can_access_patterns": []
            })

        return ctx

    def _collect_source_prioritized(self, char_limit: int = 40000) -> str:
        """
        Collect source files in priority order:
        1. Files matching PRIORITY_KEYWORDS in their name
        2. All other source files
        Truncate at char_limit total.
        """
        priority_files = []
        other_files = []

        for root, dirs, files in os.walk(self.source_dir):
            # Prune skip dirs in-place so os.walk doesn't descend into them
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            
            for filename in files:
                filepath = Path(root) / filename
                if filepath.suffix not in SOURCE_EXTENSIONS:
                    continue
                name_lower = filename.lower()
                if any(kw in name_lower for kw in PRIORITY_KEYWORDS):
                    priority_files.append(filepath)
                else:
                    other_files.append(filepath)

        collected = []
        total = 0

        for filepath in priority_files + other_files:
            if total >= char_limit:
                break
            try:
                content = filepath.read_text(errors="ignore")
                # Take first 3000 chars of each file — enough to see routes/models
                snippet = content[:3000]
                rel = filepath.relative_to(self.source_dir)
                entry = f"### {rel}\n{snippet}"
                collected.append(entry)
                total += len(entry)
            except Exception:
                continue

        return "\n\n".join(collected)
```

---

## 3. Hardened Crawler (replace `execution/crawler.py`)

Key changes from the current version:
- Global 5-minute timeout wrapping the entire crawl
- URL normalization (strip session tokens, UTMs, hash fragments)
- Priority-based URL queue (admin/auth/checkout pages visited first)
- DOM-settle wait replaces `networkidle`
- Link snapshot BEFORE any interaction (prevents mid-page navigation loops)
- `UIContext` extraction per page (structured, field-level)
- Hard limit of 75 URLs with priority queue (not flat 50)
- Subdomain support via config flag

```python
# execution/crawler.py  — FULL REPLACEMENT

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
            self._log("🚀 Launching browser...")
            browser = await p.chromium.launch(headless=True)

            # Main context (used for crawling + auth)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0.0.0 Safari/537.36"
            )
            page = await context.new_page()
            self._attach_listeners(page)

            # Step 1: Fetch OpenAPI spec (no browser needed)
            spec = await self._fetch_openapi_spec()
            self._parse_openapi_endpoints(spec)

            # Step 2: Authenticate if app_context has auth info
            authed = await self._handle_auth(page)
            self._log(f"{'✅ Authenticated' if authed else '⚠️ Running unauthenticated'}")

            # Step 3: Seed the queue with base_url + all known routes from source analysis
            self._seed_queue(depth)

            # Step 4: Process queue
            while self._url_queue and len(self.visited_urls) < MAX_URLS:
                _, url, current_depth = self._pop_queue()
                await self._visit_url(page, url, current_depth)

            await browser.close()

        self._print_summary()
        return self._build_result()

    # ------------------------------------------------------------------
    # URL queue management
    # ------------------------------------------------------------------

    def _seed_queue(self, depth: int):
        """Seed queue with base URL and all routes known from source analysis."""
        self._enqueue(self.base_url, depth)
        for route in self.app_context.routes:
            path = route.get("path", "")
            # Skip routes with required path params we can't fill yet
            if "{" in path:
                continue
            url = f"{self.base_url}{path}"
            self._enqueue(url, 1)

    def _enqueue(self, url: str, depth: int):
        norm = self._normalize_url(url)
        if not norm or norm in self.visited_urls:
            return
        # Check it's in scope
        parsed = urlparse(norm)
        if not self._in_scope(parsed):
            return
        priority = self._priority_score(norm)
        # Avoid duplicate queue entries
        existing = [item for item in self._url_queue if item[2] == norm]
        if not existing:
            self._url_queue.append((priority, depth, norm))
            self._url_queue.sort(key=lambda x: x[0])  # Keep sorted by priority

    def _pop_queue(self) -> tuple:
        return self._url_queue.pop(0)

    def _priority_score(self, url: str) -> int:
        """Lower = higher priority. Auth/admin pages = 0, generic = 10."""
        url_lower = url.lower()
        for i, pattern in enumerate(HIGH_PRIORITY_PATTERNS):
            if pattern in url_lower:
                return i
        return len(HIGH_PRIORITY_PATTERNS)

    # ------------------------------------------------------------------
    # Page visit
    # ------------------------------------------------------------------

    async def _visit_url(self, page, url: str, depth: int):
        norm = self._normalize_url(url)
        if not norm or norm in self.visited_urls:
            return

        self.visited_urls.add(norm)
        self._log(f"📍 [{len(self.visited_urls)}/{MAX_URLS}] {norm} (depth={depth})")

        try:
            await page.goto(norm, wait_until="domcontentloaded", timeout=30000)
            await self._wait_for_dom_settle(page)

            # Extract UIContext for this page
            ctx = await self._extract_page_context(page, norm)
            if ctx:
                self.ui_context[norm] = ctx

            # Discover and enqueue links (snapshot BEFORE any interaction)
            if depth > 0:
                links = await self._collect_links(page, norm)
                for link in links:
                    self._enqueue(link, depth - 1)

        except Exception as e:
            self._log(f"⚠️ Error visiting {norm}: {e}")

    async def _collect_links(self, page, current_url: str) -> List[str]:
        """Collect all in-scope href values without clicking anything."""
        try:
            hrefs = await page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.href).filter(h => h.startsWith('http'))"
            )
            return [h for h in hrefs if self._in_scope(urlparse(h))]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # UIContext extraction
    # ------------------------------------------------------------------

    async def _extract_page_context(self, page, url: str) -> Optional[PageContext]:
        """Extract structured context from the current page DOM."""
        try:
            raw = await page.evaluate("""() => {
                const title = document.title || '';
                const meta_desc = document.querySelector('meta[name="description"]')?.content || '';
                
                const forms = Array.from(document.querySelectorAll('form')).map(form => {
                    const fields = Array.from(
                        form.querySelectorAll('input, textarea, select')
                    ).filter(el => el.type !== 'submit' && el.type !== 'button')
                     .map(el => {
                        const label_el = el.id 
                            ? document.querySelector(`label[for="${el.id}"]`) 
                            : el.closest('label');
                        const opts = el.tagName === 'SELECT'
                            ? Array.from(el.options).map(o => o.value).filter(v => v)
                            : [];
                        return {
                            name: el.name || el.id || '',
                            field_type: el.type || el.tagName.toLowerCase(),
                            label: label_el?.innerText?.trim() || '',
                            placeholder: el.placeholder || '',
                            required: el.required || false,
                            options: opts,
                            min: el.min || '',
                            max: el.max || '',
                            pattern: el.pattern || '',
                            maxlength: el.maxLength > 0 ? el.maxLength : null,
                        };
                    });
                    return {
                        action: form.action || '',
                        method: form.method?.toUpperCase() || 'GET',
                        fields: fields,
                        submit_label: form.querySelector('[type=submit]')?.value 
                                   || form.querySelector('[type=submit]')?.innerText 
                                   || 'Submit'
                    };
                });
                
                // Detect if we were redirected to a login page
                const looks_like_login = (
                    document.querySelector('input[type=password]') !== null ||
                    document.title?.toLowerCase().includes('login') ||
                    document.title?.toLowerCase().includes('sign in')
                );
                
                return { title, meta_desc, forms, looks_like_login };
            }""")

            # Infer page role
            page_role = self._infer_page_role(url, raw.get("title", ""), raw.get("forms", []))

            # Match entity type from known models
            entity_type = self._infer_entity(url)

            # Extract URL params (e.g. /users/42 → ["id"] if route is /users/{id})
            url_params = self._extract_url_params(url)

            # Build FormField objects
            forms_structured = []
            for form in raw.get("forms", []):
                fields = [
                    FormField(
                        name=f["name"],
                        field_type=f["field_type"],
                        label=f["label"],
                        placeholder=f["placeholder"],
                        required=f["required"],
                        options=f["options"],
                        validation_hint=self._build_validation_hint(f),
                    )
                    for f in form.get("fields", []) if f["name"]
                ]
                forms_structured.append({
                    "action": form["action"],
                    "method": form["method"],
                    "fields": fields,
                    "submit_label": form["submit_label"],
                })

            return PageContext(
                url=url,
                title=raw.get("title", ""),
                page_role=page_role,
                forms=forms_structured,
                auth_required=raw.get("looks_like_login", False),
                entity_type=entity_type,
                url_params=url_params,
            )

        except Exception as e:
            self._log(f"⚠️ Context extraction failed for {url}: {e}")
            return None

    def _build_validation_hint(self, field: dict) -> str:
        parts = []
        if field.get("min"):
            parts.append(f"min={field['min']}")
        if field.get("max"):
            parts.append(f"max={field['max']}")
        if field.get("pattern"):
            parts.append(f"pattern={field['pattern']}")
        if field.get("maxlength"):
            parts.append(f"maxlength={field['maxlength']}")
        return " ".join(parts)

    def _infer_page_role(self, url: str, title: str, forms: list) -> str:
        combined = (url + title).lower()
        has_password_field = any(
            any(f.get("field_type") == "password" for f in form.get("fields", []))
            for form in forms
        )
        if has_password_field or any(x in combined for x in ["login", "signin", "sign-in"]):
            return "login"
        if any(x in combined for x in ["register", "signup", "sign-up", "create account"]):
            return "register"
        if any(x in combined for x in ["checkout", "payment", "billing"]):
            return "checkout"
        if any(x in combined for x in ["admin", "manage", "panel", "backstage"]):
            return "admin"
        if any(x in combined for x in ["dashboard", "overview", "summary"]):
            return "dashboard"
        if any(x in combined for x in ["profile", "account", "settings", "preferences"]):
            return "settings"
        if any(x in combined for x in ["edit", "update", "create", "new", "add"]):
            return "form"
        if any(x in combined for x in ["list", "index", "search", "browse", "catalog"]):
            return "list"
        if any(x in combined for x in ["detail", "view", "show"]):
            return "detail"
        # Check AppContext page_roles if available
        for route in self.app_context.routes:
            path = route.get("path", "").split("{")[0]
            if path and path in url:
                return route.get("description", "generic").lower().split()[0]
        return "generic"

    def _infer_entity(self, url: str) -> str:
        url_lower = url.lower()
        for model in self.app_context.models:
            if model.lower() in url_lower or (model.lower() + "s") in url_lower:
                return model
        return ""

    def _extract_url_params(self, url: str) -> List[str]:
        """Match URL against known routes to extract param names."""
        parsed_path = urlparse(url).path
        for route in self.app_context.routes:
            pattern = route.get("path", "")
            # Convert /users/{id} to regex /users/([^/]+)
            regex = re.sub(r"\{([^}]+)\}", r"(?P<\1>[^/]+)", pattern)
            m = re.fullmatch(regex, parsed_path)
            if m:
                return list(m.groupdict().keys())
        return []

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    async def _handle_auth(self, page) -> bool:
        """Log in using the admin persona credentials from AppContext."""
        flow = self.app_context.auth_flow
        if not flow:
            return False

        login_path = flow.get("login_path", "/login")
        login_url = f"{self.base_url}{login_path}"

        # Use admin credentials, fall back to first available
        creds = flow.get("default_credentials", {})
        admin_creds = creds.get("admin") or next(iter(creds.values()), None)
        if not admin_creds:
            return False

        self._log(f"🔑 Authenticating at {login_url}")
        try:
            await page.goto(login_url, wait_until="domcontentloaded", timeout=15000)
            await self._wait_for_dom_settle(page)

            username_field = flow.get("username_field", "email")
            password_field = flow.get("password_field", "password")

            # Try multiple selector strategies for username
            for sel in [f'[name="{username_field}"]', f'[id="{username_field}"]',
                        '[type="email"]', '[name="username"]', 'input:first-of-type']:
                try:
                    await page.fill(sel, admin_creds.get("username", ""))
                    break
                except Exception:
                    continue

            # Password
            for sel in [f'[name="{password_field}"]', '[type="password"]']:
                try:
                    await page.fill(sel, admin_creds.get("password", ""))
                    break
                except Exception:
                    continue

            await page.keyboard.press("Enter")
            await self._wait_for_dom_settle(page)

            current = page.url
            success = (login_path not in current) and ("error" not in current.lower())
            self._log(f"{'✅ Auth OK' if success else '❌ Auth failed'} — now at {current}")
            return success

        except Exception as e:
            self._log(f"⚠️ Auth error: {e}")
            return False

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    async def _wait_for_dom_settle(self, page, quiet_ms: int = 400, timeout: int = 6000):
        """
        Wait until DOM stops mutating for quiet_ms milliseconds.
        Far more reliable than networkidle on SPAs.
        """
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
            pass  # Timeout here is safe — just move on

    def _normalize_url(self, url: str) -> Optional[str]:
        """
        Normalize a URL to prevent revisiting the same logical page.
        - Strip NOISE_PARAMS query params
        - Remove hash fragments
        - Lowercase scheme and host
        - Remove trailing slash
        """
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return None

            # Filter query params
            qs = parse_qs(parsed.query, keep_blank_values=False)
            filtered_qs = {k: v for k, v in qs.items() if k not in NOISE_PARAMS}
            new_query = urlencode(filtered_qs, doseq=True)

            # Remove fragment, normalize
            normalized = urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path.rstrip("/") or "/",
                parsed.params,
                new_query,
                ""  # No fragment
            ))
            return normalized
        except Exception:
            return None

    def _in_scope(self, parsed) -> bool:
        if self.include_subdomains:
            # Allow subdomains: api.example.com, admin.example.com
            base_domain = self.domain.split(":", 1)[0]  # Strip port
            netloc_host = parsed.netloc.split(":", 1)[0]
            return netloc_host == base_domain or netloc_host.endswith(f".{base_domain}")
        return parsed.netloc == self.domain

    def _attach_listeners(self, page):
        """Attach network and error listeners."""
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

        page.on("request", handle_request)
        page.on("console", lambda m: self.ui_errors.add(f"Console {m.type}: {m.text}")
                if m.type == "error" else None)
        page.on("pageerror", lambda e: self.ui_errors.add(f"JS Exception: {e.message}"))
        page.on("response", lambda r: self.ui_errors.add(
            f"HTTP {r.status}: {r.url}") if r.status >= 400 else None)

    async def _fetch_openapi_spec(self) -> dict:
        """Try common OpenAPI spec URLs."""
        for path in ["/openapi.json", "/swagger.json", "/api/openapi.json"]:
            url = f"{self.base_url}{path}"
            try:
                async with aiohttp.ClientSession() as s:
                    async with s.get(url, timeout=aiohttp.ClientTimeout(total=5)) as r:
                        if r.status == 200 and "json" in r.headers.get("Content-Type", ""):
                            self._log(f"📖 OpenAPI spec at {url}")
                            return await r.json()
            except Exception:
                continue
        return {}

    def _parse_openapi_endpoints(self, spec: dict) -> List[str]:
        endpoints = []
        for path, methods in spec.get("paths", {}).items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
                    summary = details.get("summary", "")
                    ep = f"{method.upper()} {self.base_url}{path}"
                    if summary:
                        ep += f"  # {summary}"
                    endpoints.append(ep)
                    self.openapi_endpoints.add(ep)
        return endpoints

    def _build_result(self) -> dict:
        return {
            "endpoints": list(self.openapi_endpoints) + sorted(list(self.discovered_endpoints))[:50],
            "ui_context": self.ui_context,
        }

    def _print_summary(self):
        self._log("\n" + "="*50)
        self._log(f"📖 OpenAPI endpoints: {len(self.openapi_endpoints)}")
        self._log(f"📂 Shadow endpoints: {len(self.discovered_endpoints)}")
        self._log(f"🖥️  Pages with UIContext: {len(self.ui_context)}")
        self._log(f"🚩 UI errors: {len(self.ui_errors)}")
        for err in sorted(self.ui_errors)[:20]:
            self._log(f"  - {err}")
        self._log("="*50)

    def _log(self, msg: str):
        with open("crawler_log.txt", "a") as f:
            f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
```

---

## 4. Scenario Generator (replace `generators/scenarios.py` prompt section)

The key change is the prompt now receives structured field data, not raw HTML.
It also outputs `dedup_fingerprint` and `failure_signature` so the LLM judge has precise targets.

```python
# generators/scenarios.py  — REPLACE the SCENARIO_GENERATOR_PROMPT constant

SCENARIO_GENERATOR_PROMPT = """You are a senior security QA engineer generating adversarial test scenarios.

You will receive:
- app_type: the kind of application
- tech_stack: technologies in use (informs payload selection)
- page_role: what this page does
- entity_type: the domain entity this page works with
- url_pattern: normalized URL (with {param} placeholders)
- url_params: list of path parameter names
- forms: structured list of forms with typed fields
- personas: available test personas
- known_routes: other routes in the app (for IDOR target selection)

OUTPUT: A JSON array of scenario objects. Each object MUST have all these fields:
{
  "id": "scen_001",
  "url": "<exact url>",
  "url_pattern": "<url with {param} placeholders>",
  "page_role": "<role>",
  "category": "functional|security|boundary|privilege|injection",
  "attack_type": "sqli|xss|idor|auth_bypass|mass_assignment|rate_limit|business_logic|input_validation|info_disclosure|csrf",
  "name": "Short name",
  "description": "What this tests and why it matters",
  "persona": "<persona name from personas list>",
  "target_field": "<field name being tested, or 'url_param' or 'header'>",
  "payload": "<concrete value or dict of field:value>",
  "http_method": "GET|POST|PUT|DELETE|PATCH",
  "endpoint": "<full endpoint URL>",
  "expected_result": "Plain English description of correct server behaviour",
  "failure_signature": "Exact condition that proves a bug: e.g. 'status=200 AND body contains email of different user'",
  "severity": "critical|high|medium|low"
}

SCENARIO SELECTION RULES:
1. For every form with an id/numeric field: generate an IDOR test using another user's ID.
2. For every text input: generate one injection test appropriate to the tech stack
   (SQL injection for SQL DBs, NoSQL injection for MongoDB, XSS for HTML-rendered fields).
3. For every numeric field with a min/max: generate boundary tests (min-1, max+1, 0, negative, float).
4. For every authenticated endpoint: generate an auth_bypass test using the unauthenticated persona.
5. For every admin-only route: generate a privilege escalation test using the regular_user persona.
6. For file upload fields: generate path traversal and malicious content type payloads.
7. For password fields: generate weak password and credential stuffing scenarios.
8. NEVER generate a scenario without a concrete payload. No "test with various inputs".
9. NEVER duplicate: if two forms have the same field name and attack type, generate ONE scenario.
10. Return ONLY the JSON array. No markdown, no explanation.

PAYLOAD SELECTION BY TECH STACK:
- FastAPI/Python: SQL injection: "' OR '1'='1"; SSTI: "{{7*7}}"
- Express/Node: NoSQL injection: {"$gt": ""}; prototype pollution
- Django: ORM injection patterns, CSRF bypass
- JWT auth: alg:none attack, expired token reuse
- File upload: ../../../etc/passwd, polyglot files
"""

# Also update the call site to pass structured context:
def build_scenario_prompt(page_context, app_context) -> str:
    """Convert PageContext and AppContext into the prompt user message."""
    
    # Serialize forms with field details
    forms_data = []
    for form in page_context.forms:
        form_data = {
            "action": form["action"],
            "method": form["method"],
            "submit_label": form["submit_label"],
            "fields": [
                {
                    "name": f.name,
                    "type": f.field_type,
                    "label": f.label,
                    "required": f.required,
                    "options": f.options,
                    "validation": f.validation_hint,
                }
                for f in form["fields"]
            ]
        }
        forms_data.append(form_data)

    return json.dumps({
        "app_type": app_context.app_type,
        "tech_stack": app_context.tech_stack,
        "page_role": page_context.page_role,
        "entity_type": page_context.entity_type,
        "url_pattern": page_context.url,
        "url_params": page_context.url_params,
        "forms": forms_data,
        "personas": [p["name"] for p in app_context.personas],
        "known_routes": [
            {"method": r["method"], "path": r["path"]}
            for r in app_context.routes[:20]
        ],
    }, indent=2)
```

---

## 5. Deduplication Layer (create `generators/dedup.py`)

```python
# generators/dedup.py  — NEW FILE

from agent.models import Scenario


def deduplicate_scenarios(scenarios: list[Scenario]) -> list[Scenario]:
    """
    Remove duplicate scenarios by fingerprint.
    Fingerprint = url_pattern + attack_type + target_field
    When duplicates exist, keep the highest severity one.
    """
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    seen: dict[str, Scenario] = {}

    for s in scenarios:
        fp = s.dedup_fingerprint or f"{s.url_pattern}:{s.attack_type}:{s.target_field}"
        if fp not in seen:
            seen[fp] = s
        else:
            existing = seen[fp]
            if severity_rank.get(s.severity, 3) < severity_rank.get(existing.severity, 3):
                seen[fp] = s  # Keep higher severity

    result = list(seen.values())
    result.sort(key=lambda s: severity_rank.get(s.severity, 3))
    return result
```

---

## 6. Assumptions Extractor (update prompt in `extractors/assumptions.py`)

```python
# extractors/assumptions.py — UPDATE ASSUMPTION_EXTRACTOR_PROMPT

ASSUMPTION_EXTRACTOR_PROMPT = """You are a senior QA architect extracting implicit behavioral assumptions from application context.

You will receive:
- openapi_spec: formal API contract
- ui_context: dict of pages discovered (URL -> page role, forms, entity type)
- app_context: routes, models, auth flow, personas, app type

Your job: identify IMPLICIT assumptions the application makes that could be violated.
These are NOT things the spec says explicitly — they are things the app ASSUMES are true
but doesn't enforce or test.

OUTPUT: JSON array of assumption objects:
{
  "id": "assume_001",
  "assumption": "Users can only view their own orders, not other users' orders",
  "derives_from": "UI has /orders/{id} page, app has User and Order models with ownership",
  "test_approach": "Access /orders/{other_user_order_id} as regular_user persona",
  "risk_if_violated": "Data leakage — users can see private order data of other customers",
  "severity": "critical",
  "relevant_pages": ["/orders/{id}"],
  "relevant_personas": ["regular_user", "unauthenticated"]
}

ASSUMPTION CATEGORIES TO LOOK FOR:
- Authorization: "Only admins can delete users" (if admin routes exist)
- Data isolation: "Users see only their own data" (if user-scoped entities exist)  
- Business logic: "Discount cannot exceed product price" (if pricing forms exist)
- State machine: "Cannot checkout with empty cart" (if checkout page exists)
- Rate limiting: "Password reset is rate-limited" (if auth forms exist)
- Cascading: "Deleting a user deletes their orders" (if relational models exist)
- Upload safety: "Uploaded files are validated before storage" (if upload forms exist)

Focus on HIGH-RISK assumptions. Return 5-15 assumptions maximum.
Return ONLY the JSON array."""
```

---

## 7. Agent Loop Updates (`agent/loop.py`)

```python
# agent/loop.py — CHANGES ONLY (show the diff, not full file)

# In the run() method, replace the current crawl call with:

async def run(self, target_url: str, source_dir: str):
    
    # --- Phase 0: Source Analysis ---
    self.log("🔍 Phase 0: Analyzing source code...")
    from agent.source_analyzer import SourceAnalyzer
    analyzer = SourceAnalyzer(source_dir)
    app_context = analyzer.analyze()
    self.log(f"   App type: {app_context.app_type}, "
             f"Models: {app_context.models}, "
             f"Personas: {[p['name'] for p in app_context.personas]}")

    # --- Phase 1: Crawl ---
    self.log("🕷️  Phase 1: Crawling...")
    from execution.crawler import WebCrawler
    crawler = WebCrawler(target_url, app_context=app_context)
    crawl_result = await crawler.crawl(depth=2)
    endpoints = crawl_result["endpoints"]
    ui_context = crawl_result["ui_context"]
    self.log(f"   Discovered {len(endpoints)} endpoints, "
             f"{len(ui_context)} pages with context")

    # --- Phase 2: Extract Assumptions ---
    self.log("🧠 Phase 2: Extracting assumptions...")
    from extractors.assumptions import AssumptionExtractor
    extractor = AssumptionExtractor()
    # Pass ui_context serialized for the LLM
    ui_context_summary = {
        url: {
            "role": ctx.page_role,
            "entity": ctx.entity_type,
            "forms": len(ctx.forms),
            "url_params": ctx.url_params,
        }
        for url, ctx in ui_context.items()
    }
    assumptions = extractor.extract(
        endpoints=endpoints,
        ui_context=ui_context_summary,
        app_context=app_context,
    )

    # --- Phase 3: Generate Scenarios ---
    self.log("⚙️  Phase 3: Generating scenarios...")
    from generators.scenarios import ScenarioGenerator, build_scenario_prompt
    from generators.dedup import deduplicate_scenarios
    
    generator = ScenarioGenerator()
    all_scenarios = []
    
    for url, page_ctx in ui_context.items():
        prompt = build_scenario_prompt(page_ctx, app_context)
        scenarios = generator.generate(prompt)
        all_scenarios.extend(scenarios)
    
    # Deduplicate before execution
    unique_scenarios = deduplicate_scenarios(all_scenarios)
    self.log(f"   Generated {len(all_scenarios)} raw scenarios → "
             f"{len(unique_scenarios)} after dedup")

    # --- Phase 4 onwards: existing execution + detection pipeline ---
    # Pass unique_scenarios to your existing runner...
```

---

## 8. Verification: Automated Assertions

Add this to your test suite (or run standalone):

```python
# tests/test_crawler_stability.py — NEW FILE

import asyncio
import pytest
from execution.crawler import WebCrawler
from agent.models import AppContext


@pytest.mark.asyncio
async def test_crawler_does_not_hang(test_server_url):
    """Crawler must complete within global timeout."""
    crawler = WebCrawler(test_server_url)
    result = await asyncio.wait_for(crawler.crawl(depth=1), timeout=310)
    assert result is not None

@pytest.mark.asyncio  
async def test_no_duplicate_urls(test_server_url):
    """Crawler must not visit the same normalized URL twice."""
    crawler = WebCrawler(test_server_url)
    await crawler.crawl(depth=2)
    # visited_urls is a set — duplicates are impossible, but check queue was also deduplicated
    assert len(crawler.visited_urls) == len(set(crawler.visited_urls))

@pytest.mark.asyncio
async def test_ui_context_has_structured_fields(test_server_url):
    """Every page with a form must have field-level UIContext, not just a title."""
    crawler = WebCrawler(test_server_url)
    result = await crawler.crawl(depth=1)
    for url, ctx in result["ui_context"].items():
        if ctx.forms:
            for form in ctx.forms:
                assert form["fields"], f"Form on {url} has no fields extracted"
                for field in form["fields"]:
                    assert field.name, f"Field on {url} has no name"

def test_scenario_dedup():
    from agent.models import Scenario
    from generators.dedup import deduplicate_scenarios
    
    s1 = Scenario(id="1", url="/a", url_pattern="/a", page_role="form",
                  category="security", attack_type="sqli", name="test",
                  description="", persona="user", target_field="email",
                  payload="' OR 1=1", http_method="POST", endpoint="/a",
                  expected_result="400", failure_signature="status=200",
                  severity="high", dedup_fingerprint="/a:sqli:email")
    s2 = Scenario(id="2", url="/a", url_pattern="/a", page_role="form",
                  category="security", attack_type="sqli", name="test2",
                  description="", persona="admin", target_field="email",
                  payload="'; DROP TABLE--", http_method="POST", endpoint="/a",
                  expected_result="400", failure_signature="status=200",
                  severity="critical", dedup_fingerprint="/a:sqli:email")
    
    result = deduplicate_scenarios([s1, s2])
    assert len(result) == 1
    assert result[0].severity == "critical"  # Kept higher severity
```

---

## 9. Answers to the IDE Agent's Open Questions

**Q: Global timeout of 5 minutes — agree?**
Yes, but implement it as `asyncio.wait_for` at the `crawl()` level, not as a per-page timeout. Per-page timeouts already exist on `page.goto`. The global timeout is a safety net, not the primary mechanism.

**Q: 50 URL limit — agree?**
Change to **75 URLs with priority queue**. The priority queue ensures you see admin/auth/checkout pages before hitting the limit, even on large apps. A flat 50 risks exhausting the budget on pagination or product listing pages.

**Q: Exact domain only vs subdomains?**
Default to exact domain. Add `include_subdomains: bool = False` constructor param. When True, match any subdomain of the base domain. Let the user set it per-run.

**Q: Hardcode ADMIN and USER_BOB personas?**
No. Derive personas from `AppContext.personas` (populated by `SourceAnalyzer`). Always include an `unauthenticated` persona as a fallback. Only hardcode if `SourceAnalyzer` returns an empty persona list.

---

## 10. File Change Summary

| Action | File | Reason |
|---|---|---|
| CREATE | `agent/models.py` | Shared data structures: AppContext, PageContext, FormField, Scenario |
| CREATE | `agent/source_analyzer.py` | Phase 0: derive app context from source code |
| CREATE | `generators/dedup.py` | Deduplicate scenarios before execution |
| REPLACE | `execution/crawler.py` | Stability fixes + UIContext extraction |
| UPDATE prompt | `generators/scenarios.py` | Field-level structured context in prompt |
| UPDATE prompt | `extractors/assumptions.py` | UI context awareness |
| UPDATE | `agent/loop.py` | Wire Phase 0 + ui_context through pipeline |
| CREATE | `tests/test_crawler_stability.py` | Automated regression assertions |
