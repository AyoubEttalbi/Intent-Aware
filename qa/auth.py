"""
qa/auth.py — auto-login so the crawler can explore behind authentication.

Given credentials, it opens the login page, locates the username/password fields
(heuristically, or via provided selectors), submits, verifies success, and leaves
the browser context authenticated (cookies/session set). The authenticated
storage_state is returned too, for reuse/persistence.

auth config (all optional except username/password):
    {
      "login_url": "https://app/login",   # default: <base_url>/login
      "username": "...", "password": "...",
      "username_selector": "#email", "password_selector": "#password",
      "submit_selector": "button[type=submit]",
      "success_url_contains": "dashboard",  # a success signal
      "role": "user"                         # remembered as a fact
    }
"""
from __future__ import annotations

from qa.page_model import extract_page_model


def _find_login_form(model: dict) -> dict | None:
    for form in model.get("forms", []):
        if any(f.get("type") == "password" for f in form.get("fields", [])):
            return form
    return None


def _pick_identifier_field(fields: list) -> dict | None:
    """Pick the login *identifier* field flexibly — email OR username. Real apps
    use either; prefer an email input, then email-ish, then user/login-ish, then
    the first text-like field. (Hidden fields are excluded upstream.)"""
    nonpw = [f for f in fields
             if (f.get("type") or "text") not in ("password", "checkbox", "radio", "submit", "button")
             and f.get("tag", "input") in ("input", "textarea")]
    if not nonpw:
        return None

    def hay(f):
        return " ".join(str(f.get(k, "")) for k in ("ref", "placeholder", "label", "selector")).lower()

    for f in nonpw:                                       # 1. explicit email input
        if (f.get("type") or "") == "email":
            return f
    for f in nonpw:                                       # 2. email-ish by name/label/placeholder
        if any(k in hay(f) for k in ("email", "e-mail", "mail")):
            return f
    for f in nonpw:                                       # 3. username / login / identifier-ish
        if any(k in hay(f) for k in ("user", "login", "identifier", "account", "phone", "tel")):
            return f
    for f in nonpw:                                       # 4. first plain text-like field
        if (f.get("type") or "text") in ("text", "tel", "email", "search", ""):
            return f
    return nonpw[0]


def _safe_url(url: str) -> str:
    """Drop the query string before a URL goes anywhere loggable.

    A native GET form submit (see the note in `login`) puts the credentials in
    the URL as `/login?email=...&password=...`. Every message built here flows
    into the job log, which the API keeps in full and the UI renders verbatim —
    so a security product would otherwise print its user's password back at them.
    """
    return (url or "").split("?", 1)[0]


async def _verify(page, context, auth: dict, login_url: str) -> tuple[bool, str]:
    """Confirm login by REAL signals — never by 'the password field disappeared'
    (a show-password toggle clears that and false-positives). We accept: an
    explicit success URL, navigation off the login page, or a session cookie."""
    import re as _re
    sig = auth.get("success_url_contains")
    if sig and sig in page.url:
        return True, f"reached {_safe_url(page.url)}"
    cur = page.url.rstrip("/").lower()
    lu = login_url.rstrip("/").lower()
    if cur != lu and not _re.search(r"/login|/signin|/sign-in|/auth|/connexion", cur):
        return True, f"navigated to {_safe_url(page.url)}"
    try:
        for c in await context.cookies():
            name = c.get("name") or ""
            # Real apps name session cookies many ways (access/refresh/JWT/app-prefixed
            # e.g. gcrm_access). Match broadly — a freshly-set credential cookie is the
            # authoritative success signal, set immediately by the login response even
            # before the (slow, under-load) client-side redirect fires.
            if c.get("value") and _re.search(
                    r"sess|sid|auth|token|jwt|connect|access|refresh|login|gcrm|csrf|remember|_user",
                    name, _re.I):
                return True, f"session cookie '{name}' set"
    except Exception:
        pass
    return False, (f"still on the login page ({_safe_url(page.url)}) — check the email/password, "
                   "the login URL, or that the form's submit button was found "
                   "(not a 'show password' toggle)")


async def login(context, auth: dict, base_url: str, log=print):
    """Authenticate `context` in place. Returns (ok, storage_state|None, message)."""
    if not auth or not auth.get("password"):
        return False, None, "no credentials provided"
    page = await context.new_page()
    login_url = auth.get("login_url") or (base_url.rstrip("/") + "/login")
    try:
        try:
            await page.goto(login_url, wait_until="domcontentloaded", timeout=15000)
        except Exception:
            await page.goto(base_url, wait_until="domcontentloaded", timeout=15000)
            login_url = base_url
        # SPA-robust: wait for the password field to actually render (React/Vue
        # login forms mount after load) before reading the page model.
        try:
            await page.wait_for_selector("input[type=password]", timeout=8000)
        except Exception:
            await page.wait_for_timeout(700)

        model = await extract_page_model(page)
        form = _find_login_form(model)
        # selectors: explicit config wins, else infer from the login form
        pwd_sel = auth.get("password_selector")
        user_sel = auth.get("username_selector")
        submit_sel = auth.get("submit_selector")
        if form:
            if not pwd_sel:
                pf = next((f for f in form["fields"] if f.get("type") == "password"), None)
                pwd_sel = pf and pf.get("selector")
            if not user_sel:
                uf = _pick_identifier_field(form["fields"])   # email OR username, smart
                user_sel = uf and uf.get("selector")
            if not submit_sel:
                submit_sel = form.get("submit_selector")
        # Last-resort fallbacks straight off the DOM (covers forms the model missed).
        if not pwd_sel:
            pwd_sel = "input[type=password]"
        if not user_sel:
            user_sel = ('input[type=email], input[name*="email" i], input[id*="email" i], '
                        'input[autocomplete="username"], input[name*="user" i], input[type=text]')

        # Robust fill: under heavy load (the scan runs many browsers + LLM procs under
        # a tight CPU quota) the SPA can mount slowly, so explicitly wait for the field
        # to be visible and retry once — a bare page.fill would hard-timeout at 30s and
        # abort the whole login (the observed "Page.fill: Timeout 30000ms exceeded").
        async def _robust_fill(sel, val):
            last = None
            for _ in range(2):
                try:
                    await page.wait_for_selector(sel, state="visible", timeout=20000)
                    await page.fill(sel, val, timeout=12000)
                    return
                except Exception as e:
                    last = e
                    await page.wait_for_timeout(500)
            raise last
        await _robust_fill(user_sel, str(auth.get("username", "")))
        await _robust_fill(pwd_sel, str(auth.get("password", "")))
        # Prefer CLICKING a real submit button. Many SPA logins (e.g. Next.js apps
        # like GridCRM) render `<form method="get">` and authenticate via a JS
        # onClick handler on the submit button — pressing Enter then triggers a
        # *native GET submit* that leaks the credentials into the URL
        # (`/login?email=…&password=…`) and never logs in. Try the model's button,
        # then common DOM/text fallbacks, and only Enter as a last resort.
        clicked = False
        candidates = [submit_sel] if submit_sel else []
        candidates += [
            "button[type=submit]", "input[type=submit]",
            "button:has-text('Se connecter')", "button:has-text('Connexion')",
            "button:has-text('Connecter')", "button:has-text('Sign in')",
            "button:has-text('Log in')", "button:has-text('Login')",
        ]
        for sel in candidates:
            if not sel:
                continue
            try:
                await page.click(sel, timeout=4000)
                clicked = True
                break
            except Exception:
                continue
        if not clicked:
            # Last resort: submit on Enter from the password field. Works for POST
            # forms; may not authenticate a native GET form (see note above).
            try:
                await page.focus(pwd_sel)
            except Exception:
                pass
            await page.keyboard.press("Enter")
        # Verify by POLLING the real success signals for a few seconds: SPA logins
        # redirect asynchronously and, under load, that redirect is slow — a single
        # check right after submit would race it and false-report "still on login".
        # The auth cookie is usually set first, so this typically passes within ~1s.
        ok, msg = False, ""
        for _ in range(16):   # ~8s budget
            try:
                await page.wait_for_load_state("networkidle", timeout=1500)
            except Exception:
                await page.wait_for_timeout(400)
            ok, msg = await _verify(page, context, auth, login_url)
            if ok:
                break
        state = await context.storage_state() if ok else None
        return ok, state, msg
    except Exception as e:
        return False, None, f"login error: {e}"
    finally:
        await page.close()


def capture_identities(auth_identities: list, base_url: str, log=print) -> list:
    """Log in each configured identity and return Identity objects carrying session cookies."""
    import asyncio
    try:
        return asyncio.run(_capture_identities_async(auth_identities, base_url, log))
    except Exception as e:
        log(f"⚠️ identity capture failed: {e}")
        return []


async def _capture_identities_async(auth_identities: list, base_url: str, log):
    from playwright.async_api import async_playwright
    from core.models import Identity
    out = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            for cfg in (auth_identities or []):
                if not isinstance(cfg, dict):
                    continue
                name = cfg.get("name") or cfg.get("username", "user")
                role = cfg.get("role", "user")
                try:
                    ctx = await browser.new_context()
                    ok, state, msg = await login(ctx, cfg, base_url, log)
                    cookies = {}
                    if ok and state:
                        for ck in state.get("cookies", []):
                            if ck.get("name"):
                                cookies[ck["name"]] = ck.get("value", "")
                    log(f"   identity '{name}' ({role}): {'OK' if ok else 'FAILED'} — {msg}")
                    if ok:
                        out.append(Identity(name=name, role=role, cookies=cookies,
                                            owned_resource_ids=cfg.get("owned_resource_ids", {}) or {}))
                    await ctx.close()
                except Exception as e:
                    log(f"   identity '{name}' login error: {e}")
        finally:
            await browser.close()
    return out
