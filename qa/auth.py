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


async def _verify(page, context, auth: dict, login_url: str) -> tuple[bool, str]:
    """Confirm login by REAL signals — never by 'the password field disappeared'
    (a show-password toggle clears that and false-positives). We accept: an
    explicit success URL, navigation off the login page, or a session cookie."""
    import re as _re
    sig = auth.get("success_url_contains")
    if sig and sig in page.url:
        return True, f"reached {page.url}"
    cur = page.url.rstrip("/").lower()
    lu = login_url.rstrip("/").lower()
    if cur != lu and not _re.search(r"/login|/signin|/sign-in|/auth|/connexion", cur):
        return True, f"navigated to {page.url}"
    try:
        for c in await context.cookies():
            name = c.get("name") or ""
            if c.get("value") and _re.search(r"sess|sid|auth|token|jwt|connect", name, _re.I):
                return True, f"session cookie '{name}' set"
    except Exception:
        pass
    return False, (f"still on the login page ({page.url}) — check the email/password, the login URL, "
                   "or that the form's submit button was found (not a 'show password' toggle)")


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

        await page.fill(user_sel, str(auth.get("username", "")))
        await page.fill(pwd_sel, str(auth.get("password", "")))
        clicked = False
        if submit_sel:
            try:
                await page.click(submit_sel, timeout=5000)
                clicked = True
            except Exception:
                pass
        if not clicked:
            # most login forms also submit on Enter from the password field
            try:
                await page.focus(pwd_sel)
            except Exception:
                pass
            await page.keyboard.press("Enter")
        # let the login request + any redirect settle (SPA logins resolve async)
        try:
            await page.wait_for_load_state("networkidle", timeout=4000)
        except Exception:
            await page.wait_for_timeout(1500)

        ok, msg = await _verify(page, context, auth, login_url)
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
