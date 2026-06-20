"""
qa/executor.py — execute one QA test case in the live browser and collect what
happened (console errors, JS exceptions, failed network responses, native
dialogs, client-side form validity, URL change, resulting page text).

The executor only OBSERVES; the oracle decides pass/fail.
"""
from __future__ import annotations

from qa.page_model import form_by_index, field_selector

SETTLE_MS = 1000


async def _safe(coro, default=None):
    try:
        return await coro
    except Exception:
        return default


async def execute_case(page, recorder, model: dict, case: dict) -> dict:
    target = str(case.get("target", ""))
    action = case.get("action", "none")
    obs = {
        "url_before": page.url, "filled": {}, "action": action,
        "console_errors": [], "js_exceptions": [], "failed_responses": [],
        "dialogs": [], "form_valid": None, "url_after": page.url, "text_after": "",
    }
    cp = recorder.checkpoint()

    try:
        if target.startswith("form:"):
            raw = target.split(":", 1)[1]
            idx = int(raw) if raw.isdigit() else 0
            form = form_by_index(model, idx) or (model.get("forms") or [None])[0]
            if form:
                for ref, val in (case.get("inputs") or {}).items():
                    selr = field_selector(form, ref)
                    if not selr:
                        continue
                    await _safe(page.fill(selr, str(val), timeout=3000))
                    obs["filled"][ref] = str(val)
                obs["form_valid"] = await _safe(
                    page.eval_on_selector("form", "f => (f.checkValidity ? f.checkValidity() : null)"))
                if action == "submit":
                    sub = form.get("submit_selector")
                    if sub:
                        await _safe(page.click(sub, timeout=3000))
                    else:
                        await _safe(page.keyboard.press("Enter"))
        elif target.startswith("button:"):
            ref = target.split(":", 1)[1]
            sel = _button_selector(model, ref)
            if sel:
                await _safe(page.click(sel, timeout=3000))
        await _safe(page.wait_for_timeout(SETTLE_MS))
    except Exception as e:
        obs["js_exceptions"].append(f"executor error: {e}")

    ev = recorder.since(cp)
    obs["console_errors"] = ev["console_errors"]
    obs["js_exceptions"] += ev["js_exceptions"]
    obs["failed_responses"] = ev["failed_responses"]
    obs["dialogs"] = ev["dialogs"]
    obs["url_after"] = page.url
    obs["text_after"] = (await _safe(
        page.evaluate("() => document.body ? document.body.innerText.slice(0,600) : ''"))) or ""
    obs["executed"] = bool(obs["filled"]) or action in ("submit", "click")
    return obs


def _button_selector(model: dict, ref: str):
    for b in model.get("buttons", []):
        if b.get("ref") == ref and b.get("selector"):
            return b["selector"]
    return None


def steps_for(case: dict, obs: dict) -> list:
    steps = [f"Go to {obs.get('url_before', '')}"]
    for ref, val in (obs.get("filled") or {}).items():
        steps.append(f"Enter {ref!r} = {val!r}")
    act = case.get("action")
    if act == "submit":
        steps.append("Submit the form")
    elif act == "click":
        steps.append(f"Click {case.get('target', '')}")
    return steps


def obs_summary(obs: dict) -> dict:
    return {
        "console_errors": obs.get("console_errors", [])[:5],
        "js_exceptions": obs.get("js_exceptions", [])[:5],
        "failed_responses": obs.get("failed_responses", [])[:5],
        "dialogs": obs.get("dialogs", [])[:3],
        "client_side_form_valid": obs.get("form_valid"),
        "url_changed": obs.get("url_before") != obs.get("url_after"),
        "page_text_after": (obs.get("text_after") or "")[:300],
    }
