"""
qa/cross_browser.py — cross-browser compatibility smoke.

Loads the key discovered pages in Firefox and WebKit (Safari's engine) and flags
browser-specific problems: pages that fail to load, or throw JS/console errors,
where Chromium was fine ("works in Chrome, breaks in Safari").
"""
from __future__ import annotations

from playwright.async_api import async_playwright

from core.models import Finding, Evidence, VulnClass, Severity, Confidence


def _finding(engine: str, url: str, title: str, expected: str, actual: str,
             shot: str, severity: Severity) -> Finding:
    return Finding(
        vuln_class=VulnClass.UX, severity=severity, confidence=Confidence.MEDIUM,
        title=title, endpoint_key=f"{url} [{engine}]",
        evidence=Evidence(page_url=url, steps=[f"Open {url} in {engine}"],
                          expected=expected, actual=actual, screenshot=shot,
                          note=f"cross-browser ({engine})"),
        detail=actual, source=f"qa.cross_browser.{engine}")


async def cross_browser_smoke(engine_name: str, urls: list, artifacts_dir: str,
                              auth: dict | None = None, base_url: str = "", log=print) -> list:
    findings: list = []
    try:
        async with async_playwright() as p:
            engine = getattr(p, engine_name, None)
            if engine is None:
                return []
            try:
                browser = await engine.launch(headless=True)
            except Exception as e:
                log(f"   ⚠️ {engine_name} not available ({e}); skipping.")
                return []
            context = await browser.new_context()
            if auth:
                from qa.auth import login
                try:
                    await login(context, auth, base_url, log)
                except Exception:
                    pass
            page = await context.new_page()
            errors: list = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)

            for i, url in enumerate(urls):
                errors.clear()
                load_failed = None
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    await page.wait_for_timeout(700)
                except Exception as e:
                    load_failed = str(e)
                shot = f"{artifacts_dir}/xb_{engine_name}_{i}.png"
                try:
                    await page.screenshot(path=shot)
                except Exception:
                    shot = ""
                if load_failed:
                    findings.append(_finding(
                        engine_name, url, f"Page fails to load in {engine_name}",
                        "Loads correctly in Chrome", f"In {engine_name} it failed to load: {load_failed}",
                        shot, Severity.HIGH))
                elif errors:
                    findings.append(_finding(
                        engine_name, url, f"JavaScript errors in {engine_name} (not seen in Chrome)",
                        "No console/JS errors, same as Chrome",
                        f"{engine_name} reported: " + "; ".join(errors[:3]), shot, Severity.MEDIUM))
            await browser.close()
    except Exception as e:
        log(f"   ⚠️ cross-browser {engine_name} failed: {e}")
    return findings
