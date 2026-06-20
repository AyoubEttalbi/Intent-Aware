"""
qa/responsive.py — responsive / multi-viewport checks.

Renders each page at the common breakpoints, screenshots every one (evidence),
and flags horizontal overflow (content wider than the viewport → users must
scroll sideways, the classic "button off-screen on mobile" bug).
"""
from __future__ import annotations

from core.models import Finding, Evidence, VulnClass, Severity, Confidence

# (label, width, height)
VIEWPORTS = [
    ("mobile-sm", 320, 640),
    ("mobile", 375, 667),
    ("tablet", 768, 1024),
    ("laptop", 1024, 768),
    ("desktop", 1440, 900),
]
OVERFLOW_TOLERANCE = 5  # px


async def check_responsive(page, url: str, artifacts_dir: str, page_n: int, log=print) -> list:
    overflows = []
    mobile_shot = ""
    for label, w, h in VIEWPORTS:
        try:
            await page.set_viewport_size({"width": w, "height": h})
            await page.wait_for_timeout(250)
            shot = f"{artifacts_dir}/page_{page_n}_{label}_{w}.png"
            await page.screenshot(path=shot, full_page=False)
            if label == "mobile":
                mobile_shot = shot
            overflow = await page.evaluate(
                "(w) => { const d = document.documentElement;"
                " const b = document.body;"
                " return Math.max(d ? d.scrollWidth : 0, b ? b.scrollWidth : 0) - w; }", w)
            if overflow and overflow > OVERFLOW_TOLERANCE:
                overflows.append((label, w, int(overflow)))
        except Exception as e:
            log(f"   ⚠️ responsive {label} failed: {e}")
    try:
        await page.set_viewport_size({"width": 1280, "height": 800})
    except Exception:
        pass

    if not overflows:
        return []
    detail = ", ".join(f"{lbl} ({w}px, +{o}px)" for lbl, w, o in overflows)
    return [Finding(
        vuln_class=VulnClass.UI, severity=Severity.LOW, confidence=Confidence.HIGH,
        title="Page is not responsive (horizontal overflow on small screens)", endpoint_key=url,
        evidence=Evidence(page_url=url, steps=[f"Open {url} at small viewports (e.g. 375px mobile)"],
                          expected="Content fits each viewport with no horizontal scrolling",
                          actual=f"Horizontal overflow at: {detail}",
                          screenshot=mobile_shot, note="responsive layout"),
        detail=f"The page overflows its viewport width at: {detail}. On those screens the layout "
               f"breaks and users must scroll sideways.",
        source="qa.responsive")]
