"""
A modal backdrop must not make working controls look broken.

Regression origin: Phase 7 (OWASP Juice Shop). Its welcome modal renders a
full-viewport `.cdk-overlay-backdrop` that intercepts pointer events, so the
crawler's clicks never reached their targets. The judge then reported — accurately
for what it observed, but falsely about the app — three bugs from one overlay:

  [high]   "Add to Basket button does not add product to cart"
  [medium] "Search for non-existent product does not show empty state"
  [medium] "Cookie consent banner does not dismiss on action"

All three were verified false by hand: with the modal dismissed, the basket badge
goes 0 -> 1 ("Placed Apple Juice (1000ml) into basket.") and "No results found" is
displayed. Most real apps have a consent banner, so this is the difference between
trustworthy landing-page findings and noise.

Browser test (chromium), no LLM, no network — a local data: page reproduces the
exact interception.
"""
from __future__ import annotations

import asyncio
import os

import pytest

from qa.crawler import _dismiss_overlays

pytestmark = pytest.mark.skipif(
    not os.path.isdir(os.path.join(os.getcwd(), ".browsers")),
    reason="project-local Playwright browsers not installed",
)

# A working button behind a full-viewport backdrop — exactly Juice Shop's shape.
PAGE = """
<html><body>
  <button id="real" onclick="document.getElementById('out').textContent='CLICKED'">
    Add to Basket
  </button>
  <div id="out">NOT-CLICKED</div>
  <div class="cdk-overlay-container">
    <div class="cdk-overlay-backdrop"
         style="position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:9999"></div>
    <div role="dialog" style="position:fixed;top:40%;left:40%;z-index:10000;background:#fff">
      <p>Welcome!</p>
      <button aria-label="Close Welcome Banner"
              onclick="document.querySelector('.cdk-overlay-container').remove()">
        Dismiss
      </button>
    </div>
  </div>
</body></html>
"""


async def _run(dismiss_first: bool) -> str:
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.set_content(PAGE)
        if dismiss_first:
            await _dismiss_overlays(page)
        try:
            await page.click("#real", timeout=2500)
        except Exception:
            pass                                  # the backdrop ate the click
        out = await page.inner_text("#out")
        await browser.close()
        return out


def test_backdrop_blocks_the_click_without_dismissal():
    """Proves the false-positive mechanism is real, not theoretical."""
    assert asyncio.run(_run(dismiss_first=False)) == "NOT-CLICKED"


def test_dismissal_lets_the_real_click_through():
    """After dismissal the working button works — no bogus 'button is broken'."""
    assert asyncio.run(_run(dismiss_first=True)) == "CLICKED"


def test_dismissal_is_safe_on_a_page_with_no_overlay():
    """No overlay -> nothing clicked, nothing broken."""
    async def go():
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            await page.set_content(
                "<html><body><button id='b' "
                "onclick=\"document.title='PRESSED'\">OK</button></body></html>")
            changed = await _dismiss_overlays(page)
            title = await page.title()
            await browser.close()
            return changed, title

    changed, title = asyncio.run(go())
    assert changed is False, "nothing to dismiss on a plain page"
    assert title != "PRESSED", "must never click an ordinary page button labelled 'OK'"
