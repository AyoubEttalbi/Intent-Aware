"""
tests/test_crawl_progress.py — uncapped crawls (max_pages=0 ⇒ no cap) must
behave sanely in both the phase split and the live progress bar.

No LLM, no browser, no network.

Two bugs this pins down:
  * `inf // 3` is nan and `max(2, nan)` is 2, so "no cap" silently shrank the
    anonymous pass to 2 pages — fewer than a default capped run.
  * the crawler logs `page 7/∞` while the API parsed `page (\\d+)/(\\d+)`, so the
    bar froze at the crawl-phase floor for the entire (now default) uncapped run.
"""
from __future__ import annotations

import pytest

from api.main import _derive_phase
from qa.crawler import _UNCAPPED_ANON_PAGES, QACrawler

AUTH = {"login_url": "http://x/login", "username": "u", "password": "p"}


@pytest.fixture(autouse=True)
def _pin_env(monkeypatch):
    """QACrawler builds a real LLMClient; pin the provider so this needs no key,
    and pin the backstop so the assertions don't depend on the host's env."""
    monkeypatch.setenv("LLM_PROVIDER", "claude_code")
    monkeypatch.setenv("CRAWL_MAX_PAGES", "500")


def _anon_cap(max_pages, auth):
    """Mirror of the phase-1 cap decision in QACrawler.run."""
    c = QACrawler("http://127.0.0.1:1", max_pages=max_pages, auth=auth)
    if not c.auth:
        return c.max_pages
    if c._uncapped:
        return _UNCAPPED_ANON_PAGES
    return max(2, c.max_pages // 3)


# --- phase split -----------------------------------------------------------

def test_nan_arithmetic_is_the_trap_being_guarded():
    """Documents *why* the branch exists — max() silently swallows a nan."""
    assert float("inf") // 3 != float("inf") // 3      # nan != nan
    assert max(2, float("inf") // 3) == 2


def test_uncapped_with_auth_gets_a_real_public_pass():
    assert _anon_cap(0, AUTH) == _UNCAPPED_ANON_PAGES
    assert _UNCAPPED_ANON_PAGES > 2, "must beat the old nan-collapsed value"


def test_uncapped_public_pass_beats_a_default_capped_run():
    """Removing the cap must never *reduce* anonymous coverage."""
    assert _anon_cap(0, AUTH) >= _anon_cap(20, AUTH)


def test_capped_with_auth_still_splits_a_third():
    assert _anon_cap(20, AUTH) == 6
    assert _anon_cap(3, AUTH) == 2          # floor still applies


def test_without_auth_the_whole_budget_is_anonymous():
    assert _anon_cap(20, None) == 20
    assert _anon_cap(0, None) == 500          # the CRAWL_MAX_PAGES backstop


def test_uncapped_still_carries_a_backstop():
    """"No cap" must not mean "never terminates" — the frontier is not
    guaranteed to drain on apps with paginated or filtered listings."""
    c = QACrawler("http://127.0.0.1:1", max_pages=0)
    assert c._uncapped is True
    assert c.max_pages == 500, "an uncapped crawl needs a finite backstop"


def test_backstop_is_configurable_and_can_be_removed(monkeypatch):
    monkeypatch.setenv("CRAWL_MAX_PAGES", "42")
    assert QACrawler("http://127.0.0.1:1", max_pages=0).max_pages == 42
    monkeypatch.setenv("CRAWL_MAX_PAGES", "0")     # opt back into truly unbounded
    assert QACrawler("http://127.0.0.1:1", max_pages=0).max_pages == float("inf")


def test_an_explicit_cap_is_never_overridden_by_the_backstop(monkeypatch):
    monkeypatch.setenv("CRAWL_MAX_PAGES", "500")
    c = QACrawler("http://127.0.0.1:1", max_pages=20)
    assert c._uncapped is False and c.max_pages == 20


# --- progress bar ----------------------------------------------------------

def test_capped_progress_still_scales_with_the_denominator():
    _, pct = _derive_phase("🔎 QA page 10/20: /x", "crawl", 0.0)
    assert pct == pytest.approx(0.22)


def test_uncapped_progress_advances_instead_of_freezing():
    _, p1 = _derive_phase("🔎 QA page 7/∞: /x", "crawl", 0.0)
    _, p2 = _derive_phase("🔎 QA page 60/∞: /y", "crawl", 0.0)
    _, p3 = _derive_phase("🔎 QA page 300/∞: /z", "crawl", 0.0)
    assert 0.14 < p1 < p2 < p3, "uncapped progress must keep moving"


def test_uncapped_progress_never_leaves_the_crawl_band():
    for n in (1, 25, 300, 100_000):
        _, pct = _derive_phase(f"🔎 QA page {n}/∞: /x", "crawl", 0.0)
        assert 0.14 <= pct < 0.30, f"n={n} escaped the crawl band at {pct}"


def test_progress_never_regresses():
    _, pct = _derive_phase("🔎 QA page 1/∞: /x", "crawl", 0.25)
    assert pct >= 0.25


def test_zero_denominator_does_not_divide_by_zero():
    _, pct = _derive_phase("🔎 QA page 5/0: /x", "crawl", 0.0)
    assert 0.14 <= pct < 0.30


def test_overshooting_the_denominator_stays_in_the_band():
    """max_pages=1 floors the anon cap to 2, so `page 2/1` is really emitted —
    unclamped that is 0.46, which the never-regress rule would then pin."""
    _, pct = _derive_phase("🔎 QA page 2/1: /x", "crawl", 0.0)
    assert pct == pytest.approx(0.30), "ratio must clamp at 1.0"
    # 0.14 + 0.16 is 0.30000000000000004 in binary floating point — compare with
    # a tolerance rather than a bare <=, which would fail on representation alone.
    assert pct <= 0.30 + 1e-9
    _, huge = _derive_phase("🔎 QA page 999/1: /x", "crawl", 0.0)
    assert huge == pytest.approx(0.30)
