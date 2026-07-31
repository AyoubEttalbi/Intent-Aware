"""
tests/test_llm_budget.py — the brain's call budget must be PER SCAN, not per
process.

No LLM, no browser, no network.

The counter lives at module scope in agent.llm and was never reset. In a
long-lived API process that means two crawl-enabled scans burn the ~200-call
ceiling permanently, after which every later scan silently degrades to
heuristics — while brain_status() still reports the brain healthy, because it
only shells `claude --version`.
"""
from __future__ import annotations

import pytest

import agent.llm as llm
from agent.llm import _llm_budget_ok, llm_budget_state, reset_llm_budget


@pytest.fixture(autouse=True)
def _restore_budget():
    """Keep this module's fiddling out of the rest of the suite."""
    used, ceiling = llm_budget_state()
    yield
    llm._LLM_CALLS, llm._LLM_MAX_CALLS = used, ceiling


def _spend(n: int) -> int:
    """Consume up to n calls; return how many were granted."""
    return sum(1 for _ in range(n) if _llm_budget_ok())


def test_budget_is_consumed_and_then_refused():
    reset_llm_budget(5)
    assert _spend(5) == 5
    assert _llm_budget_ok() is False
    assert llm_budget_state() == (5, 5)


def test_reset_restores_a_full_budget_for_the_next_scan():
    reset_llm_budget(3)
    _spend(3)
    assert _llm_budget_ok() is False, "precondition: budget exhausted"

    reset_llm_budget(3)          # a new scan starts
    used, _ = llm_budget_state()
    assert used == 0
    assert _llm_budget_ok() is True, "a fresh scan must get a fresh budget"


def test_reset_without_an_argument_restores_the_configured_ceiling():
    """A scan asking for a SMALLER budget must not shrink every later scan."""
    reset_llm_budget(7)                        # scan A wants a tight budget
    assert llm_budget_state()[1] == 7
    reset_llm_budget()                         # scan B passes no max_llm_calls
    used, ceiling = llm_budget_state()
    assert used == 0
    assert ceiling == llm._LLM_DEFAULT_MAX, (
        "the configured LLM_MAX_CALLS ceiling was not restored — scan B inherits "
        "scan A's tighter budget and gets a false 'budget exhausted' caveat"
    )


def test_a_nonsense_ceiling_falls_back_to_the_configured_default():
    """0/-1/None all mean 'no explicit budget' — they must restore the configured
    ceiling, never silently keep a previous scan's tighter one."""
    for bad in (0, -1, None):
        reset_llm_budget(9)
        reset_llm_budget(bad)
        assert llm_budget_state()[1] == llm._LLM_DEFAULT_MAX, f"max_calls={bad!r}"


def test_engine_resets_the_budget_when_a_scan_starts(monkeypatch):
    """The regression that matters: a fresh SecurityEngine.run() must re-arm."""
    from agent.engine import SecurityEngine

    reset_llm_budget(4)
    _spend(4)
    assert _llm_budget_ok() is False, "precondition: previous scan drained it"

    eng = SecurityEngine(base_url="http://127.0.0.1:1", max_llm_calls=4)
    # Stop run() right after the reset — we only care that the budget re-armed.
    monkeypatch.setattr(eng, "log", lambda *a, **k: None)
    monkeypatch.setattr("agent.engine.brain_status",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("stop")))
    with pytest.raises(RuntimeError):
        eng.run()

    assert llm_budget_state()[0] == 0, "run() did not reset the per-scan budget"
    assert _llm_budget_ok() is True
