"""
tests/test_llm_wiring.py — the per-scan brain selection (model + effort) must
reach EVERY LLM call site, not just the two the engine makes itself.

No LLM, no browser, no network: the crawler entry point is stubbed and we only
assert on what the engine hands it.

Why this exists: the UI's Brain picker sends `model`/`effort`, the API forwards
them as `llm_model`/`llm_effort`, and the engine used them for Planner and
Explainer only — it passed `llm=None` to the QA crawler, which then built a bare
LLMClient off the env default. With `crawl_ui=True` the crawl is 2N+1 of the
2N+3 calls in a scan, so the user's choice applied to almost nothing.
"""
from __future__ import annotations

import pytest

import qa.crawler
from agent.engine import SecurityEngine

MODEL = "claude-haiku-4-5"
EFFORT = "high"


@pytest.fixture(autouse=True)
def _force_claude_code(monkeypatch):
    """Pin the provider so `.model` / `.effort` live on ClaudeCodeProvider, and
    clear the env fallbacks so the assertions don't depend on this host's .env
    (agent.llm calls load_dotenv() at import time)."""
    monkeypatch.setenv("LLM_PROVIDER", "claude_code")
    monkeypatch.delenv("CLAUDE_CODE_EFFORT", raising=False)


@pytest.fixture
def captured_crawl_llm(monkeypatch):
    """Stub run_qa_crawl and capture the LLMClient the engine passes it."""
    box: dict = {}

    def _fake_run_qa_crawl(base_url, **kw):
        box["llm"] = kw.get("llm")
        return ([], {}, "")

    # _run_qa imports run_qa_crawl lazily from the module at call time.
    monkeypatch.setattr(qa.crawler, "run_qa_crawl", _fake_run_qa_crawl)
    return box


def _engine(**kw) -> SecurityEngine:
    return SecurityEngine(base_url="http://127.0.0.1:1", crawl_ui=True,
                          llm_model=MODEL, llm_effort=EFFORT, **kw)


def test_qa_crawler_receives_selected_model_and_effort(captured_crawl_llm):
    """The crawl's brain (QAPlanner/QAJudge/FlowPlanner) must honour the picker."""
    _engine()._run_qa([])

    llm = captured_crawl_llm["llm"]
    assert llm is not None, (
        "engine passed llm=None to run_qa_crawl — the crawler will fall back to "
        "a bare LLMClient() using CLAUDE_CODE_MODEL, ignoring the user's choice"
    )
    assert llm.provider.model == MODEL
    assert llm.provider.effort == EFFORT


def test_planner_and_explainer_receive_selected_model_and_effort():
    """Regression guard on the path that already worked."""
    eng = _engine()
    for component in (eng.planner, eng.explainer):
        assert component.llm.provider.model == MODEL
        assert component.llm.provider.effort == EFFORT


def test_unset_model_and_effort_fall_back_to_env_defaults(captured_crawl_llm):
    """Omitting the picker must not crash or force a hardcoded model."""
    SecurityEngine(base_url="http://127.0.0.1:1", crawl_ui=True)._run_qa([])

    llm = captured_crawl_llm["llm"]
    assert llm is not None
    # No explicit selection -> provider resolves from env, effort stays unset.
    assert llm.provider.effort is None
