"""
tests/test_brain_log.py — every brain call must be visible in the activity log.

LLMClient takes an optional log sink and a per-call label; each ask() emits
one line (model, elapsed, cached?, tokens/cost when the provider reports
them). No network, no CLI: providers are stubbed. Silent by default.
"""
from __future__ import annotations

import json
import subprocess

import pytest

import agent.llm as llm_mod
from agent.llm import LLMClient
from agent.planner import Planner
from detection.explainer import Explainer


class _StubProvider(llm_mod.LLMProvider):
    def __init__(self, model="stub-model"):
        self.model = model
        self.calls = 0

    def generate(self, system_prompt, user_prompt, max_tokens=4000):
        self.calls += 1
        return '{"ok": true}'


@pytest.fixture()
def logged_client(monkeypatch):
    lines: list = []
    client = LLMClient()
    stub = _StubProvider()
    monkeypatch.setattr(client, "provider", stub)
    client._log = lines.append
    return client, stub, lines


def test_ask_logs_label_model_elapsed(logged_client):
    client, _stub, lines = logged_client
    client.ask("sys", "hi", label="planner")
    assert len(lines) == 1
    line = lines[0]
    assert "planner" in line
    assert "stub-model" in line
    assert "s" in line  # elapsed seconds


def test_cache_hit_logged_not_silent(logged_client):
    client, stub, lines = logged_client
    client.ask("sys", "hi", label="planner")
    client.ask("sys", "hi", label="planner")
    assert stub.calls == 1
    assert len(lines) == 2
    assert "cached" in lines[1]


def test_silent_by_default(monkeypatch):
    client = LLMClient()
    monkeypatch.setattr(client, "provider", _StubProvider())
    client.ask("sys", "hi", label="planner")  # must not raise, must not print-crash


def test_opencode_usage_parsed_and_logged(monkeypatch):
    events = "\n".join([
        json.dumps({"type": "text", "sessionID": "s",
                    "part": {"type": "text", "text": "hi"}}),
        json.dumps({"type": "step_finish", "sessionID": "s",
                    "part": {"type": "step-finish", "reason": "stop",
                             "tokens": {"total": 59471, "input": 59431,
                                        "output": 9, "reasoning": 31},
                             "cost": 0.0084734}}),
    ])

    class _Proc:
        stdout = events
        returncode = 0
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc())
    monkeypatch.setenv("LLM_PROVIDER", "opencode")
    monkeypatch.setenv("OPENCODE_MODEL", "fw/router")
    lines: list = []
    client = LLMClient(log=lines.append)
    assert client.ask("sys", "hi", label="probe") == "hi"
    assert client.provider.last_usage["input"] == 59431
    assert client.provider.last_usage["cost"] == 0.0084734
    assert any("0.008" in ln for ln in lines), lines


def test_planner_and_explainer_forward_log():
    lines: list = []
    fn = lines.append
    assert Planner(log=fn).llm._log is fn
    assert Explainer(log=fn).llm._log is fn
