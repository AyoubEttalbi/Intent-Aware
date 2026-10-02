"""
tests/test_opencode_models.py — the dynamic brain-model catalog.

`opencode models --verbose` emits a `provider/model` header line plus a JSON
block per model (name, status, cost, capabilities, variants). The UI picker is
built from this catalog — never hardcoded. No network, no CLI: subprocess and
the file cache are stubbed/mocked. Fixtures below are real captured blocks
(opencode 1.18.x, 2026-09-29).
"""
from __future__ import annotations

import json
import subprocess

import pytest

import agent.llm as llm_mod

GLM_BLOCK = """tokenrouter/z-ai/glm-5.3-free
{
  "id": "z-ai/glm-5.3-free",
  "providerID": "tokenrouter",
  "name": "GLM-5.3 (free)",
  "family": "glm",
  "status": "active",
  "cost": {"input": 0, "output": 0},
  "limit": {"context": 1000000, "output": 131072},
  "capabilities": {"temperature": true, "reasoning": true},
  "variants": {
    "low": {"reasoningEffort": "low"},
    "high": {"reasoningEffort": "high"},
    "max": {"reasoningEffort": "max"}
  }
}"""

PICKLE_BLOCK = """opencode/big-pickle
{
  "id": "big-pickle",
  "providerID": "opencode",
  "name": "Big Pickle",
  "family": "big-pickle",
  "status": "active",
  "cost": {"input": 0, "output": 0},
  "limit": {"context": 200000, "output": 32000},
  "capabilities": {"temperature": true, "reasoning": true},
  "variants": {}
}"""

DEAD_BLOCK = """tokenrouter/z-ai/old-gone
{
  "id": "z-ai/old-gone",
  "providerID": "tokenrouter",
  "name": "Old Gone",
  "status": "disabled",
  "variants": {"low": {}}
}"""


def test_parse_verbose_blocks():
    models = llm_mod._parse_models_verbose(
        "\n".join([GLM_BLOCK, PICKLE_BLOCK, DEAD_BLOCK, "not json at all"]))
    by_id = {m["id"]: m for m in models}
    # Disabled models never reach the picker.
    assert set(by_id) == {"tokenrouter/z-ai/glm-5.3-free", "opencode/big-pickle"}
    glm = by_id["tokenrouter/z-ai/glm-5.3-free"]
    assert glm["name"] == "GLM-5.3 (free)"
    assert glm["variants"] == ["high", "low", "max"]
    # No declared variants -> the UI disables effort for this model.
    assert by_id["opencode/big-pickle"]["variants"] == []


def test_parse_tolerates_garbage():
    assert llm_mod._parse_models_verbose("") == []
    assert llm_mod._parse_models_verbose("opencode/x\n{broken\n") == []


def test_catalog_uses_cache(monkeypatch, tmp_path):
    cache = tmp_path / "models.json"
    monkeypatch.setenv("OPENCODE_MODELS_CACHE", str(cache))

    def _boom(*_a, **_k):
        raise AssertionError("subprocess must not run on a warm cache")

    monkeypatch.setattr(subprocess, "run", _boom)
    cache.write_text(json.dumps({"ts": 9999999999, "models": [{"id": "x/y"}]}))
    assert llm_mod.opencode_models() == [{"id": "x/y"}]


def test_catalog_refresh_bypasses_cache(monkeypatch, tmp_path):
    cache = tmp_path / "models.json"
    monkeypatch.setenv("OPENCODE_MODELS_CACHE", str(cache))
    cache.write_text(json.dumps({"ts": 9999999999, "models": [{"id": "x/y"}]}))
    box = {}

    class _Proc:
        stdout = PICKLE_BLOCK
        returncode = 0
        stderr = ""

    def _fake(cmd, **kw):
        box["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr(subprocess, "run", _fake)
    models = llm_mod.opencode_models(refresh=True)
    assert "--refresh" in box["cmd"]
    assert [m["id"] for m in models] == ["opencode/big-pickle"]


def test_variant_gating(monkeypatch):
    catalog = [
        {"id": "opencode/big-pickle", "variants": []},
        {"id": "fw/router", "variants": ["low", "max"]},
    ]
    monkeypatch.setattr(llm_mod, "opencode_models", lambda refresh=False: catalog)
    box = {}

    class _Proc:
        stdout = '{"type":"text","sessionID":"s","part":{"type":"text","text":"ok"}}'
        returncode = 0
        stderr = ""

    def _fake(cmd, **kw):
        box["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr(subprocess, "run", _fake)
    llm_mod.OpenCodeProvider(model="opencode/big-pickle",
                             effort="medium").generate("s", "u")
    assert "--variant" not in box["cmd"]
    llm_mod.OpenCodeProvider(model="fw/router", effort="max").generate("s", "u")
    assert box["cmd"][box["cmd"].index("--variant") + 1] == "max"
    # Unknown model (catalog miss) keeps today's pass-through behavior.
    llm_mod.OpenCodeProvider(model="new/vendor-model",
                             effort="high").generate("s", "u")
    assert "--variant" in box["cmd"]


def test_models_endpoint(monkeypatch):
    from fastapi.testclient import TestClient
    import api.main as api_main

    monkeypatch.setattr(api_main, "opencode_models",
                        lambda refresh=False: [{"id": "opencode/big-pickle",
                                                "name": "Big Pickle",
                                                "variants": []}])
    client = TestClient(api_main.app)
    r = client.get("/models")
    assert r.status_code == 200
    body = r.json()
    assert body["default"] == ("fireworks-ai/accounts/fireworks/routers/"
                                 "qwen-max-latest")
    assert body["models"][0]["id"] == "opencode/big-pickle"
    r = client.get("/models", params={"refresh": True})
    assert r.status_code == 200
