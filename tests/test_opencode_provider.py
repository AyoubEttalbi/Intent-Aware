"""
tests/test_opencode_provider.py — the opencode brain backend.

LLM_PROVIDER=opencode routes the brain through the locally-installed opencode
CLI (`opencode run --format json`) instead of `claude -p`. No network, no CLI,
no browser: subprocess is mocked and we assert on command construction, the
file-based sandbox agent, NDJSON event parsing, and model resolution. The
deny-all agent file itself is pinned by test_brain_agent_file_denies_all so
sandbox drift fails loudly.

Real CLI output this is grounded in (fireworks-ai probe, opencode 1.18.x):
  {"type":"text", ...,
   "part":{"type":"text","text":"PROBE_OK",...}}
  {"type":"step_finish", ..., "part":{"reason":"stop",...}}
  {"type":"error", ..., "error":{"name":"APIError", ...}}
Every event carries a top-level sessionID used for chat continuity.
"""
from __future__ import annotations

import json
import os
import subprocess

import pytest

import agent.llm as llm_mod
from agent.llm import LLMClient


TEXT_EVENT = json.dumps({
    "type": "text", "timestamp": 1, "sessionID": "ses_abc",
    "part": {"id": "prt_1", "messageID": "msg_1", "sessionID": "ses_abc",
             "type": "text", "text": "hello "},
})
TEXT_EVENT_2 = json.dumps({
    "type": "text", "timestamp": 2, "sessionID": "ses_abc",
    "part": {"id": "prt_2", "messageID": "msg_1", "sessionID": "ses_abc",
             "type": "text", "text": "world"},
})
FINISH_EVENT = json.dumps({
    "type": "step_finish", "timestamp": 3, "sessionID": "ses_abc",
    "part": {"id": "prt_3", "messageID": "msg_1", "sessionID": "ses_abc",
             "type": "step-finish", "reason": "stop"},
})
ERROR_EVENT = json.dumps({
    "type": "error", "timestamp": 4, "sessionID": "ses_err",
    "error": {"name": "APIError",
              "data": {"message": "Upstream request failed: nope"}}},
)


@pytest.fixture(autouse=True)
def _force_opencode(monkeypatch):
    """Pin the provider so tests never depend on this host's .env."""
    monkeypatch.setenv("LLM_PROVIDER", "opencode")
    monkeypatch.setenv("OPENCODE_MODEL",
                       "fireworks-ai/accounts/fireworks/routers/glm-flash-latest")
    monkeypatch.delenv("OPENCODE_MODEL_PROVIDER", raising=False)
    monkeypatch.delenv("OPENCODE_VARIANT", raising=False)


class _Proc:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


def _run_ok(monkeypatch, stdout, returncode=0, stderr=""):
    box = {}

    def _fake(cmd, **kw):
        box["cmd"] = cmd
        box["env"] = kw.get("env", {})
        box["cwd"] = kw.get("cwd")
        box["input"] = kw.get("input")
        return _Proc(stdout=stdout, returncode=returncode, stderr=stderr)

    monkeypatch.setattr(subprocess, "run", _fake)
    return box


def test_generate_accumulates_text_parts(monkeypatch):
    _run_ok(monkeypatch, "\n".join([TEXT_EVENT, TEXT_EVENT_2, FINISH_EVENT]))
    client = LLMClient()
    assert client.ask("sys", "hi") == "hello world"


def test_generate_raises_on_error_event(monkeypatch):
    _run_ok(monkeypatch, ERROR_EVENT)
    with pytest.raises(RuntimeError, match="(?i)opencode.*nope|nope"):
        LLMClient().ask("sys", "hi")


def test_generate_raises_on_empty_output(monkeypatch):
    _run_ok(monkeypatch, "")
    with pytest.raises(RuntimeError, match="(?i)no output|empty"):
        LLMClient().ask("sys", "hi")


def test_generate_raises_when_no_text_parts(monkeypatch):
    _run_ok(monkeypatch, FINISH_EVENT)
    with pytest.raises(RuntimeError):
        LLMClient().ask("sys", "hi")


def test_command_shape_and_hermetic_config(monkeypatch):
    box = _run_ok(monkeypatch, "\n".join([TEXT_EVENT, FINISH_EVENT]))
    LLMClient().ask("sys", "hello prompt")
    cmd = box["cmd"]
    assert cmd[0].endswith("opencode") or cmd[0] == "opencode"
    assert "run" in cmd
    assert "--agent" in cmd and "intent-brain" in cmd
    assert "--model" in cmd
    assert "--format" in cmd and "json" in cmd
    assert "--dir" in cmd
    assert "--pure" in cmd  # no external plugins, ever
    # Prompt travels via stdin, never argv (no ps-visible findings, no ARG_MAX).
    # `run` has no system channel, so system is composed into the message.
    assert "hello prompt" not in cmd
    assert box["input"] == "sys\n\nhello prompt"
    # The child env is allowlisted — host secrets must not travel with it.
    for leaked in ("DATABASE_URL", "ANTHROPIC_API_KEY", "OLLAMA_API_KEY"):
        monkeypatch.setenv(leaked, "secret-should-not-travel")
    LLMClient().ask("sys", "hi again")
    for leaked in ("DATABASE_URL", "ANTHROPIC_API_KEY", "OLLAMA_API_KEY"):
        assert leaked not in box["env"], f"{leaked} must be stripped"


def test_brain_agent_file_denies_all():
    """The deny-all sandbox lives in .opencode/agents/intent-brain.md (the CLI
    only resolves agents from files). If the file drifts from the code's
    permission map — or gains a model pin, tools, or a narrower mode — the
    brain must not run silently unsandboxed."""
    import yaml

    path = llm_mod.OpenCodeProvider._agent_file()
    assert os.path.isfile(path), f"brain agent file missing: {path}"
    with open(path) as f:
        body = f.read()
    assert body.startswith("---")
    frontmatter = body.split("---", 2)[1]
    cfg = yaml.safe_load(frontmatter)
    assert cfg.get("mode") == "primary"
    assert cfg.get("temperature") == 0
    assert "model" not in cfg, \
        "model must come from the --model flag (per-call), not the file"
    perms = cfg.get("permission", {})
    expected = llm_mod.OpenCodeProvider(None)._agent_config(None)["permission"]
    assert perms == expected, \
        f"agent file drifted from code: {[k for k in set(perms) ^ set(expected)]}"
    for tool in ("edit", "bash", "read", "task", "skill", "webfetch",
                 "playwright_*", "staruml_*", "mcp_*", "*_mcp", "*"):
        assert perms.get(tool) == "deny", f"{tool} must be denied"


def test_default_model_is_qwen_max(monkeypatch):
    monkeypatch.delenv("OPENCODE_MODEL", raising=False)
    assert llm_mod.OpenCodeProvider.resolve_model(None) == (
        "fireworks-ai/accounts/fireworks/routers/qwen-max-latest")


def test_qualified_model_passes_through(monkeypatch):
    box = _run_ok(monkeypatch, "\n".join([TEXT_EVENT, FINISH_EVENT]))
    LLMClient(model="openrouter/anthropic/claude-sonnet-5").ask("s", "u")
    i = box["cmd"].index("--model")
    assert box["cmd"][i + 1] == "openrouter/anthropic/claude-sonnet-5"


def test_bare_model_falls_back_to_default(monkeypatch):
    """Bare ids (e.g. the UI's claude-sonnet-5) can't be trusted across
    providers — the Zen route is unfunded — so they resolve to OPENCODE_MODEL."""
    box = _run_ok(monkeypatch, "\n".join([TEXT_EVENT, FINISH_EVENT]))
    LLMClient(model="claude-sonnet-5").ask("s", "u")
    i = box["cmd"].index("--model")
    assert box["cmd"][i + 1] == ("fireworks-ai/accounts/fireworks/routers/"
                                 "glm-flash-latest")


def test_variant_effort_passed_through(monkeypatch):
    box = _run_ok(monkeypatch, "\n".join([TEXT_EVENT, FINISH_EVENT]))
    LLMClient(model=None, effort="high").ask("s", "u")
    assert "--variant" in box["cmd"]
    i = box["cmd"].index("--variant")
    assert box["cmd"][i + 1] == "high"


def test_nonzero_exit_surfaces_stderr(monkeypatch):
    box = _run_ok(monkeypatch, "", returncode=1, stderr="boom: bad --variant")
    with pytest.raises(RuntimeError, match="(?i)exit 1.*boom"):
        LLMClient().ask("sys", "hi")
    assert box["cmd"][0].endswith("opencode") or box["cmd"][0] == "opencode"


def test_missing_session_id_raises(monkeypatch):
    no_sid = json.dumps({"type": "text", "part": {"type": "text", "text": "x"}})
    _run_ok(monkeypatch, no_sid)
    with pytest.raises(RuntimeError, match="(?i)sessionID"):
        llm_mod.opencode_chat("hi", session_id="", resume=False)


def test_model_and_effort_flag_guard(monkeypatch):
    _run_ok(monkeypatch, "\n".join([TEXT_EVENT, FINISH_EVENT]))
    with pytest.raises(ValueError, match="(?i)model"):
        LLMClient(model="--share").ask("s", "u")
    with pytest.raises(ValueError, match="(?i)effort|variant"):
        LLMClient(effort="--auto").ask("s", "u")


def test_session_id_captured_for_chat(monkeypatch):
    _run_ok(monkeypatch, "\n".join([TEXT_EVENT, FINISH_EVENT]))
    text, sid = llm_mod.opencode_chat("hello", session_id="",
                                      resume=False, system="ctx")
    assert text == "hello "
    assert sid == "ses_abc"


def test_chat_resume_passes_session(monkeypatch):
    box = _run_ok(monkeypatch, "\n".join([TEXT_EVENT, FINISH_EVENT]))
    llm_mod.opencode_chat("follow-up", session_id="ses_abc", resume=True,
                          system="ctx")
    assert "--session" in box["cmd"]
    i = box["cmd"].index("--session")
    assert box["cmd"][i + 1] == "ses_abc"


def test_brain_chat_dispatches_by_provider(monkeypatch):
    _run_ok(monkeypatch, "\n".join([TEXT_EVENT, FINISH_EVENT]))
    text, sid = llm_mod.brain_chat("hi", session_id="x", resume=False)
    assert text == "hello "
    assert sid == "ses_abc"


def test_brain_status_opencode_ok(monkeypatch):
    import shutil

    def _fake_run(cmd, **kw):
        if cmd[-1] == "--version":
            return _Proc(stdout="1.18.33\n")
        if cmd[:2] == ["opencode", "auth"] or cmd[1:2] == ["auth"]:
            return _Proc(stdout="OpenCode Zen\nFireworks AI\n")
        raise AssertionError(f"unexpected status probe: {cmd}")

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: "/usr/bin/opencode")
    monkeypatch.setattr(os, "access", lambda *_a, **_k: True)
    monkeypatch.setattr(subprocess, "run", _fake_run)
    ok, reason = llm_mod.brain_status()
    assert ok, reason


def test_brain_status_opencode_no_binary(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: None)
    monkeypatch.delenv("OPENCODE_BIN", raising=False)
    ok, reason = llm_mod.brain_status()
    assert not ok
    assert "opencode" in reason.lower()


def test_brain_status_opencode_no_credentials(monkeypatch):
    import shutil

    def _fake_run(cmd, **kw):
        if cmd[-1] == "--version":
            return _Proc(stdout="1.18.33\n")
        return _Proc(stdout="   \n", returncode=0)

    monkeypatch.setattr(shutil, "which", lambda *_a, **_k: "/usr/bin/opencode")
    monkeypatch.setattr(subprocess, "run", _fake_run)
    ok, _reason = llm_mod.brain_status()
    assert not ok
