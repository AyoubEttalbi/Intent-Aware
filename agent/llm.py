import os
import json
import re
import shutil
import subprocess
import tempfile
import threading
import time
import anthropic
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
from dotenv import load_dotenv

load_dotenv()


def _fmt_tokens(n) -> str:
    """59_431 -> '59.4k' for one-line activity log usage."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "0"
    if n >= 1000:
        return f"{n / 1000:.1f}k"
    return str(int(n))


def _strip_fences(text: str) -> str:
    t = (text or "").strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z0-9]*\s*", "", t)
        t = re.sub(r"\s*```\s*$", "", t)
    return t.strip()


def _balanced_json(text: str):
    """Return the first balanced {...} or [...] region, ignoring braces in strings."""
    start = next((i for i, c in enumerate(text) if c in "{["), None)
    if start is None:
        return None
    depth, in_str, esc = 0, False, False
    for j in range(start, len(text)):
        c = text[j]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c in "{[":
                depth += 1
            elif c in "}]":
                depth -= 1
                if depth == 0:
                    return text[start:j + 1]
    return text[start:]


def extract_json(raw: str):
    """Best-effort parse of a JSON value out of an LLM response. Returns dict/list or None."""
    if not raw:
        return None
    cleaned = _strip_fences(raw)
    for candidate in (cleaned, _balanced_json(cleaned)):
        if not candidate:
            continue
        for attempt in (candidate, re.sub(r",(\s*[}\]])", r"\1", candidate)):  # drop trailing commas
            try:
                return json.loads(attempt)
            except Exception:
                continue
    return None

class LLMProvider(ABC):
    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000) -> str:
        pass

class ClaudeProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "claude-sonnet-5",
                 temperature: float = 0.0):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.temperature = temperature

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=self.temperature,   # 0 = reproducible findings/verdicts
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}]
        )
        return response.content[0].text

class OllamaProvider(LLMProvider):
    def __init__(self, base_url: str, api_key: str = "ollama", model: str = "llama3"):
        # Ollama often uses OpenAI-compatible API. Imported lazily so the
        # claude / claude_code providers don't require the `openai` package.
        from openai import OpenAI
        self.client = OpenAI(base_url=base_url, api_key=api_key)
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            max_tokens=max_tokens,
            temperature=0,
            response_format={"type": "json_object"},   # weak models need the nudge to emit valid JSON
        )
        return response.choices[0].message.content

class ClaudeCodeProvider(LLMProvider):
    """LLM backend that calls the locally-installed Claude Code CLI (`claude -p`)
    as a pure text engine. No API key is required — authentication comes from the
    machine's logged-in `claude` session.

    Isolation — this provider must never read or affect anything outside this
    project:
      * every built-in tool is disabled        -> no file / shell / network access
      * --strict-mcp-config (and no MCP config) -> external MCP servers are ignored
      * the subprocess runs with cwd pinned to this project's root
    The CLI can therefore only read the prompt we pass on stdin and return text;
    it cannot reach other projects, services, or files on this host.
    """

    # Deny every built-in tool. The agent's prompts are self-contained, so the
    # CLI must answer from the prompt alone.
    _DISALLOWED_TOOLS = [
        "Bash", "Read", "Edit", "Write", "Glob", "Grep",
        "WebFetch", "WebSearch", "Task", "NotebookEdit", "TodoWrite",
    ]
    # .../Intent-Aware — the only directory this provider is allowed to run in.
    _PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def __init__(self, binary: Optional[str] = None, model: Optional[str] = None,
                 timeout: Optional[int] = None, effort: Optional[str] = None):
        self.binary = (binary or os.getenv("CLAUDE_CODE_BIN")
                       or shutil.which("claude") or "claude")
        # Cost-efficient default; set CLAUDE_CODE_MODEL='' to use the CLI's
        # own session default instead.
        self.model = model if model is not None else os.getenv("CLAUDE_CODE_MODEL", "claude-sonnet-5")
        # Reasoning effort: low | medium | high | xhigh | max (None = CLI default).
        self.effort = effort if effort is not None else (os.getenv("CLAUDE_CODE_EFFORT") or None)
        self.timeout = int(timeout if timeout is not None else os.getenv("CLAUDE_CODE_TIMEOUT", "900"))

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000) -> str:
        cmd = [self.binary, "-p", "--output-format", "json", "--strict-mcp-config"]
        if self.model:
            cmd += ["--model", self.model]
        if self.effort:
            cmd += ["--effort", self.effort]
        if system_prompt:
            cmd += ["--append-system-prompt", system_prompt]
        cmd += ["--disallowed-tools", *self._DISALLOWED_TOOLS]

        # The CLI authenticates from the machine's logged-in session. A stray or
        # placeholder ANTHROPIC_API_KEY in the environment (e.g. `your_key_here`
        # from .env) makes it try that bogus *external* key instead → "Invalid API
        # key". Strip it so claude_code always uses the OAuth session.
        env = {k: v for k, v in os.environ.items()
               if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")}
        try:
            proc = subprocess.run(
                cmd, input=user_prompt, capture_output=True, text=True,
                timeout=self.timeout, cwd=self._PROJECT_ROOT, env=env,
            )
        except FileNotFoundError:
            raise RuntimeError(f"Claude Code CLI not found at '{self.binary}'. "
                               "Install it or set CLAUDE_CODE_BIN.")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Claude Code CLI timed out after {self.timeout}s")

        raw = (proc.stdout or "").strip()
        if not raw:
            err = (proc.stderr or "").strip()[:500]
            raise RuntimeError(f"Claude Code CLI returned no output "
                               f"(exit {proc.returncode}): {err}")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Some versions/modes may emit plain text rather than a JSON envelope.
            return raw
        if data.get("is_error"):
            raise RuntimeError(f"Claude Code CLI error: {str(data.get('result'))[:500]}")
        return str(data.get("result", ""))


def _int_or_default(explicit, env_value, default: int) -> int:
    """int() that survives blank/missing env values (e.g. `OPENCODE_TIMEOUT=`)."""
    for candidate in (explicit, env_value):
        if candidate is None or (isinstance(candidate, str) and not candidate.strip()):
            continue
        try:
            return int(candidate)
        except (TypeError, ValueError):
            continue
    return default


class OpenCodeProvider(LLMProvider):
    """LLM backend that calls the locally-installed opencode CLI
    (`opencode run --format json`) as a pure text engine. Authentication comes
    from the machine's `opencode auth` credentials — no API key required.

    Isolation — this provider must never read or affect anything outside this
    project:
      * the `intent-brain` agent (`.opencode/agents/intent-brain.md`) has
        every tool permission denied, including MCP wildcards plus a `"*"`
        catch-all — `opencode run` only resolves agents from real config
        locations, so the agent lives in the repo, not in env config
        (OPENCODE_CONFIG_CONTENT / OPENCODE_CONFIG_DIR are ignored by the
        CLI in 1.18.x — verified by probe, do not rely on them)
      * `--pure` (no external plugins), cwd + `--dir` pinned to the project
      * the child env is allowlisted (no host secrets travel with it)
      * the prompt travels via stdin, never argv
    The CLI can therefore only read the prompt we pass on stdin and return
    text; it cannot reach other projects, services, or files on this host.
    """

    _AGENT = "intent-brain"
    # Deny every tool permission. Anything not explicitly allowed is denied,
    # and non-interactive `run` must never touch the host. MCP servers default
    # to allow, so their tools are wildcard-denied too, plus a catch-all —
    # permission keys match as wildcards against tool names. These live in
    # .opencode/agents/intent-brain.md (kept in sync by
    # tests/test_opencode_provider.py::test_brain_agent_file_denies_all).
    _DENIED_PERMISSIONS = [
        "edit", "bash", "read", "glob", "grep", "list", "task",
        "webfetch", "websearch", "lsp", "skill", "todowrite",
        "question", "doom_loop", "external_directory",
        "playwright_*", "staruml_*", "mcp_*", "*_mcp", "*",
    ]
    # .../Intent-Aware — the only directory this provider is allowed to run in.
    _PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # Last-resort default; OPENCODE_MODEL env wins. Locked from live probes:
    # fireworks-ai qwen-max router (funded, JSON-disciplined, works under the
    # deny-all intent-brain agent). Zen free-tier models (incl. big-pickle)
    # REJECT sandboxed custom agents with 403 "free tier can only be used from
    # within OpenCode" — verified: minimal-deny custom agent 403s, built-in
    # plan agent 200s. So free models are unusable as brain; they stay listed
    # in the catalog but cannot be the default. Other dead ends: Zen claude-*
    # and OpenRouter 402, tokengo 401, tokenrouter 503 (2026-09-29).
    _DEFAULT_MODEL = ("fireworks-ai/accounts/fireworks/routers/"
                      "qwen-max-latest")

    def __init__(self, binary: Optional[str] = None, model: Optional[str] = None,
                 timeout: Optional[int] = None, effort: Optional[str] = None):
        self.binary = (binary or os.getenv("OPENCODE_BIN")
                       or shutil.which("opencode") or "opencode")
        if model is not None and model.startswith("-"):
            raise ValueError(f"refusing flag-like opencode model: {model!r}")
        self.model = self.resolve_model(model)
        if effort is not None and effort.startswith("-"):
            raise ValueError(f"refusing flag-like opencode effort: {effort!r}")
        # Reasoning effort maps to opencode --variant (provider-specific).
        self.effort = effort if effort else (os.getenv("OPENCODE_VARIANT") or None)
        self.timeout = _int_or_default(timeout, os.getenv("OPENCODE_TIMEOUT"), 900)
        self.last_usage: Optional[Dict[str, Any]] = None

    @classmethod
    def resolve_model(cls, model: Optional[str]) -> str:
        """Fully-qualified `provider/model` ids pass through untouched.

        Bare ids (e.g. the UI picker's `claude-sonnet-5`) cannot be trusted
        across providers — the Zen route is currently unfunded — so without an
        explicit OPENCODE_MODEL_PROVIDER prefix they resolve to OPENCODE_MODEL.
        """
        default = os.getenv("OPENCODE_MODEL", cls._DEFAULT_MODEL)
        if model:
            if "/" in model:
                return model
            prefix = os.getenv("OPENCODE_MODEL_PROVIDER") or ""
            if prefix:
                return f"{prefix}/{model}"
            print(f"⚠️ opencode: bare model {model!r} has no provider mapping — "
                  f"using OPENCODE_MODEL={default}")
        return default

    # Env allowlist for the child: the model cannot see env without a tool,
    # but a sandbox bypass must not turn into secret exfiltration. Auth lives
    # in opencode's data dir, not env, so nothing secret needs to travel.
    _ENV_KEEP_EXACT = frozenset({
        "PATH", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
        "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "PATHEXT", "OS",
        "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TERM",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    })
    _ENV_KEEP_PREFIX = ("OPENCODE_",)

    @classmethod
    def _sandbox_env(cls, extra: Dict[str, str]) -> Dict[str, str]:
        env = {k: v for k, v in os.environ.items()
               if k in cls._ENV_KEEP_EXACT or k.startswith(cls._ENV_KEEP_PREFIX)}
        env.update(extra)
        return env

    @staticmethod
    def _agent_file() -> str:
        return os.path.join(
            OpenCodeProvider._PROJECT_ROOT, ".opencode", "agents",
            OpenCodeProvider._AGENT + ".md")

    def _agent_config(self, system_prompt: Optional[str]) -> Dict[str, Any]:
        """The live permission map — must match intent-brain.md exactly.

        The CLI resolves `--agent` from files only, so this dict is NOT sent
        anywhere; it exists so tests can assert the file and the code agree.
        """
        return {"permission": {tool: "deny" for tool in self._DENIED_PERMISSIONS},
                "temperature": 0, "mode": "primary"}

    @staticmethod
    def _parse_events(raw: str):
        """Accumulate assistant text from `opencode run --format json` NDJSON.

        Returns (text, session_id, usage). Raises on error events or empty
        output. Usage (tokens/cost from step_finish) drives the activity log
        and answers "what did this scan cost".
        """
        texts: List[str] = []
        session_id = ""
        usage: Dict[str, Any] = {}
        for line in (raw or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get("sessionID"):
                session_id = str(event["sessionID"])
            if event.get("type") == "error":
                raise RuntimeError(
                    f"opencode error: {json.dumps(event.get('error', {}))[:500]}")
            part = event.get("part")
            if (event.get("type") == "text" and isinstance(part, dict)
                    and part.get("type") == "text" and part.get("text")):
                texts.append(str(part["text"]))
            if event.get("type") == "step_finish" and isinstance(part, dict):
                tokens = part.get("tokens") or {}
                usage = {"input": tokens.get("input", 0),
                         "output": tokens.get("output", 0),
                         "cost": part.get("cost", 0)}
        text = "".join(texts)
        if not text.strip():
            raise RuntimeError("opencode returned empty output (no text parts)")
        return text, session_id, usage

    def _run(self, user_prompt: str, system: Optional[str] = None,
             session: Optional[str] = None):
        if not os.path.isfile(self._agent_file()):
            raise RuntimeError(
                f"opencode brain agent missing: {self._agent_file()} "
                "(the deny-all sandbox is undefined without it — refusing to run)")
        cmd = [self.binary, "run", "--pure", "--agent", self._AGENT,
               "--model", self.model, "--format", "json",
               "--dir", self._PROJECT_ROOT]
        if self.effort:
            if self._variant_supported(self.effort):
                cmd += ["--variant", self.effort]
            else:
                print(f"⚠️ opencode: model {self.model} declares no "
                      f"{self.effort!r} variant — sending without --variant")
        if session:
            cmd += ["--session", session]
        # `run` has no system-prompt channel, so the system prompt is composed
        # into the message (it stays ordinary text — the agent file already
        # forbids tools, and untrusted parts arrive fenced via prompt_safety).
        # The prompt travels via stdin — never argv (no ps-visible findings).
        message = user_prompt if not system else (system + "\n\n" + user_prompt)
        env = self._sandbox_env({})
        try:
            proc = subprocess.run(
                cmd, input=message, capture_output=True, text=True,
                timeout=self.timeout, cwd=self._PROJECT_ROOT, env=env,
            )
        except FileNotFoundError:
            raise RuntimeError(f"opencode CLI not found at '{self.binary}'. "
                               "Install it or set OPENCODE_BIN.")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"opencode CLI timed out after {self.timeout}s")
        if proc.returncode != 0 and not (proc.stdout or "").strip():
            raise RuntimeError(f"opencode exit {proc.returncode}: "
                               f"{(proc.stderr or '').strip()[:500]}")
        text, session_id, usage = self._parse_events(proc.stdout or "")
        self.last_usage = usage
        return text, session_id

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000) -> str:
        text, _ = self._run(user_prompt, system=system_prompt)
        return text

    def _variant_supported(self, effort: str) -> bool:
        """True unless the catalog declares variants for this model that
        exclude the effort. Unknown models pass through (today's behavior)."""
        try:
            catalog = opencode_models()
        except Exception:
            return True
        for entry in catalog:
            if entry.get("id") == self.model:
                return effort in (entry.get("variants") or [])
        return True


def _parse_models_verbose(text: str):
    """Parse `opencode models --verbose` into picker records.

    The CLI prints a `provider/model` header line plus a JSON block per model.
    Returns [{id, name, family, status, cost{input,output}, variants[]}],
    skipping inactive models and malformed blocks.
    """
    models = []
    header, buf = None, []

    def flush():
        nonlocal header, buf
        if not header or not buf:
            header, buf = None, []
            return
        try:
            data = json.loads("\n".join(buf))
        except (json.JSONDecodeError, ValueError):
            header, buf = None, []
            return
        if isinstance(data, dict) and data.get("status") == "active":
            cost = data.get("cost") or {}
            models.append({
                "id": header,
                "name": data.get("name") or header,
                "family": data.get("family") or "",
                "status": "active",
                "cost": {"input": cost.get("input", 0),
                         "output": cost.get("output", 0)},
                "variants": sorted((data.get("variants") or {}).keys()),
            })
        header, buf = None, []

    for line in (text or "").splitlines():
        if line and not line[0].isspace() and "/" in line and not line.startswith("{"):
            flush()
            header = line.strip()
        elif header is not None:
            buf.append(line)
    flush()
    return models


def _models_cache_path() -> str:
    return (os.getenv("OPENCODE_MODELS_CACHE")
            or os.path.join(tempfile.gettempdir(), "intent-aware-opencode-models.json"))


def opencode_models(refresh: bool = False):
    """Brain-model catalog for the UI picker. Cached 1h on disk (TTL via
    OPENCODE_MODELS_TTL, path via OPENCODE_MODELS_CACHE); [] on any failure —
    a stale/empty catalog must never break scans."""
    cache_path = _models_cache_path()
    ttl = _int_or_default(None, os.getenv("OPENCODE_MODELS_TTL"), 3600)
    if not refresh:
        try:
            with open(cache_path) as f:
                cached = json.load(f)
            if time.time() - float(cached.get("ts", 0)) < ttl:
                return cached.get("models", [])
        except (OSError, ValueError, TypeError, KeyError):
            pass
    binary = os.getenv("OPENCODE_BIN") or shutil.which("opencode") or "opencode"
    cmd = [binary, "models", "--verbose"] + (["--refresh"] if refresh else [])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
        return _read_models_cache(cache_path)
    if proc.returncode != 0:
        return _read_models_cache(cache_path)
    models = _parse_models_verbose(proc.stdout or "")
    if models:
        try:
            with open(cache_path, "w") as f:
                json.dump({"ts": time.time(), "models": models}, f)
        except OSError:
            pass
    return models if models else _read_models_cache(cache_path)


def _read_models_cache(cache_path: str):
    try:
        with open(cache_path) as f:
            return json.load(f).get("models", [])
    except (OSError, ValueError, AttributeError):
        return []


# Process-wide LLM-call ceiling so an unexpectedly large target can't trigger
# unbounded (slow, costly) model calls. Callers already degrade to heuristics on error.
_LLM_CALLS = 0
_LLM_CALLS_LOCK = threading.Lock()
# The configured ceiling, kept separately so a scan that asks for a SMALLER
# budget can't permanently lower it for every later scan in the process.
_LLM_DEFAULT_MAX = int(os.getenv("LLM_MAX_CALLS", "200"))
_LLM_MAX_CALLS = _LLM_DEFAULT_MAX


def _llm_budget_ok() -> bool:
    global _LLM_CALLS
    with _LLM_CALLS_LOCK:
        if _LLM_CALLS >= _LLM_MAX_CALLS:
            return False
        _LLM_CALLS += 1
        return True


def reset_llm_budget(max_calls: Optional[int] = None) -> None:
    """Start a fresh per-run LLM budget. Call once at the top of a scan.

    The counter is process-wide, so without this a long-lived API process burns
    the ceiling permanently: after ~200 calls (two crawl-enabled scans) EVERY
    later scan silently degrades to heuristics, while `brain_status()` still
    reports the brain healthy because it only shells `claude --version`.

    `max_calls=None` restores the configured LLM_MAX_CALLS ceiling — a scan that
    asked for a smaller budget must not shrink every later scan in the process.

    Caveat: the budget is process-wide, so two scans running CONCURRENTLY in one
    process reset each other's counter. (Progress is per-job — this one is not.)
    Single scan at a time is the assumption; revisit if that changes.
    """
    global _LLM_CALLS, _LLM_MAX_CALLS
    with _LLM_CALLS_LOCK:
        _LLM_CALLS = 0
        _LLM_MAX_CALLS = (int(max_calls)
                          if max_calls is not None and int(max_calls) > 0
                          else _LLM_DEFAULT_MAX)


def llm_budget_state() -> tuple:
    """(used, ceiling) — for logging and the coverage/degraded notes."""
    with _LLM_CALLS_LOCK:
        return _LLM_CALLS, _LLM_MAX_CALLS


def brain_status(timeout: int = 12):
    """Cheap, no-cost liveness check for the configured LLM brain.

    Returns (ok: bool, reason: str). For claude_code this only resolves the CLI
    binary and runs `claude --version` — no API call, no tokens spent — so a
    deterministic-only fallback can be surfaced loudly instead of failing silently
    (e.g. when a hardened systemd service runs as a user that can't reach the
    machine's logged-in `claude` session).
    """
    provider = os.getenv("LLM_PROVIDER", "claude").lower()
    if provider in ("claude_code", "claude-code", "cli"):
        binary = os.getenv("CLAUDE_CODE_BIN") or shutil.which("claude")
        if not binary:
            return False, "claude CLI not found on PATH (set CLAUDE_CODE_BIN)"
        if os.path.isabs(binary) and not os.access(binary, os.X_OK):
            return False, f"claude CLI not readable/executable for this user ({binary})"
        try:
            r = subprocess.run([binary, "--version"], capture_output=True,
                               text=True, timeout=timeout)
        except (FileNotFoundError, PermissionError) as e:
            return False, f"claude CLI not runnable for this user ({binary}): {e}"
        except subprocess.TimeoutExpired:
            return False, "claude --version timed out"
        if r.returncode != 0:
            return False, f"claude --version failed: {(r.stderr or r.stdout or '').strip()[:160]}"
        return True, f"claude_code ({(r.stdout or '').strip()[:40]})"
    if provider == "claude":
        ok = bool(os.getenv("ANTHROPIC_API_KEY"))
        return ok, ("anthropic api key set" if ok else "ANTHROPIC_API_KEY missing")
    if provider == "opencode":
        binary = os.getenv("OPENCODE_BIN") or shutil.which("opencode")
        if not binary:
            return False, "opencode CLI not found on PATH (set OPENCODE_BIN)"
        if os.path.isabs(binary) and not os.access(binary, os.X_OK):
            return False, f"opencode CLI not readable/executable for this user ({binary})"
        try:
            r = subprocess.run([binary, "--version"], capture_output=True,
                               text=True, timeout=timeout)
        except (FileNotFoundError, PermissionError) as e:
            return False, f"opencode CLI not runnable ({binary}): {e}"
        except subprocess.TimeoutExpired:
            return False, "opencode --version timed out"
        if r.returncode != 0:
            return False, f"opencode --version failed: {(r.stderr or r.stdout or '').strip()[:160]}"
        ver = (r.stdout or "").strip()[:40]
        try:
            a = subprocess.run([binary, "auth", "list"], capture_output=True,
                               text=True, timeout=timeout)
        except Exception as e:
            # Unknown auth state must read as unhealthy, never as healthy:
            # callers silently degrade to heuristics on a healthy report.
            return False, f"opencode auth check failed: {e}"
        if a.returncode != 0 or not (a.stdout or "").strip():
            return False, "opencode has no authenticated providers (run `opencode auth login`)"
        return True, f"opencode ({ver})"
    if provider == "ollama":
        return True, f"ollama ({os.getenv('OLLAMA_BASE_URL', 'localhost')})"
    return True, provider


def claude_chat(message: str, *, session_id: str, resume: bool = False,
                system: Optional[str] = None, model: Optional[str] = None,
                effort: Optional[str] = None, timeout: int = 180):
    """Conversational claude_code turn bound to a persistent session id.

    First turn  -> resume=False: creates `session_id` and seeds `system` (the
                   test context), so the chat "knows" that scan.
    Later turns -> resume=True: continues the SAME session; context accrues.

    Each test (job) keeps its own session id, so chats never cross-contaminate.
    Sandboxed like the brain: tools disabled, strict MCP, no external API key.
    Returns (reply_text, session_id).
    """
    binary = os.getenv("CLAUDE_CODE_BIN") or shutil.which("claude") or "claude"
    model = model or os.getenv("CLAUDE_CODE_MODEL") or "claude-sonnet-5"
    cmd = [binary, "-p", "--output-format", "json", "--strict-mcp-config", "--model", model]
    if effort:
        cmd += ["--effort", effort]
    cmd += ["--disallowed-tools", *ClaudeCodeProvider._DISALLOWED_TOOLS]
    if resume:
        cmd += ["--resume", session_id]
    else:
        cmd += ["--session-id", session_id]
    # Re-seed the findings context on EVERY turn (not just the first) so a long
    # chat can never drift away from the scan it's about.
    if system:
        cmd += ["--append-system-prompt", system]
    env = {k: v for k, v in os.environ.items()
           if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")}
    # Run in a neutral dir (the data home) so the chat doesn't inherit the
    # project's dev-oriented CLAUDE.md as context. Sessions persist per-cwd, so
    # keeping it stable is what lets --resume find the conversation.
    cwd = os.getenv("HOME") or ClaudeCodeProvider._PROJECT_ROOT
    try:
        proc = subprocess.run(cmd, input=message, capture_output=True, text=True,
                              timeout=timeout, cwd=cwd, env=env)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"chat timed out after {timeout}s")
    raw = (proc.stdout or "").strip()
    if not raw:
        raise RuntimeError(f"chat: no output (exit {proc.returncode}): {(proc.stderr or '').strip()[:300]}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw, session_id
    if data.get("is_error"):
        raise RuntimeError(f"chat error: {str(data.get('result'))[:300]}")
    return str(data.get("result", "")), str(data.get("session_id") or session_id)


def opencode_chat(message: str, *, session_id: str, resume: bool = False,
                  system: Optional[str] = None, model: Optional[str] = None,
                  effort: Optional[str] = None, timeout: int = 180):
    """Conversational opencode turn bound to a persistent session id.

    First turn  -> resume=False: opencode creates a session; its id is read
                    back from the JSON events and returned.
    Later turns -> resume=True: continues the SAME session via --session.

    Each test (job) keeps its own session id, so chats never cross-contaminate.
    Sandboxed like the brain: deny-all agent, hermetic config, cwd pinned.
    Returns (reply_text, session_id).
    """
    provider = OpenCodeProvider(model=model, effort=effort, timeout=timeout)
    text, sid = provider._run(
        message, system=system, session=session_id if resume else None)
    if not sid:
        raise RuntimeError("opencode returned no sessionID — cannot continue this chat")
    return text, sid


def brain_chat(message: str, *, session_id: str, resume: bool = False,
               system: Optional[str] = None, model: Optional[str] = None,
               effort: Optional[str] = None, timeout: int = 180):
    """Route a conversational turn to the configured brain's chat backend."""
    if os.getenv("LLM_PROVIDER", "claude").lower() == "opencode":
        return opencode_chat(message, session_id=session_id, resume=resume,
                             system=system, model=model, effort=effort,
                             timeout=timeout)
    return claude_chat(message, session_id=session_id, resume=resume,
                       system=system, model=model, effort=effort,
                       timeout=timeout)


class LLMClient:
    def __init__(self, model: Optional[str] = None, effort: Optional[str] = None,
                 log=None):
        self.provider_name = os.getenv("LLM_PROVIDER", "claude").lower()
        self._model = model
        self._effort = effort
        self._log = log    # activity sink (engine log) — None keeps old silence
        self.provider = self._setup_provider()
        self._cache: Dict[Any, str] = {}
        self._cache_lock = threading.Lock()
        self._cache_enabled = os.getenv("LLM_CACHE", "1") != "0"

    def _setup_provider(self) -> LLMProvider:
        if self.provider_name in ("claude_code", "claude-code", "cli"):
            return ClaudeCodeProvider(model=self._model, effort=self._effort)

        if self.provider_name == "opencode":
            return OpenCodeProvider(model=self._model, effort=self._effort)

        if self.provider_name == "claude":
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not found in .env")
            return ClaudeProvider(api_key=api_key, model=os.getenv("CLAUDE_MODEL", "claude-sonnet-5"))
        
        elif self.provider_name == "ollama":
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
            api_key = os.getenv("OLLAMA_API_KEY", "ollama")
            model = os.getenv("OLLAMA_MODEL", "llama3")
            return OllamaProvider(base_url=base_url, api_key=api_key, model=model)
        
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider_name}")

    def _emit(self, label: str, elapsed: float, cached: bool = False) -> None:
        if self._log is None:
            return
        model = getattr(self.provider, "model", self.provider_name)
        usage = ""
        if not cached:
            stats = getattr(self.provider, "last_usage", None) or {}
            if stats.get("input") or stats.get("output") or stats.get("cost"):
                usage = (f" · {_fmt_tokens(stats.get('input', 0))} in/"
                         f"{_fmt_tokens(stats.get('output', 0))} out · "
                         f"${float(stats.get('cost', 0)):.4f}")
        try:
            self._log(f"🧠 {label or 'brain'} → {model} "
                      f"({elapsed:.1f}s{' · cached' if cached else ''}{usage})")
        except Exception:
            pass

    def ask(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000,
            label: str = "") -> str:
        key = (system_prompt, user_prompt, max_tokens)
        if self._cache_enabled:
            with self._cache_lock:
                if key in self._cache:
                    self._emit(label, 0.0, cached=True)
                    return self._cache[key]      # cache hits don't consume budget
        if not _llm_budget_ok():
            raise RuntimeError("LLM call budget exhausted (LLM_MAX_CALLS)")
        start = time.monotonic()
        if not self._cache_enabled:
            result = self.provider.generate(system_prompt, user_prompt, max_tokens)
            self._emit(label, time.monotonic() - start)
            return result
        result = self.provider.generate(system_prompt, user_prompt, max_tokens)
        with self._cache_lock:
            self._cache[key] = result
        self._emit(label, time.monotonic() - start)
        return result

    def ask_json(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000,
                 retries: int = 1, label: str = "") -> Dict[str, Any]:
        prompt, raw = user_prompt, ""
        for attempt in range(retries + 1):
            raw = self.ask(system_prompt, prompt, max_tokens, label=label)
            parsed = extract_json(raw)
            if isinstance(parsed, dict):
                return parsed
            if isinstance(parsed, list):
                return {"items": parsed}      # tolerate a top-level array
            if attempt < retries:
                print(f"⚠️ JSON parse failed (attempt {attempt + 1}/{retries + 1}), retrying…")
                prompt = (user_prompt + "\n\nIMPORTANT: Respond with ONLY a single valid JSON object. "
                          "No prose, no markdown fences, no trailing commas.")
        print(f"❌ Could not parse JSON after {retries + 1} attempts. Preview: {raw[:300]!r}")
        return {}
