import os
import json
import re
import shutil
import subprocess
import threading
import anthropic
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
from dotenv import load_dotenv

load_dotenv()


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
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6",
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
                 timeout: Optional[int] = None):
        self.binary = (binary or os.getenv("CLAUDE_CODE_BIN")
                       or shutil.which("claude") or "claude")
        # Cost-efficient default; set CLAUDE_CODE_MODEL='' to use the CLI's
        # own session default instead.
        self.model = model if model is not None else os.getenv("CLAUDE_CODE_MODEL", "claude-sonnet-4-6")
        self.timeout = int(timeout if timeout is not None else os.getenv("CLAUDE_CODE_TIMEOUT", "900"))

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000) -> str:
        cmd = [self.binary, "-p", "--output-format", "json", "--strict-mcp-config"]
        if self.model:
            cmd += ["--model", self.model]
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


# Process-wide LLM-call ceiling so an unexpectedly large target can't trigger
# unbounded (slow, costly) model calls. Callers already degrade to heuristics on error.
_LLM_CALLS = 0
_LLM_CALLS_LOCK = threading.Lock()
_LLM_MAX_CALLS = int(os.getenv("LLM_MAX_CALLS", "200"))


def _llm_budget_ok() -> bool:
    global _LLM_CALLS
    with _LLM_CALLS_LOCK:
        if _LLM_CALLS >= _LLM_MAX_CALLS:
            return False
        _LLM_CALLS += 1
        return True


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
    if provider == "ollama":
        return True, f"ollama ({os.getenv('OLLAMA_BASE_URL', 'localhost')})"
    return True, provider


class LLMClient:
    def __init__(self):
        self.provider_name = os.getenv("LLM_PROVIDER", "claude").lower()
        self.provider = self._setup_provider()
        self._cache: Dict[Any, str] = {}
        self._cache_lock = threading.Lock()
        self._cache_enabled = os.getenv("LLM_CACHE", "1") != "0"

    def _setup_provider(self) -> LLMProvider:
        if self.provider_name in ("claude_code", "claude-code", "cli"):
            return ClaudeCodeProvider()

        if self.provider_name == "claude":
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not found in .env")
            return ClaudeProvider(api_key=api_key, model=os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6"))
        
        elif self.provider_name == "ollama":
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
            api_key = os.getenv("OLLAMA_API_KEY", "ollama")
            model = os.getenv("OLLAMA_MODEL", "llama3")
            return OllamaProvider(base_url=base_url, api_key=api_key, model=model)
        
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider_name}")

    def ask(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000) -> str:
        key = (system_prompt, user_prompt, max_tokens)
        if self._cache_enabled:
            with self._cache_lock:
                if key in self._cache:
                    return self._cache[key]      # cache hits don't consume budget
        if not _llm_budget_ok():
            raise RuntimeError("LLM call budget exhausted (LLM_MAX_CALLS)")
        if not self._cache_enabled:
            return self.provider.generate(system_prompt, user_prompt, max_tokens)
        result = self.provider.generate(system_prompt, user_prompt, max_tokens)
        with self._cache_lock:
            self._cache[key] = result
        return result

    def ask_json(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000,
                 retries: int = 1) -> Dict[str, Any]:
        prompt, raw = user_prompt, ""
        for attempt in range(retries + 1):
            raw = self.ask(system_prompt, prompt, max_tokens)
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
