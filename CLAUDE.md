# Intent-Aware — working notes for Claude

Autonomous QA + security tester for non-technical app builders. Input = a live URL (+ optional
description / OpenAPI spec / credentials); output = a founder-grade report. The LLM is the brain;
deterministic plugins are the hands. Read [README.md](README.md) for the full picture and
[IMPROVEMENT_PLAN.md](IMPROVEMENT_PLAN.md) for the architecture history.

## Prime directive — isolation
- This project is **self-contained** and has its **own `.git`** (remote: `AyoubEttalbi/Intent-Aware`,
  branch `main`). Scope all git to this repo root; everything the project needs lives under it.
- The brain is the local **Claude Code CLI** (`claude -p`, provider `claude_code` in `agent/llm.py`),
  run **sandboxed**: all tools disabled, `--strict-mcp-config`, cwd pinned, and the child env strips
  `ANTHROPIC_API_KEY`/`ANTHROPIC_AUTH_TOKEN` (see Operations below — this matters).
- Alternative brain: **opencode CLI** (`LLM_PROVIDER=opencode`, `OpenCodeProvider` in `agent/llm.py`).
  Sandboxed via the `intent-brain` agent file (`.opencode/agents/intent-brain.md`: every tool
  permission denied incl. MCP wildcards + `"*"` catch-all, temperature 0) plus `--pure`,
  cwd/`--dir` pinned, an allowlisted child env, and stdin prompts. The CLI only resolves
  agents from files (env-injected config is ignored in 1.18.x — probed, do not rely on it),
  and `run` has no system channel, so the per-call system prompt is composed into the
  message. Model is a fully-qualified `provider/model` id (`OPENCODE_MODEL`, default
  the fireworks-ai `qwen-max-latest` router). Zen free-tier models (incl. `big-pickle`)
  403 against sandboxed custom agents — verified by probe, never default one.
  Auth is `opencode auth`, no key in `.env`.
- Self-contained runtime: own `.venv` and project-local Playwright browsers (`PLAYWRIGHT_BROWSERS_PATH=./.browsers`).
- **Historical note (was VPS-hosted):** it ran on a VPS *shared with the production GridCRM*, so the rule
  there was "never touch anything outside the project dir, never change the host, no `apt install`." That
  constraint was about protecting prod — **on a local machine it no longer applies** (you may install
  system deps, run your own systemd unit or just `uvicorn`, etc.). The shared-host story explains some
  design choices (e.g. the tight CPU quota) flagged below.

## Architecture — edit the live engine, not the legacy
Live v2 path (what runs): `agent/engine.py` (orchestrator) · `agent/llm.py` (brain) ·
`agent/planner.py` · `agent/prompt_safety.py` · `core/` (models, http, surface, context, auth_adapters,
discovery) · `attacks/` (base + payloads + 16 plugins) ·
`qa/` (crawler, page_model, qa_planner, executor, oracle, auth, flows, responsive, cross_browser) ·
`detection/explainer.py` · `reports/founder_report.py` · `extractors/parser.py` · `api/main.py`.

**Legacy v1 — do NOT build on these** (kept only for the `tests/` suite): `agent/loop.py`,
`agent/state_graph.py`, `detection/layer1|2|3*.py`, `reports/generator.py`, `extractors/intent.py`,
`extractors/assumptions.py`, `execution/crawler.py`, `execution/runner.py`.

## Run & test
```bash
./.venv/bin/python ...                       # always use the venv
# start the demo target app (localhost only):
./.venv/bin/python -m uvicorn target_app.main:app --host 127.0.0.1 --port 8080
# browser features need the project-local browsers:
export PLAYWRIGHT_BROWSERS_PATH="$(pwd)/.browsers"
```

**Fast iteration = no-LLM tests.** Every `claude -p` call costs ~20–40s and real money, so for logic
changes stub the LLM and exercise the deterministic core:
```python
eng = SecurityEngine(spec_url, desc, base_url, crawl_ui=False, auth_identities=[...])
eng.planner.plan = lambda *a, **k: {}        # skip the LLM planner
eng.explainer.enrich = lambda *a, **k: None  # skip the LLM explainer
res = eng.run()
```
Only run a **full-LLM** verification (no stubs) once at the end, and run it in the **background**
(it's long): launch with `run_in_background`, then a `until ! kill -0 <pid>; do sleep 3; done; cat log`
waiter. Bind any server to `127.0.0.1` only.

## Gotchas (learned the hard way)
- **Never `pkill -f "uvicorn …"`** — the pattern matches *your own shell's* command line and kills it
  → `exit 144`. Kill by **port** instead:
  `for p in $(ss -ltnp | grep ':8080' | grep -oP 'pid=\K[0-9]+'); do kill "$p"; done`.
- **WebKit can't launch here** (missing host libs, and we may not `apt install`). Cross-browser
  degrades gracefully — Chromium + Firefox work; WebKit is skipped with a message. That's expected.
- `httpx` **follows redirects**, so an auth-gated endpoint that 303s to `/login` returns 200 (the login
  page). Don't treat 200 as "accessible" — compare the body to the owner's response (see `authz_matrix`).
- **Form vs JSON**: send `data=` for `application/x-www-form-urlencoded` endpoints, `json=` otherwise.
  `Endpoint.request_content_type` carries this; write-request builders set `Request.content_type`.
- The QA judge must stay **grounded** — verdicts come only from the *observed* result, never from page
  content (otherwise it hallucinates security bugs). Keep the strict "default to PASS" prompt.
- Long sessions accumulate stray headless-browser processes; clean by port/comm filter, never by a
  pattern that matches the shell.

## Conventions
- **Effect oracles, not status codes.** A finding must prove real exploitation (differential baseline,
  marker reflection, time delay, persisted read-back). This keeps false positives low — the product's
  whole credibility. Verify new detectors find the planted bug **and** produce zero FP on clean endpoints.
- **Add an attack plugin**: subclass `AttackPlugin` in `attacks/`, `@register` it, add it to
  `attacks/__init__.py`. Set `identity_agnostic = True` for input-injection (runs once as anon); leave
  it `False` for access-control checks (runs per identity). Findings dedup by `(vuln_class, endpoint)`.
- **Memory**: thread relevant context through `RunContext.brief()` into LLM prompts; record facts/
  findings so the brain doesn't repeat work or contradict itself.
- To verify new bug classes, add a **deliberately-vulnerable fixture** to `target_app/main.py` (keep the
  existing planted bugs intact), then assert the engine catches it.

## v2.1 — flexibility & safety (must-know)
- **Regression gate:** `./.venv/bin/python -m pytest tests/test_v2_engine.py` (13 tests, ~2.5 min, no
  LLM/browser). It boots `target_app`, logs in real cookie + token_exchange identities, and asserts all
  **16** detectors catch their planted bug with **zero FP**. Run it after any change to the engine/attacks.
- **Safety defaults:** write-based probes (`mass_assignment`, `stored_xss`, body-injection) are OFF unless
  `allow_writes=True`; DELETE is never injected. `spec_url` is host-allowlisted and refuses non-http
  sources (no SSRF/local-file-read). Redirects are followed only same-host for safe methods.
- **Auth adapters** (`core/auth_adapters.py`): `auth_identities` entries carry a `type` —
  `form` (browser), `bearer`, `api_key`, `header`, `session`, `token_exchange`. Non-`form` resolve with
  NO browser. `owned_resource_ids` is auto-harvested (`core/discovery.py`) when omitted.
- **Discovery:** `spec_url` optional (auto-probed); YAML + Swagger-2.0; UI shadow endpoints are first-class
  (params/body/content-type/auth inferred); GraphQL detected + introspection-checked.
- **Prompts:** untrusted app text is wrapped via `agent/prompt_safety.wrap_untrusted` + a data-framing
  system rule — keep new prompts doing this. Temperature is pinned to 0. `LLM_MAX_CALLS` caps brain calls.
- **New plugins** live in `attacks/web_extra.py`, `attacks/jwt_attacks.py`, `attacks/graphql.py`; each needs
  an effect oracle, a planted fixture in `target_app/main.py`, and a test assertion. Keep fixtures distinct
  (e.g. SQLi sleeps on `sleep(`, command-injection on `; sleep`).

## Operations & hard-won findings (read before touching auth, the brain, or the API)
These are real production lessons. Re-introducing any of them re-breaks a shipped fix.

- **The brain's auth is OAuth, and OAuth refresh tokens ROTATE.** `claude -p` authenticates from a
  credentials file in its config dir (`CLAUDE_CONFIG_DIR`). If you seed that from a *copy* of another
  install's creds, it goes stale the moment that other install refreshes (the old refresh token is
  single-use and gets invalidated) → `401 Invalid authentication credentials` in chat/scan. **Durable
  fix = a dedicated long-lived token for this install: `claude setup-token`** (writes to the config
  dir; doesn't rotate hourly; won't fight another login). Re-copying creds is only a ~1h band-aid.
- **`ANTHROPIC_API_KEY` placeholder trap.** A `.env` line like `ANTHROPIC_API_KEY=your_key_here` gets
  loaded and handed to the `claude -p` child, which then tries that bogus *external* key and fails
  *silently* (the `--version` probe still passes, so `brain_available` looks True while every real call
  errors). `ClaudeCodeProvider.generate` strips `ANTHROPIC_API_KEY`/`ANTHROPIC_AUTH_TOKEN` from the
  child env on purpose — keep it that way, and keep the placeholder OUT of `.env`.
- **Login must survive load — don't "simplify" `qa/auth.py`.** When the scan runs many parallel browser
  pages + `claude -p` subprocesses under a CPU cap, the SPA login page mounts *slowly*; a bare
  `page.fill(sel)` would hard-timeout at 30s and abort the whole login (`Page.fill: Timeout 30000ms
  exceeded`). `login()` therefore does a **robust fill** (explicit `wait_for_selector(state=visible)` +
  one retry) and **verifies by polling** real success signals for ~8s (SPA redirects resolve async and
  are slow under load). `_verify` treats success as: an explicit success URL, navigation off the login
  page, OR a freshly-set session cookie — and the cookie regex is intentionally broad
  (`sess|sid|auth|token|jwt|connect|access|refresh|login|gcrm|csrf|remember|_user`) because real apps
  name cookies anything (e.g. GridCRM sets `gcrm_access`/`gcrm_refresh`). Never gate success on "the
  password field vanished" — a show-password toggle clears it and false-positives.
- **Live progress logs must persist.** `api/main.py` keeps the FULL per-job log history (high safety
  cap) so the UI log never loses earlier activity mid-test; the frontend renders the full scrollable
  history. The earlier "keep only the last N lines" made logs appear to vanish during a scan.
- **CPU contention is real (was the VPS cap, `CPUQuota=150%`).** Under a tight CPU quota shared by the
  browser and the `claude` subprocesses, browser ops inflate ~25× (measured: 0.8s → 19.6s for the same
  login). This is why per-call LLM latency and login timeouts were so bad. **On local hardware this
  mostly evaporates** — give it real cores. The crawler bounds concurrent `claude` procs with a
  semaphore (~250 MB each); tune `CRAWL_CONCURRENCY` to your machine.

## Local development (the project is moving VPS → local)
Stand it up from a clone (a full setup recipe with the actual tokens/creds is kept OUT of the repo —
ask the owner for `intent-aware-LOCAL-SETUP.md`):
```bash
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
export PLAYWRIGHT_BROWSERS_PATH="$(pwd)/.browsers"
./.venv/bin/python -m playwright install chromium firefox      # project-local browsers
cp .env.example .env                                            # then fill real values (NO ANTHROPIC_API_KEY)
# brain: install the Claude Code CLI and mint a token for THIS project's config dir:
#   CLAUDE_CONFIG_DIR=$(pwd)/.claude  claude setup-token
# run the API + the web UI:
./.venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port 8473
cd web && npm install && npm run dev        # Vite dev server on 127.0.0.1:6173
```
Ports: API `8473`, web dev `6173`, demo target app `8080`. Set `LLM_PROVIDER=claude_code` and
`CLAUDE_CONFIG_DIR`/`CLAUDE_CODE_BIN` so the brain uses this project's token, not your personal login.

## Roadmap — what's next
1. **Per-call LLM latency (the big one).** Each `claude -p` call is 30–80s (process spawn + API). Plan:
   (a) Tier-1, free: kill the JSON-retry that doubles latency, use a neutral cwd so the crawler's brain
   doesn't load this CLAUDE.md, trim the prompt (cap `context.brief()` + page-model size); (b) Tier-2,
   pick a transport: route through the already-deployed **LiteLLM** proxy (~3–8s, effectively free) vs a
   warm/persistent claude session vs a direct API key. Locally, also just give it more cores.
2. **Confirm login fix on a 2nd real app** beyond GridCRM (different cookie names / 2-step logins).
3. **`🚩 User journey failed: User Login` E2E finding** — decide if it's a real flow bug or a
   FlowPlanner quirk (it's separate from `qa/auth.login()`, which now succeeds).
4. **WebKit cross-browser** — blocked on the old host's missing libs; revisit locally (`playwright
   install webkit` should now work) so cross-browser isn't degraded.
5. **Token durability** — make `claude setup-token` the standard so the brain never 401s on rotation.

## Definition of done
Tests pass against `target_app` (all planted bugs caught, **zero** false positives), code compiles,
nothing unrelated touched. Report outcomes honestly — if something is a known limitation (e.g. WebKit),
say so.
