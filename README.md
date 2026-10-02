# Intent-Aware — Autonomous QA + Security Tester

> Point it at a live app. It explores everything like a real QA engineer, attacks it like a
> real pentester, and hands back a plain-language report a non-technical founder can act on.

Built for the people shipping apps today — vibe-coders, no-code builders, solo founders — who don't
have a QA team or a security background. You give it a **URL** (and optionally a description, an
OpenAPI spec, and login credentials); it does the rest.

---

## What makes it different

| | Scripted tests | Fuzzers / scanners | **Intent-Aware** |
|---|---|---|---|
| Understands what the app is *for* | ❌ | ❌ | ✅ (LLM reads the app) |
| Finds **functional** bugs (broken forms, dead links, journeys) | partial | ❌ | ✅ |
| Finds **security** bugs (auth, injection, access control) | ❌ | partial | ✅ |
| Tests **behind a login** + across **roles** | ❌ | ❌ | ✅ |
| Verifies real exploitation (not just "got 200") | ❌ | ❌ | ✅ effect oracles |
| Explains findings in **plain language** | ❌ | ❌ | ✅ |
| Requires you to write tests | ✅ | ❌ | ❌ |

The core idea: **the LLM is the brain, deterministic plugins are the hands.** The brain decides what
to test, fills forms with realistic data, understands each screen, and explains bugs. The plugins own
the payloads and the *proof* (differential checks, marker reflection, time delays) — so every finding
is reproducible and false positives stay low.

---

## The brain: Claude Code, no API key

The LLM backend is the locally-installed **Claude Code CLI** (`claude -p`), wired in
[`agent/llm.py`](agent/llm.py) as the `claude_code` provider. Authentication comes from the machine's
logged-in `claude` session — **no `ANTHROPIC_API_KEY` required**. The CLI runs fully sandboxed: all
built-in tools disabled, MCP servers ignored (`--strict-mcp-config`), cwd pinned to the project — so
it can only read the prompt and return text. Alternative providers (`claude` via Anthropic API,
`ollama`) are available by changing `LLM_PROVIDER`.

---

## How it works

```
Input: live URL  (spec / description / credentials all OPTIONAL)
            │
            ▼
   ┌──────────────────────┐   OpenAPI auto-discovery (JSON/YAML, v2+v3) + LLM-guided browser
   │  Discover            │   crawl (auth-aware, SPA) + GraphQL detection → one structured
   └──────────────────────┘   Surface: endpoints + UI map + shadow spec (params/body/auth)
            │
            ▼
   ┌──────────────────────┐   anon · + each role via auth ADAPTERS (form/bearer/api_key/
   │  Identities          │   session/token_exchange) · owned ids + foreign ids auto-harvested
   └──────────────────────┘
            │
            ▼
   ┌──────────────────────┐   LLM picks targets, sample values, priorities; explains findings
   │  Brain (Claude Code) │   shared run-memory carries "what we know" into every decision
   └──────────────────────┘
            │
       ┌────┴───────────────────────────┐
       ▼                                 ▼
┌──────────────────┐            ┌──────────────────────┐
│  Security matrix │            │  QA crawler          │
│  16 attack       │            │  understand → test → │
│  plugins · oracles│           │  execute → verify    │
└──────────────────┘            └──────────────────────┘
       │                                 │
       └────────────────┬────────────────┘
                        ▼
   ┌──────────────────────┐   A–F grade (coverage-gated) · confirmed vs needs-review ·
   │  Founder report      │   plain language · repro curl / steps · screenshots · coverage
   └──────────────────────┘
```

Read-only by default and host-scoped, so it's safe to point at a third-party target; write-based
probes are opt-in (`allow_writes`) for disposable/staging environments only.

Pipeline: **discover → plan → attack + QA-crawl → detect → explain → report**, in
[`agent/engine.py`](agent/engine.py).

---

## Security: the attack matrix

Sixteen plugins ([`attacks/`](attacks/)), each owning its payloads **and** an effect-based oracle.
Identity-aware: access-control checks run as anon **and** every logged-in role; injection checks run
once (behaviour is identity-independent).

| Plugin | Vulnerability | How it proves it |
|---|---|---|
| `broken_auth` | Broken authentication / access control | rejects no-credentials but accepts an invalid token; or auth-required endpoint reachable by anon |
| `idor` | Insecure Direct Object Reference | enumerates ids, confirms a *different* record's sensitive data is returned |
| `mass_assignment` | Privilege escalation via extra fields | injects `role`/`is_admin`/… then confirms it persisted |
| `sqli` | SQL injection — **error-based + blind/time-based** | DB error signature, or a sleep payload that delays the response (re-tested to confirm) |
| `xss` | Reflected XSS | unique marker reflected **unescaped** in an HTML response |
| `stored_xss` | Stored / persistent XSS | writes a marked payload, reads it back, confirms it renders unescaped |
| `path_traversal` | Directory traversal / file read | `../` payload returns a system-file signature |
| `authz_matrix` | Multi-role authorization | **vertical** (non-admin reaches admin endpoint) + **horizontal** (user A reads user B's resource) |
| `jwt_attacks` | JWT signature not verified | forged `alg=none` / stripped-signature token returns the same protected data |
| `cors_misconfig` | CORS misconfiguration | an arbitrary `Origin` is reflected in `Access-Control-Allow-Origin` (esp. with credentials) |
| `open_redirect` | Open redirect | a redirect param 3xx-redirects to an attacker-controlled host |
| `ssti` | Server-side template injection | an uncommon template expression is evaluated server-side |
| `command_injection` | OS command injection | a shell payload causes a reproducible time delay (re-tested) |
| `secrets_exposure` | Secret / PII exposure | a response leaks a high-signal secret (AWS / Stripe / private key / …) |
| `graphql_introspection` | GraphQL introspection enabled | `/graphql` discloses its `__schema` to an anonymous caller |
| `security_headers` | Missing hardening headers | CSP / HSTS / X-Frame-Options / nosniff absent (reported once, LOW) |

Each detector owns an **effect oracle** (it proves real exploitation), and **write-based** probes
(`mass_assignment`, `stored_xss`, body-injection) are **off by default** — set `allow_writes` only against
a disposable/staging target. DELETE is never injected.

**Multi-role authz** is the headline capability: give it two logins (e.g. `admin` + `user`, each with
its owned resource ids) and it catches privilege-escalation and cross-user access bugs that only exist
*behind* a login — which anon-only and single-user testing structurally cannot find.

---

## QA: the smart crawler

A human-QA-style browser crawler ([`qa/`](qa/)) driven by the brain:

- **Crawl everything** — frontier crawl of pages/links/forms (same-host, bounded), safe by default
  (skips logout / delete / pay).
- **Understand each screen** — the LLM reads a structured page snapshot and states the page's intent.
- **Generate + run test cases** — happy-path, negative, boundary, and input-validation tests per form,
  with realistic data; a grounded LLM judge decides pass/fail from the *observed* result only.
- **Auth-gated crawling** — auto-logs-in and explores **behind** the login.
- **Multi-step E2E journeys** — the LLM designs user journeys (e.g. create → verify it appears) and runs
  them as one stateful session.
- **Responsive testing** — renders at 320 / 375 / 768 / 1024 / 1440, screenshots each, flags horizontal
  overflow.
- **Cross-browser** — Chromium + Firefox (WebKit/Safari when host libraries are present, else skipped
  gracefully).
- **Shadow spec** — captures the real API calls the UI makes and feeds them back into the attack matrix.

Deterministic QA oracles also catch broken links (4xx), JavaScript exceptions, and server errors.

---

## The report

[`reports/founder_report.py`](reports/founder_report.py) produces a founder-grade report
(`latest_report.md` + JSON), not a wall of jargon:

- **A–F security grade** + executive summary + top priorities
- **Confirmed issues** vs **needs human review** (by confidence)
- Per finding: **what we found / why it matters / how to fix** in plain English
- Reproduction: copy-paste **`curl`** (API) or **numbered steps + screenshot** (UI)
- **Coverage**: endpoints discovered, requests sent, attack classes, and **roles/identities tested**

---

## Engine qualities

- **Safe by default** — read-only unless `allow_writes`; DELETE never injected; requests host-allowlisted
  on **every** redirect hop; `spec_url` refuses non-http sources (no SSRF / local-file read); credentials
  redacted from repros and run-memory.
- **Honest coverage** — a **LOW-COVERAGE** gate withholds a passing grade (and says why) when too little of
  the app could be tested, so "couldn't test" can't masquerade as "secure".
- **Prompt-injection hardened** — untrusted app text (page snapshots, API bodies, descriptions) is fenced
  in a per-run sentinel with a data-framing system rule, so a hostile target can't hijack the brain.
- **Bounded** — per-run **request** budget (enforced at the point of spend) *and* an LLM-call budget;
  rate-limited with 429/Retry-After backoff.
- **Shared run-memory** ([`core/context.py`](core/context.py)) — learned facts + harvested ids flow into
  every brain call, so it doesn't repeat work or contradict itself.
- **Concurrent** attack execution (thread-safe) + an in-run LLM response cache; temperature pinned to 0
  for reproducible findings.
- **Robust** LLM JSON parsing (brace-matching, fence-stripping, trailing-comma repair) so a messy model
  response never silently drops a finding.
- **Form-aware** — sends `application/x-www-form-urlencoded` or JSON based on the endpoint's spec/observed
  traffic; repro `curl` matches.
- **Resumable** — the run context is returned and can be passed back via `resume_context` (or
  `resume_from_job_id` on the API).

---

## Getting started

Requires Python 3.11+ and a logged-in LLM brain: the Claude Code CLI (for the default `claude_code`
provider) or the opencode CLI with at least one funded provider (`opencode auth login`,
then `LLM_PROVIDER=opencode` — see `.env.example` for the verified model).

```bash
# 1. install
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
PLAYWRIGHT_BROWSERS_PATH="$(pwd)/.browsers" ./.venv/bin/playwright install chromium firefox

# 2. configure
cp .env.example .env          # default LLM_PROVIDER=claude_code needs no API key

# 3a. run the built-in demo (vulnerable target app + full analysis)
./.venv/bin/python run_demo.py

# 3b. or run the API server
./.venv/bin/uvicorn api.main:app --port 8000
```

Then POST a job:

```bash
curl -X POST http://localhost:8000/analyze -H 'Content-Type: application/json' -d '{
  "spec_url": "https://yourapp.com/openapi.json",
  "base_url": "https://yourapp.com",
  "description": "A notes app. Users should only see their own notes; admins manage users.",
  "crawl_ui": true,
  "auth": {"login_url": "https://yourapp.com/login", "username": "alice", "password": "…",
           "success_url_contains": "dashboard"},
  "auth_identities": [
    {"name": "admin", "role": "admin", "login_url": "https://yourapp.com/login",
     "username": "alice", "password": "…", "owned_resource_ids": {"notes": ["1"]}},
    {"name": "user",  "role": "user",  "login_url": "https://yourapp.com/login",
     "username": "bob",   "password": "…", "owned_resource_ids": {"notes": ["2"]}}
  ],
  "cross_browser": ["firefox"]
}'
# → {"job_id": "..."}  then GET /status/{job_id}
```

The result includes `findings`, `coverage`, `grade`, `report_markdown`, and the run `context`.

---

## Configuration reference

**`/analyze` options** (all but `spec_url` / `base_url` optional):

| Field | Purpose |
|---|---|
| `base_url` | the app's base URL (the only truly required field) |
| `spec_url`, `description` | **optional**: OpenAPI URL (auto-discovered from well-known paths if omitted) + a plain-English description |
| `allow_writes` | permit mutating probes — **only** for a disposable/staging target (default `false`) |
| `extra_hosts` | additional in-scope hosts for split `app.*` / `api.*` topologies |
| `crawl_ui` | also run the smart QA crawler (default `false`) |
| `max_pages` | QA-crawl page budget (default 20) |
| `auth` | single login used for auth-gated crawling |
| `auth_identities` | multi-role logins for authz testing. Each is a declarative **auth adapter** — `type` one of: `form` (browser login, default), `bearer` (`{token}`), `api_key` (`{key, header}`), `header` (`{headers}`), `session` (`{cookies}`), or `token_exchange` (`{token_url, creds, token_path}` → bearer). Non-`form` types resolve **without a browser**, so JWT / API-key / mobile backends are testable behind login. `owned_resource_ids` is auto-discovered when omitted. |
| `cross_browser` | extra engines for the compatibility smoke, e.g. `["firefox","webkit"]` |
| `max_requests` | hard cap on attack requests, enforced at the point of spend (default 400) |
| `resume_context` / `resume_from_job_id` | resume a prior run (inline context, or by a prior job id on the API) |

**`.env`** (see [`.env.example`](.env.example)):

| Var | Default | Notes |
|---|---|---|
| `LLM_PROVIDER` | `claude_code` | `claude_code` (CLI, no key) · `claude` (Anthropic API) · `opencode` (opencode CLI, no key) · `ollama` |
| `CLAUDE_CODE_MODEL` | `claude-sonnet-5` | model for the CLI provider |
| `OPENCODE_MODEL` | fireworks `qwen-max-latest` router | fully-qualified `provider/model` for `LLM_PROVIDER=opencode` (Zen free-tier models reject the sandboxed agent — see `.env.example`) |
| `CLAUDE_MODEL` | `claude-sonnet-5` | model for the `claude` (API) provider; temperature is pinned to 0 |
| `LLM_CACHE` | `1` | in-run response cache; `0` to disable |
| `LLM_MAX_CALLS` | `200` | hard ceiling on LLM calls per run (brain degrades to heuristics past it) |
| `PLAYWRIGHT_BROWSERS_PATH` | `./.browsers` | keep browsers project-local |
| `CRAWLER_HEADLESS` | `true` | set `false` to watch the browser locally |

---

## Project structure

```
core/        models · http (identity-aware, scope-safe client) · surface (OpenAPI v2/v3 → endpoints) ·
             context (run-memory) · auth_adapters (browserless logins) · discovery (id harvesting)
attacks/     base + payloads + 16 plugins — broken_auth, idor, mass_assignment, sqli, xss, stored_xss,
             path_traversal, authz_matrix, jwt_attacks, graphql, and web_extra (cors, security_headers,
             open_redirect, ssti, command_injection, secrets_exposure)
qa/          crawler · page_model · qa_planner · executor · oracle · auth · flows · responsive · cross_browser
agent/       engine (orchestrator) · llm (Claude Code brain) · planner (security planner) · prompt_safety
detection/   explainer (plain-language LLM pass)
reports/     founder_report
api/         FastAPI server (/analyze, /status/{id})
tests/       test_v2_engine.py — no-LLM/no-browser regression gate (16 detectors, zero FP)
db/          SQLite job + findings store
target_app/  deliberately-vulnerable demo app used by run_demo.py and the test suite
```

> Some original v1 modules remain for reference (`agent/loop.py`, `detection/layer*`, the old
> `execution/crawler.py`, `reports/generator.py`, `extractors/intent.py`); the live engine is
> `agent/engine.py` and the packages above. See [`IMPROVEMENT_PLAN.md`](IMPROVEMENT_PLAN.md) for the
> architecture history.

---

## The demo target app

[`target_app/main.py`](target_app/main.py) is a small FastAPI app with **intentional** bugs — one per
detector — used to verify the engine end-to-end with **zero false positives**: IDOR, broken auth, mass
assignment, a login-gated dashboard with private notes (horizontal + vertical authz + stored XSS),
blind/time-based SQLi, reflected XSS + SSTI, OS command injection, open redirect, CORS misconfiguration,
secrets exposure, a JWT endpoint that doesn't verify signatures, and a GraphQL endpoint with introspection
enabled. `run_demo.py` boots it and runs a full analysis; the regression suite
([`tests/test_v2_engine.py`](tests/test_v2_engine.py)) asserts every planted bug is caught and clean
classes stay clean.

---

## Safety & scope

- **Read-only by default.** Mutating probes (`mass_assignment`, stored-XSS, body-injection) run only with
  `allow_writes` — point those at a disposable/staging environment. DELETE is never injected.
- Requests are **host-allowlisted** on every redirect hop; `spec_url` is fetched within scope and refuses
  non-http sources (no SSRF / arbitrary file read). The QA crawler **skips destructive controls**
  (logout / delete / pay) by default.
- Captured credentials are **redacted** from repros, the returned context, and run-memory.
- Run only against apps you own or are authorized to test.

## Roadmap

CSRF plugin · DOM/stored-XSS confirmation in JSON-rendered SPAs via the browser · deeper GraphQL
field-level authz/IDOR · a true adaptive agenda loop (bug → escalate chaining) · CVSS-style scoring ·
a web UI so non-technical founders can launch a scan without `curl`.
