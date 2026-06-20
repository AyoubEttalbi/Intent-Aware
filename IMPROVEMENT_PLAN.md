# Intent-Aware — Improvement Plan & Architecture v2

> Goal: turn Intent-Aware into an **autonomous QA + security tester for non-technical builders**.
> Input = a live app URL + an optional description/spec. The LLM "brain" (local Claude Code CLI,
> wired in `agent/llm.py` as provider `claude_code`) drives everything: it crawls *everything*,
> behaves like a real human QA, fills every form with realistic data, attacks the UI + API with the
> full vulnerability matrix (SQLi, XSS, IDOR, auth bypass, privilege escalation, mass assignment, …),
> tests auth + roles, and explains findings in plain language a founder can act on.

---

## ✅ Status (delivered)

Phases **0–6 are delivered and verified** against `target_app`; **Phase 7 is partial**. The engine now
catches every planted bug — 3 API criticals (IDOR, broken auth, mass assignment) + stored XSS +
blind/time-based SQLi + **vertical & horizontal authorization** — with **zero false positives**, behind
a login and across roles.

### v2.1 flexibility hardening (delivered — see `CLAUDE-IMPROVEMENTS.md`)
A second pass made the engine flexible enough for arbitrary, non-demo apps and safe for third-party
targets. Highlights, all regression-tested in `tests/test_v2_engine.py` (16 detectors, zero FP):
- **Safety:** read-only by default (write probes need `allow_writes`, DELETE never injected); `spec_url`
  SSRF + local-file-read closed; scope-checked redirect following; credential redaction; LLM-prompt
  injection sentinels; honest **LOW-COVERAGE** gate so a clean grade can't hide "couldn't test".
- **Discovery:** optional `spec_url` with auto-probe of well-known paths; YAML + Swagger-2.0 (`basePath`,
  `in: body`); first-class shadow endpoints (params/body/content-type/auth inferred, incl. form POSTs);
  GraphQL detection + introspection check; multi-host scope.
- **Auth:** declarative adapters (`bearer`/`api_key`/`header`/`session`/`token_exchange`) that resolve
  **without a browser**; behavioural auth-required + scheme-correct invalid-credential probes;
  auto-discovery of `owned_resource_ids` and real foreign ids (UUID/slug-safe IDOR/authz).
- **Coverage:** new detectors — JWT (`alg=none`/stripped-sig), CORS, open redirect, SSTI, command
  injection (time-based), secrets/PII exposure, security headers, GraphQL introspection.
- **Brain:** planner `focus` consumed; canonical-key lookup; temperature 0; per-run request **and**
  LLM-call budgets.

**Delivered beyond the original plan:** multi-role authorization testing (`attacks/authz_matrix.py`),
authenticated identities feeding the attack matrix, stored-XSS verification, blind/time-based SQLi, a
shared run-memory layer (`core/context.py`), form-encoded request support, and performance work
(concurrent execution, in-run LLM cache, hardened LLM JSON parsing). See [README.md](README.md) and
[CLAUDE.md](CLAUDE.md).

---

## 1. Diagnosis — the original v1 problem (from the 3-angle audit)

The system is a **linear pipeline described as an agent**. The genuinely agentic parts were stubbed or
imported-but-unused and never connected. Concretely:

| # | Problem | Evidence |
|---|---|---|
| D1 | **No agent loop.** `run()` is a nested `for assumption in assumptions[:2]`. Results never feed back into decisions. | `agent/loop.py:78-126`, `max_assumptions=2` default |
| D2 | **Planner is empty, state graph is dead.** `planner.py` = 1 empty line, 0 refs. `StateGraph.DiGraph` never populated; only a flat `set()` is used. | `agent/planner.py`, `agent/state_graph.py` |
| D3 | **LLM used as 5 disconnected one-shot prompts**, never as a controller that decides what to test next. | intent/assumptions/scenarios/crawler-fill/judge |
| D4 | **No identity model.** All requests are one anonymous session. The runner can *add* auth but can **never strip it** → broken-auth is undetectable. | `execution/runner.py:20-42` |
| D5 | **No real attack payloads.** "Attacks" are LLM-improvised JSON. No SQLi/XSS/traversal/SSRF corpora; ~2 of ~13 vuln classes covered, incidentally. | `generators/scenarios.py` |
| D6 | **Oracles check status, not effect.** "Got 200" ≠ "exploited". No differential baseline, no marker reflection, no time-based test. | `detection/layer1_contract.py`, `layer2_behavioral.py` |
| D7 | **Confidence-promotion bug.** Judge `confidence` is dropped when promoting a finding → low-confidence verdicts masquerade as **confirmed CRITICALs**. | `agent/loop.py:106-111` + `reports/generator.py` |
| D8 | **Evidence not captured.** Only status+latency stored; request headers + response body dropped → reports are **not reproducible** (violates `rules.md §4.4/§5.5`). | `agent/loop.py:113-120` |
| D9 | **Crawler is a 1-page DFS toy.** No auth, no SPA routing, no multi-step flows, no modal/scroll/iframe/upload, no safety guards (clicks logout/delete), shadow-spec = string blob. | `execution/crawler.py` |
| D10 | **Report inflates noise.** UI 404s / JS errors counted as MEDIUM "confirmed bugs"; flat `100 − 15×count` health score. | `agent/loop.py:50-55`, `reports/generator.py` |

**Why the last run missed broken-auth on `GET /orders/{id}`:** the endpoint *requires presence* of an
`Authorization` header but not validity. To catch it you must send the request with **no** auth and
still get 200. The runner has no negative-auth primitive (D4) and no per-class oracle (D6), so the bug
is structurally invisible. IDOR + mass-assignment landed only because they're exploitable in a single
unauthenticated request with a visible body tell.

**Good news:** `rules.md` and `deepseek-improvements.md` already specify the correct design (personas,
contract-based adversarial generation, stateful sequences, semantic detection, layered escalation,
confirmed-vs-potential separation). This plan *implements the vision the repo already documents*.

---

## 2. Target architecture v2

```
Input: URL + optional description/spec
        │
        ▼
┌──────────────────────┐   OpenAPI fetch (/openapi.json,/swagger.json,/docs) +
│  Discovery           │   LLM-guided browser crawl (auth-aware, SPA, flows)
│  → unified Surface   │   → structured Endpoints (method/path/params/body/auth/responses)
└──────────────────────┘   + UI map + shadow-spec DIFF vs declared spec
        │
        ▼
┌──────────────────────┐   anon · userA · userB · admin
│  Identities          │   (login flows, token/cookie capture, owned-resource map)
└──────────────────────┘
        │
        ▼
┌──────────────────────┐   reads Surface + State + Findings + Frontier + Budget
│  Planner (LLM BRAIN) │   → next batch of Actions (endpoint × attack-class × identity)
│                      │   → replans on discovery, chains follow-ups (bug → escalate)
└──────────────────────┘
        │
        ▼
┌──────────────────────┐   HTTP runner (identity-aware, strip-auth) +
│  Executors           │   Browser driver (forms/clicks/flows) — FULL evidence captured
└──────────────────────┘
        │
        ▼
┌──────────────────────┐   per vuln-class: payload corpus + EFFECT oracle
│  Attack plugins      │   idor · broken_auth · mass_assignment · sqli · xss ·
│                      │   path_traversal · ssrf · authz_matrix · csrf …
└──────────────────────┘
        │
        ▼
┌──────────────────────┐   L1 contract (real jsonschema) → L2 behavioral (cross-identity diff)
│  Detection           │   → L3 LLM judge (scoped, ambiguous-only) → plain-language explainer
└──────────────────────┘
        │
        ▼
┌──────────────────────┐   nodes=states, edges=actions; frontier=untested; coverage %;
│  State + Coverage     │   persisted to qa_agent.db (resume across runs)
└──────────────────────┘
        │
        ▼
┌──────────────────────┐   founder-grade: exec summary + A–F grade, grouped findings,
│  Report              │   repro curl, impact, fix; confirmed vs potential (correct gating)
└──────────────────────┘
```

**Design principles**
- **Brain for creativity, deterministic plugins for exploit + verification.** The LLM picks targets,
  maps params, generates realistic data, and writes plain-language explanations. Payloads and
  effect-oracles are deterministic so findings are reproducible and trustworthy.
- **One source of truth.** A shared `core/models.py` (Endpoint, Identity, Request, Response, Action,
  Finding, Evidence). No more string-blob hand-offs.
- **Everything is bounded.** A run budget (max actions / wall-clock / LLM calls) replaces
  `max_assumptions=2`. Scope = target host allowlist; destructive actions gated.
- **Safe by default.** Non-destructive mode (no delete/pay/send/logout) unless explicitly allowed;
  host-allowlisted requests; native-dialog handling.

---

## 3. Phased plan (each phase ships verifiable value)

### Phase 0 — Correctness fixes *(small, high value)* — ✅ DELIVERED
Fix the bugs that make today's output wrong, so every later phase builds on truth.
- Preserve judge `confidence` end-to-end; route low/medium → "potential issues" (fix D7).
- Capture full request headers + response body as `Evidence`; render repro `curl` (fix D8).
- Pass the judge only the **relevant** contract, not `all_contracts` (cost + accuracy).
- Demote UI crawl 404s/JS errors out of "Confirmed Bugs" → "UI/QA observations" (fix D10).
- Enforce **target-host allowlist** in the runner (don't let a poisoned spec aim us at a third party).

### Phase 1 — Identity model + negative-auth primitive *(unlocks auth/authz/IDOR)* — ✅ DELIVERED
- `core/identity.py`: `Identity{name, role, auth headers/cookies, owned_resource_ids}`.
- Refactor `execution/runner.py` → `execute(Request)` that applies an identity and supports
  `strip_auth=True` (guarantees **no** `Authorization`). **This alone makes the `/orders` bug catchable.**
- Config: identities supplied via request payload / config file (anon always present).

### Phase 2 — Unified Surface + full discovery *("test everything")* — ✅ DELIVERED
- `core/surface.py`: structured `Endpoint` + `Surface` (merge spec ∪ shadow, templated paths).
- Fetch OpenAPI from `/openapi.json`, `/swagger.json`, `/docs`; parse **all** paths/methods/params/schemas.
- Crawler emits structured `EndpointObservation` (method, templated path, headers, body, response) and a
  **diff** vs the declared spec (undocumented endpoints = a finding class).
- Seed every endpoint as a frontier target (replace the `loop.py:62-65` text append).

### Phase 3 — Attack-plugin architecture + corpora + oracles *(real attacks)* — ✅ DELIVERED (8 plugins, effect oracles)
- `attacks/base.py`: `AttackPlugin{ applies_to(endpoint, surface), generate(endpoint, identities) -> [Probe], verify(probe, responses, baseline) -> Finding|None }` + a registry.
- `attacks/payloads/`: curated corpora (SQLi, XSS, traversal, SSRF hosts, mass-assignment fields).
- Plugins (each owns an **effect oracle**):
  - `broken_auth` — strip auth → 2xx with protected data ⇒ bug (catches `/orders`).
  - `idor` — cross-identity / id-enumeration → A receives B's owned resource ⇒ bug (catches `/users`).
  - `mass_assignment` — inject privileged fields → read back → persisted ⇒ bug (catches `PUT /users`).
  - `sqli` — error-signature + boolean/time-based differential.
  - `xss` — unique marker → reflected/stored re-read.
  - `path_traversal` — `../` corpus + file-signature oracle.
  - `authz_matrix` — {identities} × {actions} grid; role can only do its policy.
- LLM's role shrinks to *target/param selection + realistic data + novel-payload proposals* (validated by the same oracle).

### Phase 4 — Agentic loop + LLM planner *(the brain drives)* — ✅ DELIVERED (LLM planner + explainer; full replanning loop still light)
- Implement `agent/planner.py`: `next_actions(state, surface, findings, frontier, budget) -> [Action]` with reasoning.
- Replace the nested `for` with a `while frontier and budget` agenda loop; on a confirmed bug, ask the
  planner for follow-ups (bug → IDOR → privesc chain).
- Make `StateGraph` real: nodes = states (url/role/screen-intent), edges = actions; expose
  `frontier()` + `coverage()`; log every decision with one-line reasoning (`rules.md §6.5`).

### Phase 5 — LLM-guided exhaustive crawler *("crawl everything like a real QA")* — ✅ DELIVERED (auth, flows, responsive, cross-browser)
- Auth-aware browser crawling: drive login once, persist `storage_state`, reuse; re-auth on logout.
- LLM chooses next action from a page snapshot; re-discover elements after every interaction
  (modals, dropdowns, tabs, infinite scroll); pierce iframes + shadow DOM; handle file uploads.
- Frontier queue (BFS) instead of reload-DFS; path-templated dedup; multi-step flow traversal with
  LLM "is this flow complete?" judgment.
- **Safety:** classify controls, skip/quarantine destructive verbs (logout/delete/pay/send) unless
  allowed; register native-dialog handler; `max_pages`/`max_actions`/throttle; `dry_run` mode.

### Phase 6 — Founder-grade report + coverage — ✅ DELIVERED (A–F grade, plain language, repro, screenshots, roles tested)
- Severity = exploitability × impact × blast-radius; overall **A–F grade**; demote cosmetic noise.
- Group related findings ("auth missing on all `/users/*`"); per-finding repro `curl`; impact +
  fix suggestion; uniform **plain-language** explainer ("what we found / how a hacker abuses it /
  impact / how to fix"); correct confirmed-vs-potential split.
- Coverage report: endpoint × method × identity × attack-class matrix; % surface tested.

### Phase 7 — Robustness / persistence / scale — 🔶 PARTIAL (concurrency, in-run LLM cache, hardened JSON parsing, `resume_context` done; full DB-table persistence + structured logging pending)
- Persist surface + state + findings to `qa_agent.db`; resume after crash; concurrency over the frontier.
- Typed exceptions (kill silent `except:`), structured JSON logs, token/time observability, config file
  (budget, risk threshold, excluded endpoints, identities, scope).

---

## 4. Bug-coverage matrix (acceptance for the demo target_app) — ✅ ALL CAUGHT

| Planted bug | Endpoint | Status | By |
|---|---|---|---|
| IDOR | `GET /users/{id}` | ✅ effect oracle | `attacks/idor` |
| Mass assignment / privesc | `PUT /users/{id}` | ✅ | `attacks/mass_assignment` |
| Broken auth | `GET /orders/{id}` | ✅ negative-auth primitive | `attacks/broken_auth` |
| Vertical privilege escalation | `GET /admin/users` | ✅ multi-role | `attacks/authz_matrix` |
| Horizontal (cross-user) access | `GET /notes/{id}` | ✅ multi-role, behind login | `attacks/authz_matrix` |
| Stored XSS | `POST /notes` → `GET /notes` | ✅ write→read-back | `attacks/stored_xss` |
| Blind / time-based SQLi | `GET /search?q` | ✅ delay reproduced | `attacks/sqli` |

Acceptance (met): running against `target_app` finds **all of the above** with reproducible evidence
(curl / steps + screenshots), correct severity/confidence, roles tested in the coverage section, and
**zero false positives** — verified including across `anon` + `admin` + `user` identities.

---

## 5. Open questions for real (non-demo) targets
These don't block the demo but shape real-app runs (sensible safe defaults used until answered):
- **Credentials for auth-gated crawling** — username/password for the LLM to drive login, or a
  pre-baked `storage_state`/cookie? Multiple roles?
- **Target = production or disposable test instance?** Decides whether destructive actions are
  dry-run-only or hard-forbidden (default: forbidden).
- **Scope bounds** — max pages/time, subdomains in/out, path allow/deny (default: same-host, bounded).

---

## 6. Sequencing
Phases 0→1→2→3→4 form the **security engine** (catches the full API vuln matrix incl. all 3 planted
bugs) and are the priority. Phase 5 (exhaustive UI crawl) and 6 (report polish) make it
"everything + founder-grade". Phase 7 makes it production-grade. Implementation proceeds in this order,
verifying against `target_app` after each meaningful increment.
