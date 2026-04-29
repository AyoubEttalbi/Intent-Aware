# Tasks — Intent-Aware Autonomous QA Agent

> Each phase builds on the previous. Do not start a phase until the prior one is validated.
> Status legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

---

## Phase 1 — Foundation & Intent Extraction
> Goal: Given an OpenAPI spec + description, extract a meaningful list of behavior contracts and assumptions.
> Success criterion: Output is readable, accurate, and non-trivial (not just restating the spec).

- [x] Set up project repo with folder structure from README
- [x] Set up Python virtual environment + install core deps (fastapi, uvicorn, anthropic, openapi-spec-validator)
- [x] Build OpenAPI spec parser — load and validate a spec from URL or file
- [x] Write the Intent Extractor prompt (LLM reads spec + description, outputs behavior contracts in JSON)
- [x] Write the Assumption Extractor prompt (LLM outputs list of assumptions the app makes)
- [x] Define JSON schema for contracts and assumptions output
- [ ] Test intent extraction on 3 real public OpenAPI specs (Petstore, GitHub, Stripe sandbox)
- [ ] Evaluate quality: are the contracts meaningful? Are assumptions non-obvious?
- [ ] Refine prompts based on evaluation
- [ ] Write unit tests for the parser and extractor modules

---

## Phase 2 — Scenario Generation
> Goal: For each assumption, generate a set of adversarial test cases ranked by risk.
> Success criterion: Scenarios are creative, targeted, and would actually catch bugs if run.

- [x] Design the Scenario Generator prompt (assumption → list of adversarial test cases)
- [x] Define JSON schema for a test scenario (endpoint, method, headers, body, expected failure type)
- [/] Implement risk ranking logic (security bugs > data integrity > UX issues)
- [x] Build scenario deduplication (avoid generating identical tests)
- [/] Write a scenario validator (check that generated scenarios are structurally valid HTTP requests)
- [x] Test generation on assumptions from Phase 1 outputs
- [x] Evaluate: are scenarios genuinely adversarial or just happy-path variations?
- [x] Refine prompts to increase adversarial creativity
- [ ] Add coverage tracking — which assumptions have been targeted, which haven't
- [ ] Write unit tests for generator and validator

---

## Phase 3 — Execution Engine
> Goal: Run generated test scenarios against a live app and collect raw responses.
> Success criterion: Engine runs all scenarios reliably, handles auth, sessions, and errors gracefully.

- [x] Set up Playwright in Python (playwright install)
- [x] Build HTTP execution layer (for API-only testing, no browser needed yet)
- [x] Handle authentication flows (Bearer token, API key, session cookie)
- [ ] Implement request interceptor using Playwright network hooks
- [x] Build response collector (status, headers, body, latency)
- [x] Handle edge cases: timeouts, connection refused, malformed responses
- [x] Implement retry logic (in LLM layer)
- [x] Build state graph using NetworkX — nodes = app states, edges = actions taken
- [x] Track which paths have been explored, which are new
- [ ] Write integration tests against a local test app (e.g., OWASP Juice Shop or dvwa)

---

## Phase 4 — Failure Detection
> Goal: Determine whether a response represents a real bug, not just an unexpected response.
> Success criterion: Layer 1 catches contract violations with zero false negatives. Layers 2 and 3 catch semantic bugs.

- [x] Build Layer 1 — Contract rule checker
- [x] Build Layer 2 — Behavioral assertion engine
- [x] Build Layer 3 — LLM-as-Judge
- [x] Build failure severity classifier (critical / high / medium / low)
- [x] Write tests to verify detection against known-buggy endpoints

---

## Phase 5 — Agent Loop
> Goal: Wire all components into a self-directing agent that plans, executes, observes, and re-plans.
> Success criterion: Agent runs end-to-end without manual steering. It backtracks and re-plans when stuck.

- [x] Build the main agent loop (see decision loop in README)
- [x] Implement assumption priority queue (highest risk untested assumption first)
- [x] Implement backtracking logic (State Graph)
- [x] Implement re-planning (Logic in loop.py)
- [x] Add loop termination conditions (max assumptions, errors)
- [ ] Add agent memory — persist visited states and results to PostgreSQL
- [x] Test full loop against a target app end-to-end
- [x] Verify agent doesn't repeat already-explored paths
- [x] Verify agent handles auth expiry mid-run gracefully

---

## Phase 6 — API Server & Report Generation
> Goal: Expose the system as a usable API and generate human-readable bug reports.
> Success criterion: A developer can POST a spec and get back a clear, actionable report.

- [x] Build FastAPI server with POST /analyze endpoint
- [x] Add input validation (spec must be valid OpenAPI, description must be non-empty)
- [x] Add async job system (analysis runs in background, client polls for status)
- [x] Build report generator
- [x] Output formats: JSON (always) + Markdown report (optional)
- [x] Add run summary (total assumptions tested, bugs found, coverage %)
- [x] Write API integration tests

---

## Phase 7 — Validation on Real Targets
> Goal: Prove the system finds real bugs, not just synthetic ones.
> Success criterion: At least 3 confirmed bugs found in real open-source apps.

- [ ] Run against OWASP Juice Shop — document all findings
- [ ] Run against OWASP dvwa — document all findings
- [ ] Run against a real open-source API of your choice
- [ ] Compare findings to known vulnerability lists for those apps
- [ ] Measure false positive rate (how many flagged bugs are actually correct?)
- [ ] Measure false negative rate (how many known bugs did we miss?)
- [ ] Document 3 bug case studies for demo/portfolio use

---

## Phase 8 — Hardening & Polish (Post-Validation)
> Only start this phase after Phase 7 confirms real-world usefulness.

- [ ] Add rate limiting to the API server
- [ ] Add structured logging (every decision the agent makes is logged with reasoning)
- [ ] Add observability (track token spend per run, execution time per phase)
- [ ] Write full README with usage examples
- [ ] Docker setup for easy local deployment
- [ ] Add config file support (max budget, risk threshold, excluded endpoints)
- [ ] Security review of the system itself (it's a tool that sends adversarial inputs — handle carefully)
