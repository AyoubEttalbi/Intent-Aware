# Agent Rules — Intent-Aware Autonomous QA Agent

> These rules govern how the AI agent thinks, decides, and acts at every step.
> They exist because a system that violates them will produce noisy, expensive, or dangerous results.

---

## 1. Core Principles

### 1.1 — Intent is the ground truth
The agent must always reason from the behavior contract, not from the HTTP spec alone. A 200 response is not success. A 400 is not always failure. The question is always: **"Does this response match what the app is supposed to do?"**

### 1.2 — Assume nothing is safe
Every endpoint, every parameter, every header is a potential attack surface. The agent does not skip endpoints because they look "read-only" or "harmless." Assumptions are bugs waiting to be found.

### 1.3 — Be goal-directed, not random
The agent must never fuzz randomly. Every test scenario must be tied to a specific assumption it is trying to violate. If a test case cannot be linked to an assumption, it should not be run.

### 1.4 — Fail loudly and specifically
When the agent finds a bug, it must report exactly what failed, which contract was violated, the exact request that caused it, and the exact response that proved it. Vague reports are useless.

### 1.5 — Cost awareness is mandatory
The agent runs LLM calls that cost money. It must never call Layer 3 (LLM-as-judge) unless Layers 1 and 2 were inconclusive. It must enforce a maximum token budget per run and stop cleanly if the budget is reached.

---

## 2. Intent Extraction Rules

### 2.1 — Contracts must be falsifiable
A behavior contract is only valid if it can be proven false by an observable response. "The app should be secure" is not a valid contract. "Unauthenticated requests to /user/{id} must return 401" is.

### 2.2 — Assumptions must be non-obvious
Do not generate assumptions that simply restate the spec. "GET /products returns a list of products" is not an assumption — it's the spec. "A user cannot access another user's order by changing the order ID in the URL" is an assumption worth testing.

### 2.3 — Scope assumptions to observable behavior
Only generate assumptions that can be tested via HTTP requests and response inspection. Do not generate assumptions about internal system state that cannot be observed from the outside.

### 2.4 — Flag ambiguous contracts
If the spec or description is ambiguous about expected behavior, the agent must flag the ambiguity in the report and generate test cases for both possible interpretations.

---

## 3. Scenario Generation Rules

### 3.1 — One assumption per scenario
Each test scenario must target exactly one assumption. Scenarios that try to violate multiple assumptions at once are harder to debug and produce unreliable signals.

### 3.2 — Always include an expected failure type
Every scenario must declare what failure it expects to find: auth bypass, data leak, business logic violation, schema violation, or unexpected state change. This is used by the failure detector to route correctly.

### 3.3 — Prioritize by impact, not by ease
The agent must always test high-risk assumptions first: authentication and authorization bugs before schema bugs, data integrity bugs before UX bugs. The risk ranking must follow this order:
1. Authentication/authorization bypass
2. Data exposure (accessing other users' data)
3. Business logic violations (checkout without payment, etc.)
4. Data integrity (wrong calculations, missing constraints)
5. Schema violations
6. UX/usability issues

### 3.4 — Generate at minimum 5 scenarios per assumption
A single test case proves nothing. Each assumption must be attacked from multiple angles: happy-path violation, boundary values, null/missing values, wrong types, replayed or reordered requests.

### 3.5 — Never generate duplicate scenarios
Before adding a new scenario to the queue, check if an equivalent scenario (same endpoint, same parameter mutation, same expected failure type) already exists. Duplicates waste budget and add noise.

---

## 4. Execution Rules

### 4.1 — Never modify production data
The agent must only run against explicitly designated test environments. If no test environment is specified, it must ask before executing. It must never guess that a live URL is safe to test.

### 4.2 — Respect rate limits
The agent must track request timing per host and enforce a minimum interval between requests. Default: no more than 10 requests per second to any single host. This is configurable.

### 4.3 — Handle auth expiry gracefully
If the agent receives a 401 mid-run due to token expiry, it must re-authenticate and retry the current scenario exactly once. If re-authentication fails, it must log the failure and continue to the next scenario — never block the entire run.

### 4.4 — Record everything
Every request and response must be logged with full headers and body before failure detection runs. Logs must be preserved even for passing tests — a "pass" today may need to be re-examined later.

### 4.5 — Mark explored paths, never revisit them
Once a specific (endpoint, method, parameter set) combination has been executed, it must be marked in the state graph. The agent must not repeat it unless the app's state has changed in a way that makes the path meaningfully different.

### 4.6 — Isolate test cases
Each scenario must start from a known, clean state. The agent must not assume state carries over from a previous test. Create fresh test data per scenario where possible.

---

## 5. Failure Detection Rules

### 5.1 — Layer escalation is mandatory
Detection must always start at Layer 1. Only escalate to Layer 2 if Layer 1 finds no violation. Only escalate to Layer 3 if Layer 2 finds no violation or is inconclusive. Never jump to Layer 3 directly.

### 5.2 — A passing status code is not a passing test
HTTP 200 is not proof the response is correct. The agent must validate the response body against the behavior contract regardless of status code.

### 5.3 — Layer 3 must justify its verdict
When LLM-as-judge flags a bug, it must output: the specific clause of the behavior contract that was violated, a one-sentence explanation of why the response is wrong, and a confidence level (high/medium/low). Low-confidence verdicts must be flagged as "requires human review" in the report — never reported as confirmed bugs.

### 5.4 — False positives are worse than false negatives in early builds
When uncertain, do not report a bug. A developer who sees false positives will stop trusting the system. Mark uncertain cases as "potential issue — review manually" and include the raw request/response so the developer can decide.

### 5.5 — Never classify a bug without a reproduction case
A bug report without a reproduction case is worthless. Every bug in the report must include the exact request (method, URL, headers, body) that triggered it.

---

## 6. Agent Loop Rules

### 6.1 — Always have a plan before acting
The agent must not execute requests speculatively. Before each execution cycle, it must select a target assumption, retrieve or generate scenarios for it, and validate they are runnable. Execution without a plan is forbidden.

### 6.2 — Replan after state changes
If the execution of a scenario reveals a new app state (new endpoint discovered, new parameter accepted, unexpected redirect), the agent must pause, update the state graph, and replan before continuing.

### 6.3 — Backtrack explicitly
If all scenarios for an assumption have been exhausted without finding a bug, the assumption must be marked "tested — no bug found" and the agent moves on. It must never re-test the same assumption with the same scenarios.

### 6.4 — Hard stop on budget exhaustion
If the token budget or time budget is exhausted, the agent must stop cleanly, save all current state, and generate a partial report. It must never exceed the configured budget, even if there are untested assumptions remaining.

### 6.5 — Log every decision with reasoning
Every decision the agent makes — which assumption to target next, why a scenario was skipped, why a failure was escalated to Layer 3 — must be logged with a one-sentence reasoning string. This is not optional. It is what makes the system debuggable.

---

## 7. Reporting Rules

### 7.1 — Severity must follow a defined scale
- **Critical** — Auth bypass, direct data exposure of other users' PII
- **High** — Business logic bypass (e.g., free checkout), privilege escalation
- **Medium** — Data integrity violation, incorrect state transitions
- **Low** — Schema mismatch, missing field, unexpected but harmless response
- **Info** — Behavioral observation that may warrant review, no confirmed bug

### 7.2 — Every report must be reproducible by a human
A developer must be able to read the report, copy the reproduction case, run it with curl or Postman, and see the same result. If they can't, the report is incomplete.

### 7.3 — Never speculate about root cause
The agent reports what it observed, not why it happened. "The endpoint returned 200 for an unauthenticated request, violating the authentication contract" is correct. "The developer forgot to add an auth middleware" is speculation and must never appear in a report.

### 7.4 — Separate confirmed bugs from potential issues
The report must have two distinct sections: confirmed bugs (Layers 1/2 with high confidence, or Layer 3 with high confidence) and potential issues (Layer 3 with medium/low confidence, or edge cases requiring human judgment). Never mix them.
