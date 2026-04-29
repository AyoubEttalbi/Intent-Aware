# Intent-Aware Autonomous QA Agent

> A system that understands what your app is supposed to do — then actively tries to break it like a real user or attacker.

---

## The Problem

Current testing tools follow scripts, require manual test writing, don't understand intent, and don't explore unexpected paths. They test what you *told* them to test.

Real users click random things, misuse flows, and break assumptions. Real attackers probe boundaries you didn't think to defend.

**This system closes that gap.**

---

## What It Does

1. **Understands app functionality** — reads your API spec + description and builds a behavior contract (what the app is *supposed* to do)
2. **Builds a behavior model** — maps all states, flows, and assumptions
3. **Generates adversarial test scenarios** — targets each assumption with smart, creative violations
4. **Explores edge cases autonomously** — uses a goal-directed agent loop, not random fuzzing
5. **Detects semantic failures** — not just HTTP 500s, but cases where the response is *wrong* even if it looks fine

---

## Architecture

```
Input: API Spec (OpenAPI) + App Description
              │
              ▼
    ┌─────────────────────┐
    │   Intent Extractor  │  ← LLM reads spec + description
    │   (LLM)             │    outputs: behavior contracts,
    └─────────────────────┘    assumption list
              │
              ▼
    ┌─────────────────────┐
    │  Scenario Generator │  ← LLM generates adversarial
    │  (LLM)              │    test cases per assumption,
    └─────────────────────┘    ranked by risk
              │
              ▼
    ┌─────────────────────┐
    │  Execution Engine   │  ← Playwright (browser/API)
    │  (Playwright)        │    runs tests against live app
    └─────────────────────┘    tracks state as a graph
              │
              ▼
    ┌─────────────────────────────────────────┐
    │           Failure Detector              │
    │                                         │
    │  Layer 1: Contract rules (fast, cheap)  │
    │  Layer 2: Behavioral assertions         │
    │  Layer 3: LLM-as-judge (flagged cases)  │
    └─────────────────────────────────────────┘
              │
              ▼
    ┌─────────────────────┐
    │   Report Generator  │  ← Bug found, severity,
    └─────────────────────┘    reproduction steps, why it's a bug
```

The agent loop is **not linear**. It explores, hits dead ends, backtracks, re-plans. The graph engine tracks visited states so it doesn't repeat paths.

---

## Tech Stack

### Core
| Layer | Technology | Why |
|---|---|---|
| Language | Python | Best AI/automation ecosystem |
| API Server | FastAPI | Fast, async, clean |
| LLM | Claude / GPT-4 class via API | No training needed at v1 |
| Browser Automation | Playwright | Handles modern JS apps, headless, network hooks |
| Agent Loop | Custom (no LangChain) | Full control over decision logic |

### Storage
| Purpose | Technology |
|---|---|
| Main DB | PostgreSQL |
| State graph | NetworkX (v1), Neo4j (later) |
| Vector memory | pgvector (v1), Qdrant (later) |

### What We Don't Add Until Needed
- Redis / Celery — only when running parallel test suites at scale
- Custom model training — only after collecting real bug classification data
- Neo4j — only when graph queries become a bottleneck

---

## The Agent Decision Loop

```
While unexplored_assumptions > 0:
    1. Pick highest-risk untested assumption
    2. Generate adversarial scenarios for it
    3. Execute scenarios against the app
    4. Collect responses
    5. Run failure detection (Layer 1 → 2 → 3)
    6. If bug found → log with full context
    7. Update state graph (mark paths explored)
    8. Re-plan based on new discovered states
```

This is what separates this system from a glorified script runner.

---

## Failure Detection Layers

**Layer 1 — Contract Violations** (fast, cheap, always runs)
- Expected 401, got 200 → auth bypass
- Response schema doesn't match spec
- Required field missing from response

**Layer 2 — Behavioral Assertions** (derived from intent model)
- Cart total ≠ sum of items
- User A can read User B's resource
- Action succeeded in wrong order (e.g., checkout before login)

**Layer 3 — LLM-as-Judge** (slow, expensive, only for ambiguous flagged cases)
- Request + response + intent contract → LLM asked: "Is this correct behavior?"
- Catches subtle semantic failures that rules miss

---

## v1 Scope (What We Actually Build First)

Input: OpenAPI spec + one paragraph description of the app
Output: List of semantic bugs with reproduction steps

**Out of scope for v1:**
- UI/browser testing (API-only first)
- Security payload fuzzing (SQLi, XSS) — Layer 1/2 only
- Multi-user session simulation
- Custom model training

---

## Project Structure

```
qa-agent/
├── api/                  # FastAPI server
│   ├── main.py
│   └── routes/
├── agent/                # Core agent loop
│   ├── loop.py
│   ├── planner.py
│   └── state_graph.py
├── extractors/           # Intent + assumption extraction
│   ├── intent.py
│   └── assumptions.py
├── generators/           # Scenario generation
│   └── scenarios.py
├── execution/            # Playwright runner
│   └── runner.py
├── detection/            # Failure detection layers
│   ├── layer1_contract.py
│   ├── layer2_behavioral.py
│   └── layer3_llm_judge.py
├── reports/              # Report generation
│   └── generator.py
├── db/                   # DB models + migrations
└── tests/                # Meta-tests for the system itself
```

---

## Getting Started

```bash
# Install dependencies
pip install fastapi uvicorn playwright anthropic psycopg2 networkx openapi-spec-validator
playwright install

# Set environment
cp .env.example .env
# Add your LLM API key

# Run
uvicorn api.main:app --reload
```

Then POST to `/analyze` with:
```json
{
  "spec_url": "https://yourapp.com/openapi.json",
  "description": "An e-commerce API where authenticated users can browse products, add to cart, and checkout. Users should never see other users' data."
}
```

---

## What Makes This Different

| Feature | Scripted Tests | Fuzzer | This System |
|---|---|---|---|
| Understands intent | ❌ | ❌ | ✅ |
| Finds semantic bugs | ❌ | ❌ | ✅ |
| Explores unexpected paths | ❌ | Randomly | ✅ Goal-directed |
| Explains why something is a bug | ❌ | ❌ | ✅ |
| Requires manual test writing | ✅ | ❌ | ❌ |
