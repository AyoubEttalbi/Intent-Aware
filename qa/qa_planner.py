"""
qa/qa_planner.py — the QA brain.

Given a structured page snapshot, the LLM (acting as a senior QA engineer that
asks "how can this break?") returns the page's intent and a set of concrete test
cases: happy path, negative, boundary, validation — plus which links to explore
next. The deterministic executor then runs these cases.
"""
from __future__ import annotations

import json

from agent.llm import LLMClient
from agent.prompt_safety import wrap_untrusted, data_framing_rule

QA_SYS = ("You are a meticulous senior QA engineer. Your instinct is always "
          "'how can this break?'. Return ONLY valid JSON." + data_framing_rule())

QA_PROMPT = """App description (may be empty):
{description}

What we already know about this app (shared memory — use it; don't re-test or re-report what's covered):
{memory}

Web page under test (structured snapshot):
{page}

Act like a professional QA engineer testing THIS page. Produce a focused QA plan.

For each FORM, cover:
- happy path  : valid, realistic data
- negative    : invalid email, wrong types, missing required fields
- boundary    : below / at / above min & max length
- validation  : special characters, very long text, empty required fields
For buttons/links: functional checks (does it work, is it broken?).

Return JSON exactly:
{{
  "page_intent": "one sentence describing what this screen is for",
  "test_cases": [
    {{
      "id": 1,
      "kind": "happy|negative|boundary|validation|functional",
      "target": "form:<index>" | "button:<ref>" | "link:<href>",
      "title": "short QA test title",
      "inputs": {{ "<field ref from snapshot>": "<value to type>" }},
      "action": "submit|click|none",
      "expected": "what a CORRECT app should do (e.g. 'reject with a validation error, do not submit')",
      "severity_if_fail": "low|medium|high|critical"
    }}
  ],
  "explore": [ {{ "href": "<url worth visiting next>", "reason": "..." }} ]
}}

Rules:
- FOCUS on functional behaviour, form INPUT VALIDATION, and UI. Do NOT write
  authentication / authorization / IDOR / privilege security tests — a separate
  security engine owns those. (Input-validation tests using special characters
  are fine; frame them as validation, not exploitation.)
- Only generate test cases you can ACTUALLY perform on THIS page. Every test case
  must target a real form index, button, or link from the snapshot and involve a
  concrete interaction (fill/submit/click). Do not propose tests you cannot run here.
- "inputs" keys MUST be the field "ref" values from the snapshot.
- If the shared memory lists known login credentials, USE them for login happy-path tests.
  Never guess credentials and then report the failed login as a bug.
- Realistic data for happy paths; specific & adversarial for negative/boundary.
- 6-12 test cases for this page, prioritising the riskiest.
- In "explore", skip logout/delete/external links.
Return ONLY the JSON object."""


class QAPlanner:
    def __init__(self, llm: LLMClient | None = None):
        self._llm = llm

    @property
    def llm(self) -> LLMClient:
        if self._llm is None:
            self._llm = LLMClient()
        return self._llm

    def plan(self, page_model: dict, description: str = "", memory: str = "") -> dict:
        prompt = QA_PROMPT.format(description=wrap_untrusted(description or "(none)"),
                                  memory=wrap_untrusted(memory or "(nothing yet)"),
                                  page=wrap_untrusted(json.dumps(page_model, indent=2)[:6000]))
        try:
            res = self.llm.ask_json(system_prompt=QA_SYS, user_prompt=prompt)
        except Exception:
            res = None
        if not isinstance(res, dict):
            return {"page_intent": "", "test_cases": [], "explore": []}
        res.setdefault("page_intent", "")
        res.setdefault("test_cases", [])
        res.setdefault("explore", [])
        return res
