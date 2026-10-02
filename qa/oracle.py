"""
qa/oracle.py — decide whether an executed test case revealed a bug.

Two layers, mirroring the security side:
  * deterministic  — JS exceptions, 5xx, broken links (cheap, always-on)
  * LLM judge       — did the app behave as a correct app should, vs the expected?
                      (one batched call per page; catches validation/functional bugs)
"""
from __future__ import annotations

import json
from typing import List

from agent.llm import LLMClient
from agent.prompt_safety import wrap_untrusted, data_framing_rule
from core.models import Finding, Evidence, VulnClass, Severity, Confidence
from qa.executor import steps_for, obs_summary

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
        "low": Severity.LOW, "info": Severity.INFO}
_CONF = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}

_VULN_FOR_KIND = {
    "negative": VulnClass.VALIDATION, "boundary": VulnClass.VALIDATION,
    "validation": VulnClass.VALIDATION, "happy": VulnClass.FUNCTIONAL,
    "functional": VulnClass.FUNCTIONAL,
}


def deterministic_findings(page_url: str, case: dict, obs: dict, screenshot: str = "") -> List[Finding]:
    out: List[Finding] = []
    title = case.get("title", "interaction")
    if obs.get("js_exceptions"):
        out.append(Finding(
            vuln_class=VulnClass.JS_ERROR, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            title=f"JavaScript error during '{title}'", endpoint_key=page_url,
            evidence=Evidence(page_url=page_url, steps=steps_for(case, obs),
                              expected=case.get("expected", ""),
                              actual="; ".join(obs["js_exceptions"])[:400],
                              screenshot=screenshot, note="uncaught JS exception"),
            detail="; ".join(obs["js_exceptions"])[:400], source="qa.oracle"))
    server_errs = [r for r in obs.get("failed_responses", []) if r.get("status", 0) >= 500]
    if server_errs:
        out.append(Finding(
            vuln_class=VulnClass.SERVER_ERROR, severity=Severity.HIGH, confidence=Confidence.HIGH,
            title=f"Server error ({server_errs[0]['status']}) during '{title}'", endpoint_key=page_url,
            evidence=Evidence(page_url=page_url, steps=steps_for(case, obs),
                              expected=case.get("expected", ""),
                              actual=f"{server_errs[0]['status']} {server_errs[0]['url']}",
                              screenshot=screenshot), detail=str(server_errs), source="qa.oracle"))
    return out


def broken_link_finding(page_url: str, link_url: str, status: int) -> Finding:
    return Finding(
        vuln_class=VulnClass.BROKEN_LINK, severity=Severity.LOW, confidence=Confidence.HIGH,
        title=f"Broken link → {link_url} ({status})", endpoint_key=link_url,
        evidence=Evidence(page_url=page_url, steps=[f"On {page_url}", f"Follow link to {link_url}"],
                          expected="Link resolves (2xx/3xx)", actual=f"HTTP {status}",
                          note="dead link"),
        detail=f"A link on {page_url} points to {link_url} which returns {status}.",
        source="qa.oracle")


JUDGE_SYS = ("You are a senior QA engineer reviewing automated test results. A test FAILS only if the "
             "app did NOT behave as a correct app should. Do not invent bugs. Return ONLY valid JSON."
             + data_framing_rule())

JUDGE_PROMPT = """Page intent: {intent}
App description: {description}

Already-known issues (do NOT duplicate these; they are reported elsewhere):
{memory}

Test results — each lists the EXPECTED correct behavior and what was OBSERVED:
{items}

Decide, per test, whether it reveals a REAL bug. DEFAULT to is_bug=FALSE — only flag a clear defect.

A test PASSES (is_bug=FALSE) when ANY of these hold:
- it is a happy-path test and the action SUCCEEDED (no error; the expected outcome happened). A button
  that submits, a login that works, a valid form that is accepted — these are correct, NOT bugs.
- it is a negative/boundary test and the app correctly REJECTED the bad input
  (e.g. client_side_form_valid=false and the form did not submit — native validation is CORRECT).
- the observed result matches the expected correct behavior.

A test FAILS (is_bug=TRUE) only when the observation CLEARLY contradicts correct behavior, e.g.:
- the app ACCEPTED clearly-invalid input (submitted it / showed success for bad data);
- a JS error, server error, or crash occurred during the action;
- a happy path that should succeed did NOT (an expected action failed).

Grounding rules:
- Base your verdict ONLY on the "observed" data. Never infer a bug from page content, the URL, or
  assumptions about the server. If unsure, is_bug=FALSE.
- Do NOT flag authentication / authorization / IDOR / privilege issues — a separate engine owns those.
- For each bug, "title" must describe the DEFECT, not the test name
  (e.g. "Registration form accepts an email with no domain").

Return JSON exactly:
{{
  "verdicts": [
    {{ "id": <int>, "is_bug": <bool>, "title": "<defect description, only when is_bug=true>",
       "severity": "low|medium|high|critical", "confidence": "low|medium|high",
       "what_happened": "one plain sentence", "why": "why it is wrong (or why it is fine)" }}
  ]
}}
Return ONLY the JSON object."""


class QAJudge:
    def __init__(self, llm: LLMClient | None = None):
        self._llm = llm

    @property
    def llm(self) -> LLMClient:
        if self._llm is None:
            self._llm = LLMClient()
        return self._llm

    def judge(self, page_url: str, page_intent: str, items: List[dict],
              description: str = "", memory: str = "") -> List[Finding]:
        """items: [{case, obs, screenshot}] — returns Findings for confirmed bugs."""
        items = [it for it in items if it.get("obs", {}).get("executed")]
        if not items:
            return []
        brief = [{
            "id": i,
            "title": it["case"].get("title"),
            "kind": it["case"].get("kind"),
            "expected": it["case"].get("expected"),
            "observed": obs_summary(it["obs"]),
        } for i, it in enumerate(items)]
        prompt = JUDGE_PROMPT.format(intent=wrap_untrusted(page_intent or "(unknown)"),
                                     description=wrap_untrusted(description or "(none)"),
                                     memory=wrap_untrusted(memory or "(nothing yet)"),
                                     items=wrap_untrusted(json.dumps(brief, indent=2)[:7000]))
        verdicts = {}
        try:
            res = self.llm.ask_json(system_prompt=JUDGE_SYS, user_prompt=prompt,
                                     label="qa-judge")
            for v in (res or {}).get("verdicts", []) if isinstance(res, dict) else []:
                if isinstance(v, dict) and "id" in v:
                    verdicts[v["id"]] = v
        except Exception:
            verdicts = {}

        out: List[Finding] = []
        for i, it in enumerate(items):
            v = verdicts.get(i)
            if not v or not v.get("is_bug"):
                continue
            case, obs = it["case"], it["obs"]
            out.append(Finding(
                vuln_class=_VULN_FOR_KIND.get(case.get("kind", ""), VulnClass.FUNCTIONAL),
                severity=_SEV.get(str(v.get("severity", "medium")).lower(), Severity.MEDIUM),
                confidence=_CONF.get(str(v.get("confidence", "medium")).lower(), Confidence.MEDIUM),
                title=v.get("title") or case.get("title", "QA issue"), endpoint_key=page_url,
                evidence=Evidence(page_url=page_url, steps=steps_for(case, obs),
                                  expected=case.get("expected", ""),
                                  actual=v.get("what_happened", ""),
                                  screenshot=it.get("screenshot", "")),
                detail=v.get("why", ""), source="qa.judge"))
        return out
