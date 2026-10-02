"""
detection/explainer.py — turns confirmed technical findings into plain language a
non-technical founder can act on. One bounded LLM call enriches all findings with:
"what we found / why it matters / how to fix". Falls back to the technical detail
if the LLM is unavailable, so the report is never blank.
"""
from __future__ import annotations

import json
from typing import List

from agent.llm import LLMClient
from agent.prompt_safety import wrap_untrusted, data_framing_rule
from core.models import Finding

EXPLAINER_SYS = ("You explain security findings to a non-technical startup founder. "
                 "Be concrete, calm, and jargon-free. Return ONLY valid JSON." + data_framing_rule())

EXPLAINER_PROMPT = """App description (may be empty):
{description}

Confirmed findings (already verified by exploitation — do NOT second-guess them):
{findings}

For each finding, write founder-friendly text. Return JSON exactly as:
{{
  "findings": [
    {{
      "index": <the integer index>,
      "explanation": "1-2 plain sentences: what's wrong, no jargon.",
      "impact": "1 sentence: what a real attacker could do / who is harmed.",
      "fix": "1-2 concrete sentences a developer can act on."
    }}
  ]
}}
Return ONLY the JSON object."""


class Explainer:
    def __init__(self, model=None, effort=None, log=None):
        self._llm = None
        self._model = model
        self._effort = effort
        self._log = log

    @property
    def llm(self) -> LLMClient:
        if self._llm is None:
            self._llm = LLMClient(model=self._model, effort=self._effort, log=self._log)
        return self._llm

    def enrich(self, findings: List[Finding], description: str = "") -> None:
        if not findings:
            return
        brief = [{
            "index": i,
            "vuln_class": f.vuln_class.value,
            "severity": f.severity.value,
            "title": f.title,
            "endpoint": f.endpoint_key,
            "detail": f.detail,
        } for i, f in enumerate(findings)]
        prompt = EXPLAINER_PROMPT.format(description=wrap_untrusted(description or "(none)"),
                                         findings=wrap_untrusted(json.dumps(brief, indent=2)))
        by_idx = {}
        try:
            res = self.llm.ask_json(system_prompt=EXPLAINER_SYS, user_prompt=prompt,
                                     label="explainer")
            for it in (res or {}).get("findings", []) if isinstance(res, dict) else []:
                if isinstance(it, dict) and "index" in it:
                    by_idx[it["index"]] = it
        except Exception:
            by_idx = {}

        for i, f in enumerate(findings):
            it = by_idx.get(i, {})
            f.explanation = (it.get("explanation") or f.detail).strip()
            f.impact = (it.get("impact") or "").strip()
            f.fix = (it.get("fix") or "").strip()
