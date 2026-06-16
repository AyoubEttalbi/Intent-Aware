"""
agent/planner.py — the LLM "brain" that steers the deterministic attack matrix.

One bounded LLM call reads the whole discovered surface + the app description and
returns, per endpoint: realistic sample values (so probes hit real data, not 404s),
a test priority, and which vuln classes look most relevant. Deterministic plugins
still own the payloads + oracles; the brain only decides *where to aim and in what
order*. Degrades gracefully to heuristic defaults if the LLM is unavailable.
"""
from __future__ import annotations

import json
from typing import List

from agent.llm import LLMClient
from agent.prompt_safety import wrap_untrusted, data_framing_rule

PLANNER_SYS = ("You are a senior application-security engineer planning a black-box test. "
               "Return ONLY valid JSON." + data_framing_rule())

PLANNER_PROMPT = """App description (may be empty):
{description}

What we already know about this app (shared memory from the UI crawl):
{memory}

Discovered API endpoints:
{endpoints}

For EACH endpoint, decide how to test it. Return JSON exactly as:
{{
  "endpoints": [
    {{
      "key": "<the endpoint key, copied verbatim>",
      "sample_values": {{ "<path_or_query_param>": "<a value that returns REAL data, e.g. an existing id>" }},
      "priority": "high" | "medium" | "low",
      "focus": ["idor","broken_auth","mass_assignment","sqli","xss","path_traversal"]
    }}
  ]
}}

Guidance:
- sample_values: pick values likely to reference an EXISTING resource (e.g. "1" for an id) so tests exercise real responses.
- priority "high" for endpoints handling user data, auth, money, or admin actions.
- focus: the 1-3 vuln classes most worth trying first for that endpoint. Be specific; do not invent classes.
Return ONLY the JSON object."""


class Planner:
    def __init__(self, model=None, effort=None):
        self._llm = None
        self._model = model
        self._effort = effort

    @property
    def llm(self) -> LLMClient:
        if self._llm is None:
            self._llm = LLMClient(model=self._model, effort=self._effort)
        return self._llm

    def plan(self, description: str, endpoints: List, memory: str = "") -> dict:
        if not endpoints:
            return {}
        brief = [{
            "key": e.key,
            "method": e.method,
            "path": e.path_template,
            "params": [{"name": p.get("name"), "in": p.get("in"), "type": p.get("type")} for p in e.params],
            "auth_required": e.auth_required,
            "summary": e.summary,
        } for e in endpoints]
        prompt = PLANNER_PROMPT.format(description=wrap_untrusted(description or "(none)"),
                                       memory=wrap_untrusted(memory or "(nothing yet)"),
                                       endpoints=wrap_untrusted(json.dumps(brief, indent=2)))
        try:
            res = self.llm.ask_json(system_prompt=PLANNER_SYS, user_prompt=prompt)
        except Exception:
            res = None

        out: dict = {}
        items = (res or {}).get("endpoints", []) if isinstance(res, dict) else []
        for it in items or []:
            if not isinstance(it, dict):
                continue
            key = it.get("key")
            if not key:
                continue
            out[key] = {
                "sample_values": it.get("sample_values", {}) or {},
                "priority": it.get("priority", "medium"),
                "focus": it.get("focus", []) or [],
            }
        return out
