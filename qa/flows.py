"""
qa/flows.py — multi-step end-to-end journey testing.

The LLM proposes realistic user journeys (ordered steps) from the discovered site
map; the executor runs each as ONE stateful browser session and verifies the final
outcome (assert_text). This catches bugs that only appear across steps — state not
persisted, broken hand-offs, a "success" that didn't actually happen.
"""
from __future__ import annotations

import json

from agent.llm import LLMClient
from core.models import Finding, Evidence, VulnClass, Severity, Confidence

FLOW_SYS = "You are a senior QA engineer designing end-to-end user journeys. Return ONLY valid JSON."

FLOW_PROMPT = """App description:
{description}

What we know (shared memory):
{memory}

Site map discovered while crawling (pages, their intent, and their forms with field selectors):
{sitemap}

Design 1-3 realistic END-TO-END user journeys that exercise multi-step flows WITH STATE
(e.g. create something then verify it appears; a wizard with several steps; register→login→act).
Use ONLY the URLs and selectors present in the site map.

Return JSON exactly:
{{
  "journeys": [
    {{
      "name": "short journey name",
      "goal": "what the user is trying to accomplish",
      "steps": [
        {{"action": "goto", "url": "<url from sitemap>"}},
        {{"action": "fill", "selector": "<css selector from sitemap>", "value": "<realistic value>"}},
        {{"action": "click", "selector": "<submit selector from sitemap>"}},
        {{"action": "goto", "url": "<url where the result should appear>"}},
        {{"action": "assert_text", "value": "<exact text that must appear if the flow worked>"}}
      ]
    }}
  ]
}}
Rules:
- The LAST step of each journey MUST be an assert_text proving success — its value must match
  something you typed earlier (e.g. the note text you created).
- 3-6 steps per journey. Use ONLY selectors/urls from the site map.
Return ONLY the JSON object."""


class FlowPlanner:
    def __init__(self, llm: LLMClient | None = None):
        self._llm = llm

    @property
    def llm(self) -> LLMClient:
        if self._llm is None:
            self._llm = LLMClient()
        return self._llm

    def plan(self, description: str, sitemap: list, memory: str = "") -> list:
        if not sitemap:
            return []
        prompt = FLOW_PROMPT.format(description=description or "(none)", memory=memory or "(nothing)",
                                    sitemap=json.dumps(sitemap, indent=2)[:5000])
        try:
            res = self.llm.ask_json(system_prompt=FLOW_SYS, user_prompt=prompt)
        except Exception:
            res = None
        return (res or {}).get("journeys", []) if isinstance(res, dict) else []


async def run_journey(context, journey: dict, base_url: str, log=print) -> Finding | None:
    """Execute a journey in a stateful page. Returns a Finding if it breaks, else None."""
    page = await context.new_page()
    name = journey.get("name", "journey")
    trail = []
    try:
        for step in journey.get("steps", []):
            act = step.get("action")
            if act == "goto":
                url = step.get("url") or base_url
                await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                trail.append(f"Go to {url}")
            elif act == "fill":
                await page.fill(step["selector"], str(step.get("value", "")), timeout=5000)
                trail.append(f"Type {step.get('value', '')!r} into {step['selector']}")
            elif act in ("click", "submit"):
                try:
                    await page.click(step["selector"], timeout=5000)
                except Exception:
                    await page.keyboard.press("Enter")
                await page.wait_for_timeout(900)
                trail.append(f"Click {step.get('selector', 'submit')}")
            elif act == "assert_text":
                want = str(step.get("value", ""))
                body = await page.evaluate("() => document.body ? document.body.innerText : ''")
                trail.append(f"Verify the page shows {want!r}")
                if want and want not in body:
                    return Finding(
                        vuln_class=VulnClass.FUNCTIONAL, severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                        title=f"Broken user journey: {name}", endpoint_key=page.url,
                        evidence=Evidence(page_url=page.url, steps=trail,
                                          expected=f"'{want}' should appear once the journey completes",
                                          actual=f"'{want}' was NOT found — the flow did not complete end-to-end.",
                                          note="multi-step E2E journey"),
                        detail=f"The journey '{journey.get('goal', name)}' did not produce its expected result.",
                        source="qa.flows")
            await page.wait_for_timeout(200)
        return None
    except Exception as e:
        return Finding(
            vuln_class=VulnClass.FUNCTIONAL, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            title=f"User journey failed: {name}", endpoint_key=page.url,
            evidence=Evidence(page_url=page.url, steps=trail,
                              expected="The journey should complete without errors",
                              actual=f"A step failed: {e}", note="multi-step E2E journey"),
            detail=f"The journey '{name}' could not be completed: {e}", source="qa.flows")
    finally:
        await page.close()
