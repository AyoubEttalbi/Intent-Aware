import os
import json
from typing import Dict, Any, List
from dotenv import load_dotenv
from agent.llm import LLMClient

load_dotenv()

ASSUMPTION_SCHEMA = {
    "type": "object",
    "properties": {
        "assumptions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "risk_level": {"enum": ["critical", "high", "medium", "low"]},
                    "description": {"type": "string"},
                    "target_endpoints": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["id", "risk_level", "description", "target_endpoints"]
            }
        }
    },
    "required": ["assumptions"]
}

ASSUMPTION_EXTRACTOR_PROMPT = """
You are an expert Adversarial QA Engineer. Analyze the spec and description to find "Implicit Assumptions".

### Rules from Agent Charter:
1. **Non-Obviousness (Rule 2.2)**: Do NOT restate the spec. Assume the developers missed something critical.
2. **Impact Prioritization (Rule 3.3)**: Focus on high-risk areas first:
   - Auth Bypass / IDOR
   - Data Leakage
   - Business Logic Integrity
3. **Observability (Rule 2.3)**: Assumptions must be testable via HTTP.

### Input:
- App Description: {description}
- OpenAPI Spec: {spec}

### Output JSON Format:
{{
    "assumptions": [
        {{
            "id": "string",
            "description": "the non-obvious thing developers likely assumed",
            "risk_level": "critical" | "high" | "medium" | "low",
            "target_endpoints": ["/path1", "/path2"]
        }}
    ]
}}
"""

class AssumptionExtractor:
    def __init__(self):
        self.llm = LLMClient()

    def extract(self, spec: Dict[str, Any], description: str) -> List[Dict[str, Any]]:
        """
        Extracts implicit assumptions from spec and description.
        """
        prompt = ASSUMPTION_EXTRACTOR_PROMPT.format(
            description=description,
            spec=json.dumps(spec, indent=2),
            schema=json.dumps(ASSUMPTION_SCHEMA, indent=2)
        )

        data = self.llm.ask_json(
            system_prompt="You are a security-focused QA expert. Return only valid JSON.",
            user_prompt=prompt
        )

        return data.get("assumptions", [])

if __name__ == "__main__":
    print("Assumption Extractor initialized.")
