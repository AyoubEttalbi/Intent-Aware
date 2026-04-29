import os
import json
from typing import Dict, Any, List
from dotenv import load_dotenv
from agent.llm import LLMClient

load_dotenv()

SCENARIO_SCHEMA = {
    "type": "object",
    "properties": {
        "scenarios": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "assumption_id": {"type": "string"},
                    "name": {"type": "string"},
                    "endpoint": {"type": "string"},
                    "method": {"enum": ["GET", "POST", "PUT", "DELETE", "PATCH"]},
                    "headers": {"type": "object"},
                    "body": {"type": "object"},
                    "expected_failure_type": {
                        "enum": ["auth_bypass", "data_leak", "logic_violation", "schema_violation", "state_corruption"]
                    },
                    "risk_score": {"type": "integer", "minimum": 1, "maximum": 10}
                },
                "required": ["id", "assumption_id", "name", "endpoint", "method", "expected_failure_type", "risk_score"]
            }
        }
    },
    "required": ["scenarios"]
}

SCENARIO_GENERATOR_PROMPT = """
You are a Senior Penetration Tester. Generate adversarial scenarios for an assumption.

### Rules from Agent Charter:
1. **Atomic Scenarios (Rule 3.1)**: Each scenario MUST target exactly ONE assumption.
2. **Failure Types (Rule 3.2)**: Every scenario MUST declare its `expected_failure_type`.
3. **Adversarial Creativity (Rule 3.4)**: Attack from multiple angles:
   - Happy-path violation
   - Boundary values / Nulls
   - Reordered flows / Race conditions
   - Type confusion

### Context:
- Assumption: {assumption_description}
- Target Endpoints: {target_endpoints}
- Spec Snippet: {spec_snippet}

### Output JSON Instance:
{schema}
"""

class ScenarioGenerator:
    def __init__(self):
        self.llm = LLMClient()

    def generate(self, assumption: Dict[str, Any], spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generates adversarial scenarios for a given assumption.
        """
        # We only pass the relevant parts of the spec to save tokens
        # (Simplified for now: passing the whole thing or a summary)
        # Pass a larger snippet of the spec to ensure the LLM has enough context
        spec_snippet = json.dumps(spec, indent=2)[:15000] 


        prompt = SCENARIO_GENERATOR_PROMPT.format(
            assumption_id=assumption['id'],
            assumption_description=assumption['description'],
            risk_level=assumption['risk_level'],
            target_endpoints=assumption['target_endpoints'],
            spec_snippet=spec_snippet,
            schema=json.dumps(SCENARIO_SCHEMA, indent=2)
        )

        data = self.llm.ask_json(
            system_prompt="You are an adversarial QA expert. Return only valid JSON.",
            user_prompt=prompt
        )

        if not data:
            print("⚠️ Scenario generation returned empty data object.")

        return data.get("scenarios", [])

if __name__ == "__main__":
    print("Scenario Generator initialized.")
