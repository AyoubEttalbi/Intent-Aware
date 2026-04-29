import os
import json
from typing import Dict, Any, List
from dotenv import load_dotenv
from agent.llm import LLMClient

load_dotenv()

CONTRACT_SCHEMA = {
    "type": "object",
    "properties": {
        "contracts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "endpoints": {"type": "array", "items": {"type": "string"}},
                    "falsifiable_condition": {"type": "string"}
                },
                "required": ["id", "name", "description", "endpoints", "falsifiable_condition"]
            }
        }
    },
    "required": ["contracts"]
}

INTENT_EXTRACTOR_PROMPT = """
You are a Senior Security Architect. Analyze the OpenAPI spec and description to extract "Behavior Contracts".

### Rules from Agent Charter:
1. **Falsifiability (Rule 2.1)**: A contract is only valid if it can be proven false by an observable HTTP response. Avoid vague statements like "The app should be secure."
2. **Ambiguity (Rule 2.4)**: If the spec is unclear about a behavior, flag it as [AMBIGUOUS] and define two possible interpretations.
3. **Intent as Truth (Rule 1.1)**: Focus on what the app *should* do, not just what the HTTP status codes imply.

### Input:
- App Description: {description}
- OpenAPI Spec: {spec}

Output format:
Return ONLY a JSON object that is a valid INSTANCE of the following schema (do NOT return the schema itself):
{schema}

Focus on non-obvious intent and security boundaries.
"""

class IntentExtractor:
    def __init__(self):
        self.llm = LLMClient()

    def extract(self, spec: Dict[str, Any], description: str) -> List[Dict[str, Any]]:
        """
        Extracts behavior contracts from spec and description.
        """
        prompt = INTENT_EXTRACTOR_PROMPT.format(
            description=description,
            spec=json.dumps(spec, indent=2),
            schema=json.dumps(CONTRACT_SCHEMA, indent=2)
        )

        data = self.llm.ask_json(
            system_prompt="You are a QA automation expert. Return only valid JSON.",
            user_prompt=prompt
        )

        return data.get("contracts", [])

if __name__ == "__main__":
    # Placeholder for manual test
    print("Intent Extractor initialized.")
