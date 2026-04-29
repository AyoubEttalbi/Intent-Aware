import json
from typing import Dict, Any, Optional
from agent.llm import LLMClient
from execution.runner import TestResponse

LLM_JUDGE_PROMPT = """
You are a Senior Security QA Judge. Your task is to determine if an API response represents a bug OR a successful security block.

### 1. Behavior Contract
{contract}

### 2. Test Scenario
{scenario}

### 3. API Response
- Status Code: {status_code}
- Body: {body}

---

### Critical Instructions:
1. **Security Blocks are NOT Bugs**: If the scenario is an "Adversarial" or "Unauthorized" test (e.g., trying to access someone else's data), a 401 (Unauthorized), 403 (Forbidden), or 404 (Not Found) is usually the **DESIRED** behavior. Mark these as `is_bug: false`.
2. **200 is suspicious in Security Tests**: If a scenario was trying to bypass auth and got a 200 OK, that is almost certainly a bug.
3. **Logic Bugs**: If the status is 200 but the data violates the contract (e.g., "Alice" seeing "Bob's" data), that is a bug.
4. **Server Crashes**: 500 Internal Server Errors or raw stack traces are ALWAYS bugs.

### Output Format:
Return ONLY a JSON object with this schema:
{{
    "is_bug": boolean,
    "confidence": "high" | "medium" | "low",
    "reasoning": "Briefly explain if this was a successful block or a failure.",
    "severity": "critical" | "high" | "medium" | "low"
}}
"""

class Layer3LLMJudge:
    def __init__(self):
        self.llm = LLMClient()

    def judge(self, contract: Dict[str, Any], scenario: Dict[str, Any], response: TestResponse) -> Dict[str, Any]:
        """
        Uses LLM to judge if the response violates the behavior contract.
        """
        # Prepare body for prompt (truncate if too long)
        body_str = json.dumps(response.body, indent=2)
        if len(body_str) > 2000:
            body_str = body_str[:2000] + "... (truncated)"

        prompt = LLM_JUDGE_PROMPT.format(
            contract=json.dumps(contract, indent=2),
            scenario=json.dumps(scenario, indent=2),
            status_code=response.status_code,
            body=body_str
        )

        print(f"   ⚖️  LLM-as-Judge evaluating response...")
        
        result = self.llm.ask_json(
            system_prompt="You are an impartial QA judge. Return only valid JSON.",
            user_prompt=prompt
        )

        if not result:
            return {
                "is_bug": False,
                "confidence": "low",
                "reasoning": "LLM Judge failed to provide a verdict.",
                "severity": "low"
            }

        return result

if __name__ == "__main__":
    print("Layer 3 LLM Judge initialized.")
