import json
from typing import Dict, Any, Optional
from agent.llm import LLMClient
from execution.runner import TestResponse

LLM_JUDGE_PROMPT = """
You are a Senior Security QA Judge. Your task is to determine if an API response represents a security vulnerability (BUG) OR expected/desired behavior.

## CONTEXT: Test Persona
{scenario_context}

## Test Scenario
{scenario_text}

## API Response
Status: {status_code}
Body: {body}

---

## CRITICAL DECISION RULES:

### 🚫 THESE ARE NOT BUGS (Security Blocks):
- **401 Unauthorized** = Correctly blocked unauthenticated request
- **403 Forbidden** = Correctly blocked unauthorized request  
- **404 Not Found** = Resource doesn't exist (or properly hidden)
- **422 Validation Error** = Input validation working correctly

### ✅ THESE ARE REAL BUGS:
- **200 OK** on protected endpoint WITHOUT valid auth = AUTH BYPASS
- **200 OK** returning someone else's data (check user_id in response) = IDOR
- **500** or stack trace in response = SERVER ERROR

## EXAMPLES:
| Request | Response | Bug? | Reason |
|----------|-----------|------|--------|
| GET /orders/1 (no auth) | 401 | NO ✅ | Correct - auth required |
| GET /orders/1 (no auth) | 200 + data | YES | Auth bypass - should be 401 |
| GET /users/2 (as user 1) | 200 + {"id":2, "data":...} | YES | IDOR - accessing other user's data |
| GET /orders/999 | 404 | NO ✅ | Correct - resource doesn't exist |
| PUT /users/1 {"role":"admin"} (as user) | 200 | YES | Mass assignment - privilege escalation |

---

## Output:
Return JSON with is_bug (true/false), confidence, reasoning, severity, bug_type.
"""

class Layer3LLMJudge:
    def __init__(self):
        self.llm = LLMClient()

    def judge(self, contract: Dict[str, Any], scenario: Dict[str, Any], response: TestResponse, persona: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Uses LLM to judge if the response violates the behavior contract.
        
        Args:
            contract: Behavior contracts from intent extraction
            scenario: The test scenario being executed
            response: API response to evaluate
            persona: Context about who is making the request (optional)
        """
        body_str = json.dumps(response.body, indent=2)
        if len(body_str) > 2000:
            body_str = body_str[:2000] + "... (truncated)"

        persona_context = "No persona context provided."
        if persona:
            persona_context = json.dumps(persona, indent=2)

        # Use string replace instead of format to avoid { } interpreted as keys
        scenario_context = json.dumps(scenario, indent=2)
        
        prompt = LLM_JUDGE_PROMPT
        prompt = prompt.replace("{scenario_context}", persona_context)
        prompt = prompt.replace("{scenario_text}", scenario_context)
        prompt = prompt.replace("{status_code}", str(response.status_code))
        prompt = prompt.replace("{body}", body_str)

        print(f"   ⚖️  LLM-as-Judge evaluating response (status={response.status_code})...")
        
        result = self.llm.ask_json(
            system_prompt="You are an impartial QA judge. Return ONLY valid JSON with no markdown.",
            user_prompt=prompt
        )

        if not result:
            return {
                "is_bug": False,
                "confidence": "low",
                "reasoning": "LLM Judge failed to provide a verdict.",
                "severity": "low",
                "bug_type": "none"
            }

        result.setdefault("bug_type", "none")
        return result

if __name__ == "__main__":
    print("Layer 3 LLM Judge initialized.")
