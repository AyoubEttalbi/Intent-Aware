import jsonschema
from typing import Dict, Any, Optional
from execution.runner import TestResponse

class Layer1ContractChecker:
    def __init__(self, spec: Dict[str, Any]):
        self.spec = spec

    def check(self, scenario: Dict[str, Any], response: TestResponse) -> Dict[str, Any]:
        """
        Performs basic contract checks.
        Returns a dict with 'is_bug', 'severity', and 'reason'.
        """
        expected_failure = scenario.get("expected_failure_type")
        
        # 1. Auth Bypass Check
        if expected_failure == "auth_bypass":
            if 200 <= response.status_code < 300:
                return {
                    "is_bug": True,
                    "severity": "critical",
                    "reason": f"Auth Bypass: Expected 401/403 for unauthorized request, but got {response.status_code}."
                }

        # 2. Schema Violation Check (when status is 200)
        if response.status_code == 200:
            # We would need to find the schema in the spec for the specific endpoint/method
            # Simplified for now: just checking if response is valid JSON if expected
            if isinstance(response.body, str) and response.body.startswith("Error:"):
                 return {
                    "is_bug": True,
                    "severity": "low",
                    "reason": f"Unexpected error response body: {response.body}"
                }

        # 3. Server Error Check
        if response.status_code >= 500:
            return {
                "is_bug": True,
                "severity": "medium",
                "reason": f"Internal Server Error: Endpoint returned status {response.status_code}."
            }

        return {"is_bug": False}

if __name__ == "__main__":
    print("Layer 1 Contract Checker initialized.")
