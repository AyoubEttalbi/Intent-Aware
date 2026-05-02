import jsonschema
from typing import Dict, Any, Optional
from execution.runner import TestResponse

SECURITY_TEST_TYPES = {
    "auth_bypass", "data_leak", "idor", "privilege_escalation", 
    "mass_assignment", "unauthorized_access", "cross_user_access",
    "logic_violation", "schema_violation", "state_corruption"
}

class Layer1ContractChecker:
    def __init__(self, spec: Dict[str, Any]):
        self.spec = spec

    def check(self, scenario: Dict[str, Any], response: TestResponse) -> Dict[str, Any]:
        """
        Performs basic contract checks.
        Returns a dict with 'is_bug', 'severity', and 'reason'.
        """
        expected_failure = scenario.get("expected_failure_type", "")
        is_security_test = expected_failure in SECURITY_TEST_TYPES

        if is_security_test:
            if response.status_code in (401, 403, 404):
                return {
                    "is_bug": False,
                    "reason": f"Security block: Got {response.status_code} as expected for {expected_failure} test."
                }
            if 200 <= response.status_code < 300:
                return {
                    "is_bug": True,
                    "severity": "critical",
                    "reason": f"Security Bypass ({expected_failure}): Expected 401/403/404, but got {response.status_code}."
                }

        if expected_failure == "auth_bypass":
            if 200 <= response.status_code < 300:
                return {
                    "is_bug": True,
                    "severity": "critical",
                    "reason": f"Auth Bypass: Expected 401/403 for unauthorized request, but got {response.status_code}."
                }

        if response.status_code == 200:
            if isinstance(response.body, str) and response.body.startswith("Error:"):
                 return {
                    "is_bug": True,
                    "severity": "low",
                    "reason": f"Unexpected error response body: {response.body}"
                }

        if response.status_code >= 500:
            return {
                "is_bug": True,
                "severity": "medium",
                "reason": f"Internal Server Error: Endpoint returned status {response.status_code}."
            }

        return {"is_bug": False}

if __name__ == "__main__":
    print("Layer 1 Contract Checker initialized.")
