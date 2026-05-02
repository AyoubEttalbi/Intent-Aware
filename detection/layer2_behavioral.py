from typing import Dict, Any, List
from execution.runner import TestResponse

class Layer2BehavioralChecker:
    def __init__(self):
        pass

    def check(self, scenario: Dict[str, Any], response: TestResponse, history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Performs behavioral and cross-request assertions.
        'history' contains previous results from the same run.
        """
        if response.status_code != 200:
            return {"is_bug": False}

        if not isinstance(response.body, dict):
            return {"is_bug": False}

        expected_failure = scenario.get("expected_failure_type", "")
        
        if expected_failure == "idor":
            requested_user_id = self._extract_user_id_from_url(scenario.get("endpoint", ""))
            response_user_id = response.body.get("id") or response.body.get("user_id")
            if requested_user_id and response_user_id and str(requested_user_id) != str(response_user_id):
                return {
                    "is_bug": True,
                    "severity": "critical",
                    "reason": f"IDOR: Requested user {requested_user_id} but got data for user {response_user_id}"
                }

        if expected_failure in ("data_leak", "unauthorized_access", "cross_user_access", "mass_assignment"):
            sensitive_fields = ['password', 'token', 'secret', 'api_key', 'hashed_password', 'role']
            found_sensitive = [f for f in sensitive_fields if f in response.body]
            if expected_failure == "mass_assignment" and "role" in response.body:
                return {
                    "is_bug": True,
                    "severity": "critical",
                    "reason": f"Mass Assignment: Non-admin user can modify role field to '{response.body.get('role')}'"
                }
            if found_sensitive:
                return {
                    "is_bug": True,
                    "severity": "high",
                    "reason": f"Data Leak: Sensitive fields exposed: {', '.join(found_sensitive)}"
                }

        return {"is_bug": False}

    def _extract_user_id_from_url(self, endpoint: str) -> str:
        import re
        match = re.search(r'/(\d+)(?:\?|$)', endpoint)
        if match:
            return match.group(1)
        match = re.search(r'/users/([^\/]+)', endpoint)
        if match:
            return match.group(1)
        return None

if __name__ == "__main__":
    print("Layer 2 Behavioral Checker initialized.")
