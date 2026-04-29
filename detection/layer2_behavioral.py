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
        # Example 1: Data Isolation (heuristic)
        # If the body contains a 'username' or 'email' that doesn't match the test user
        if response.status_code == 200 and isinstance(response.body, dict):
            # This is a very basic heuristic, could be improved
            potential_pii = ['email', 'password', 'address', 'phone']
            for field in potential_pii:
                if field in response.body and scenario.get("expected_failure_type") == "data_leak":
                    return {
                        "is_bug": True,
                        "severity": "high",
                        "reason": f"Potential Data Leak: Sensitive field '{field}' found in response body when testing data isolation."
                    }

        return {"is_bug": False}

if __name__ == "__main__":
    print("Layer 2 Behavioral Checker initialized.")
