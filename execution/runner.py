import httpx
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

@dataclass
class TestResponse:
    status_code: int
    headers: Dict[str, str]
    body: Any
    latency_ms: float
    timestamp: float

class TestRunner:
    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.client = httpx.Client(timeout=self.timeout)

    def execute(self, scenario: Dict[str, Any], auth_config: Optional[Dict[str, str]] = None) -> TestResponse:
        """
        Executes a test scenario.
        """
        method = scenario.get("method", "GET").upper()
        endpoint = scenario.get("endpoint", "")
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
            
        url = f"{self.base_url}{endpoint}"
        raw_headers = scenario.get("headers", {})
        headers = {}
        if isinstance(raw_headers, dict):
            headers = {k: v for k, v in raw_headers.items() if v is not None}
        
        # Handle Persona-based Auth
        persona_name = scenario.get("persona_name")
        if persona_name:
            from agent.personas import PersonaManager
            pm = PersonaManager()
            persona = pm.get_persona(persona_name)
            if persona and persona.token:
                headers["Authorization"] = f"Bearer {persona.token}"
            elif persona_name == "GUEST":
                if "Authorization" in headers:
                    del headers["Authorization"]
        
        # Legacy/Manual Auth Override
        if auth_config:
            if auth_config.get("type") == "bearer":
                headers["Authorization"] = f"Bearer {auth_config['token']}"
            elif auth_config.get("type") == "apikey":
                name = auth_config.get("name", "X-API-KEY")
                headers[name] = auth_config["value"]
            elif auth_config.get("type") == "custom":
                headers.update(auth_config.get("headers", {}))

        body = scenario.get("body")

        start_time = time.perf_counter()
        
        try:
            response = self.client.request(
                method=method,
                url=url,
                headers=headers,
                json=body if method in ["POST", "PUT", "PATCH"] else None,
                follow_redirects=True
            )
            
            latency = (time.perf_counter() - start_time) * 1000
            
            try:
                resp_body = response.json()
            except:
                resp_body = response.text

            return TestResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=resp_body,
                latency_ms=latency,
                timestamp=time.time()
            )
        except Exception as e:
            latency = (time.perf_counter() - start_time) * 1000
            return TestResponse(
                status_code=0,
                headers={},
                body=str(e),
                latency_ms=latency,
                timestamp=time.time()
            )

if __name__ == "__main__":
    print("Test Runner initialized.")
