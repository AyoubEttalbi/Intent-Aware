import json
import httpx
from typing import Dict, Any, Union
from pathlib import Path

class OpenAPIParser:
    def __init__(self):
        self.client = httpx.Client(timeout=10.0, follow_redirects=True)

    def load_spec(self, source: str) -> Dict[str, Any]:
        """
        Loads an OpenAPI spec from a URL or a local file path.
        Returns an empty dict if it fails, allowing the agent to continue with Discovery mode.
        """
        try:
            if source.startswith(("http://", "https://")):
                return self._load_from_url(source)
            else:
                return self._load_from_file(source)
        except Exception as e:
            print(f"⚠️ Spec loading failed for {source}: {e}")
            return {}

    def _load_from_url(self, url: str) -> Dict[str, Any]:
        response = self.client.get(url)
        if response.status_code != 200:
            raise ValueError(f"HTTP {response.status_code}")
        
        # Try JSON first
        try:
            return response.json()
        except json.JSONDecodeError:
            # Check if it looks like YAML (basic check)
            text = response.text.strip()
            if text.startswith("openapi:") or text.startswith("swagger:"):
                # We could add a YAML parser here if needed
                raise ValueError("YAML specs are not supported yet. Use JSON.")
            raise ValueError("Response is not valid JSON")

    def _load_from_file(self, path_str: str) -> Dict[str, Any]:
        path = Path(path_str)
        if not path.exists():
            raise FileNotFoundError(f"Spec file not found: {path_str}")
        
        with open(path, "r") as f:
            return json.load(f)

if __name__ == "__main__":
    parser = OpenAPIParser()
    print("OpenAPI Parser initialized.")
