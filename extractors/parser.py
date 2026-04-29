import json
import httpx
from typing import Dict, Any, Union
from pathlib import Path
from openapi_spec_validator import validate_spec
from openapi_spec_validator.readers import read_from_filename

class OpenAPIParser:
    def __init__(self):
        self.client = httpx.Client(timeout=30.0)

    def load_spec(self, source: str) -> Dict[str, Any]:
        """
        Loads an OpenAPI spec from a URL or a local file path.
        """
        if source.startswith(("http://", "https://")):
            return self._load_from_url(source)
        else:
            return self._load_from_file(source)

    def _load_from_url(self, url: str) -> Dict[str, Any]:
        response = self.client.get(url)
        response.raise_for_status()
        
        # Try JSON first
        try:
            spec = response.json()
        except json.JSONDecodeError:
            # If not JSON, it might be YAML (not handled here but could be added)
            # For now, we'll assume it's JSON or fail
            raise ValueError(f"Failed to decode JSON from {url}")
        
        self._validate(spec)
        return spec

    def _load_from_file(self, path_str: str) -> Dict[str, Any]:
        path = Path(path_str)
        if not path.exists():
            raise FileNotFoundError(f"Spec file not found: {path_str}")
        
        spec, url = read_from_filename(path_str)
        self._validate(spec)
        return spec

    def _validate(self, spec: Dict[str, Any]):
        try:
            validate_spec(spec)
        except Exception as e:
            raise ValueError(f"Invalid OpenAPI spec: {str(e)}")

if __name__ == "__main__":
    # Quick test
    parser = OpenAPIParser()
    try:
        # Example with a known valid spec if possible, or just print usage
        print("OpenAPI Parser initialized. Use load_spec(source) to parse a spec.")
    except Exception as e:
        print(f"Error: {e}")
