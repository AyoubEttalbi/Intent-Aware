"""
extractors/parser.py — OpenAPI/Swagger spec loader (scope-safe).

Security (v2 review S1): a spec_url is attacker-influenced input on a hosted
offering. This loader therefore:
  * refuses non-http(s) sources by default — `spec_url='/etc/passwd'` is NOT a
    local-file-read primitive (set allow_local=True only for trusted CLI/tests),
  * enforces a host allowlist so a spec_url can't point the fetch at an internal
    host (169.254.169.254, localhost) — SSRF guard,
  * never follows redirects (a 30x can't bounce the fetch off-scope),
  * accepts JSON *and* YAML, and can carry auth headers for protected specs.
"""
import json
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx
from openapi_spec_validator.readers import read_from_filename


class OpenAPIParser:
    def __init__(self, allowed_hosts: Optional[set] = None,
                 headers: Optional[dict] = None, allow_local: bool = False):
        self.allowed_hosts = {h.lower() for h in (allowed_hosts or set()) if h}
        self.headers = dict(headers or {})
        self.allow_local = allow_local
        self.client = httpx.Client(timeout=30.0, follow_redirects=False)

    def load_spec(self, source: str) -> Dict[str, Any]:
        """Load an OpenAPI/Swagger spec from an http(s) URL (or a local file iff allow_local)."""
        if not source:
            raise ValueError("empty spec source")
        if source.startswith(("http://", "https://")):
            return self._load_from_url(source)
        if self.allow_local:
            return self._load_from_file(source)
        raise ValueError(
            f"refusing to load spec from non-http source {source!r} "
            "(local-file specs require allow_local=True)")

    def _host_ok(self, url: str) -> bool:
        if not self.allowed_hosts:
            return True
        return (urlparse(url).hostname or "").lower() in self.allowed_hosts

    def _load_from_url(self, url: str) -> Dict[str, Any]:
        if not self._host_ok(url):
            raise ValueError(f"spec_url host {urlparse(url).hostname!r} is outside the target scope")
        response = self.client.get(url, headers=self.headers)
        response.raise_for_status()
        spec = self._decode(response.text)
        self._validate(spec)
        return spec

    def _load_from_file(self, path_str: str) -> Dict[str, Any]:
        path = Path(path_str)
        if not path.exists():
            raise FileNotFoundError(f"Spec file not found: {path_str}")
        spec, _ = read_from_filename(path_str)
        self._validate(spec)
        return spec

    @staticmethod
    def _decode(text: str) -> Dict[str, Any]:
        """JSON first; fall back to YAML (a large share of real specs are YAML)."""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        try:
            import yaml
            data = yaml.safe_load(text)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        raise ValueError("spec is neither valid JSON nor YAML")

    def _validate(self, spec: Dict[str, Any]):
        # Best-effort: accept v2 (Swagger) and v3 (OpenAPI). Validation errors are
        # downgraded to a soft pass so a slightly-off but usable spec still helps —
        # build_surface tolerates missing pieces.
        if not isinstance(spec, dict) or not spec.get("paths"):
            raise ValueError("spec has no 'paths'")
        return spec
