"""
core/models.py — single source of truth for the v2 security engine.

Plain dataclasses shared by discovery, identities, attack plugins, detection and
reporting. No business logic beyond trivial helpers, so every layer speaks the
same structured language (no more string-blob hand-offs).
"""
from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class VulnClass(str, Enum):
    IDOR = "idor"
    BROKEN_AUTH = "broken_auth"
    MASS_ASSIGNMENT = "mass_assignment"
    SQLI = "sqli"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    AUTHZ = "authz"
    CSRF = "csrf"
    DATA_EXPOSURE = "data_exposure"
    SECURITY_HEADERS = "security_headers"
    CORS = "cors"
    OPEN_REDIRECT = "open_redirect"
    SSTI = "ssti"
    COMMAND_INJECTION = "command_injection"
    JWT = "jwt"
    RATE_LIMIT = "rate_limit"
    UNDOCUMENTED_ENDPOINT = "undocumented_endpoint"
    SERVER_ERROR = "server_error"
    UI = "ui"
    # QA / functional classes (UI crawler)
    FUNCTIONAL = "functional"
    VALIDATION = "validation"
    BROKEN_LINK = "broken_link"
    JS_ERROR = "js_error"
    UX = "ux"
    PERFORMANCE = "performance"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class Identity:
    """A user persona the engine can act as."""
    name: str                                            # "anon", "userA", "admin"
    role: str = "anonymous"
    headers: dict = field(default_factory=dict)          # e.g. {"Authorization": "Bearer ..."}
    cookies: dict = field(default_factory=dict)
    owned_resource_ids: dict = field(default_factory=dict)  # {"users": ["2"], "orders": ["2","3"]}
    description: str = ""

    @property
    def is_anonymous(self) -> bool:
        return not self.headers and not self.cookies


@dataclass
class Endpoint:
    """One testable API operation (method + templated path)."""
    method: str
    path_template: str                                   # "/users/{id}"
    base_url: str
    params: list = field(default_factory=list)           # [{"name","in","type","required"}]
    body_schema: Optional[dict] = None
    auth_required: bool = False
    source: str = "spec"                                 # spec | shadow | both
    responses: dict = field(default_factory=dict)        # {"200": schema, ...}
    summary: str = ""
    request_content_type: str = "json"                   # "json" | "form"

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path_template}"

    @property
    def path_params(self) -> list:
        return [p for p in self.params if p.get("in") == "path"]

    @property
    def query_params(self) -> list:
        return [p for p in self.params if p.get("in") == "query"]

    def concrete_path(self, values: Optional[dict] = None) -> str:
        path = self.path_template
        for name, val in (values or {}).items():
            path = path.replace("{" + name + "}", str(val))
        return path

    def url_for(self, values: Optional[dict] = None) -> str:
        return self.base_url.rstrip("/") + self.concrete_path(values or {})


@dataclass
class Request:
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: Any = None
    identity: str = "anon"
    strip_auth: bool = False          # negative-auth primitive: send with NO credentials
    label: str = ""
    content_type: str = "json"        # "json" | "form"


@dataclass
class Response:
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: Any = None
    text: str = ""
    latency_ms: float = 0.0
    error: Optional[str] = None
    final_url: str = ""          # URL after any followed (same-host) redirects
    redirected: bool = False     # did the server send a 3xx?
    redirect_location: str = ""  # first Location header (even when NOT followed)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def haystack(self) -> str:
        if isinstance(self.body, str):
            return self.body
        if self.text:
            return self.text
        try:
            return json.dumps(self.body)
        except Exception:
            return str(self.body)

    def contains(self, needle: str) -> bool:
        return bool(needle) and needle in self.haystack()


@dataclass
class Evidence:
    request: Optional[Request] = None
    response: Optional[Response] = None
    baseline_request: Optional[Request] = None
    baseline_response: Optional[Response] = None
    note: str = ""
    # QA / UI evidence (set by the crawler instead of request/response)
    page_url: str = ""
    steps: list = field(default_factory=list)   # human reproduction steps
    expected: str = ""
    actual: str = ""
    screenshot: str = ""                          # path to a saved screenshot


@dataclass
class Finding:
    vuln_class: VulnClass
    severity: Severity
    confidence: Confidence
    title: str
    endpoint_key: str
    evidence: Evidence
    identity: str = "anon"
    detail: str = ""            # technical explanation produced by the plugin oracle
    explanation: str = ""       # plain-language (filled by the explainer)
    impact: str = ""
    fix: str = ""
    source: str = ""            # plugin / layer name that produced it

    def dedup_key(self) -> str:
        return f"{self.vuln_class.value}|{self.endpoint_key}|{self.identity}"


# Header values to mask in human-facing repros / persisted evidence.
CREDENTIAL_HEADERS = {
    "authorization", "cookie", "x-api-key", "x-auth-token",
    "x-access-token", "x-session-token", "api-key", "x-csrf-token",
}


def _form_encode(body) -> str:
    from urllib.parse import urlencode
    if isinstance(body, dict):
        return urlencode({k: ("" if v is None else v) for k, v in body.items()})
    return str(body)


def to_curl(req: Optional[Request], redact: bool = True) -> str:
    """Render a copy-pasteable curl reproduction for a Request.

    Honours `req.content_type` (form vs json), omits a body for safe methods,
    avoids duplicating a Content-Type already present in the headers, and (by
    default) masks credential header values so the repro is safe to share.
    """
    if req is None:
        return ""
    method = req.method.upper()
    parts = ["curl", "-i", "-X", method]
    header_names = {k.lower() for k in (req.headers or {})}
    for k, v in (req.headers or {}).items():
        val = "<redacted>" if (redact and k.lower() in CREDENTIAL_HEADERS) else str(v)
        parts += ["-H", f"{k}: {val}"]

    has_body = req.body is not None and method not in ("GET", "HEAD")
    if has_body:
        if req.content_type == "form":
            ctype = "application/x-www-form-urlencoded"
            data = _form_encode(req.body)
        else:
            ctype = "application/json"
            data = req.body if isinstance(req.body, str) else json.dumps(req.body)
        if "content-type" not in header_names:
            parts += ["-H", f"Content-Type: {ctype}"]
        parts += ["--data", data]
    parts.append(req.url)
    return " ".join(shlex.quote(p) for p in parts)
