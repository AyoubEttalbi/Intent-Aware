from dataclasses import dataclass, field
from typing import Any, List, Optional, Dict

@dataclass
class FormField:
    name: str           # HTML name or id attribute
    field_type: str     # "text", "email", "password", "number", "select", "textarea", "hidden"
    label: str          # Associated label text
    placeholder: str
    required: bool
    options: List[str]  # For select elements
    validation_hint: str  # e.g. "min=0 max=999", "pattern=[A-Z]{3}", inferred from HTML attrs

@dataclass
class PageContext:
    url: str
    title: str
    page_role: str      # "login", "register", "dashboard", "list", "detail", "form",
                        # "checkout", "admin", "settings", "api_docs", "generic"
    forms: List[Dict]   # Each: {form_action, form_method, fields: list[FormField], submit_label}
    auth_required: bool # Inferred: True if page redirected to login when unauthenticated
    entity_type: str    # e.g. "User", "Order", "Product" — matched from AppContext.models
    url_params: List[str]  # e.g. ["id", "user_id"] from /users/{id}/orders

@dataclass
class AppContext:
    routes: List[Dict] = field(default_factory=list)
    # Each route: {method, path, auth_required, roles: list[str], description, request_body_schema}
    models: List[str] = field(default_factory=list)
    auth_flow: Dict = field(default_factory=dict)
    # auth_flow: {login_path, username_field, password_field, token_storage: "cookie"|"localStorage"|"header",
    #             default_credentials: {admin: {...}, user: {...}}}
    app_type: str = "generic"
    # "ecommerce" | "admin_dashboard" | "api_only" | "auth_heavy" | "cms" | "generic"
    personas: List[Dict] = field(default_factory=list)
    # Derived from roles in routes. Each: {name, role, credentials, can_access_patterns: list[str]}
    tech_stack: List[str] = field(default_factory=list)
    # e.g. ["FastAPI", "PostgreSQL", "JWT"] — informs injection payload selection

@dataclass
class Scenario:
    id: str
    url: str
    url_pattern: str    # Normalized: /users/{id}/orders not /users/42/orders
    page_role: str
    category: str       # "functional" | "security" | "boundary" | "privilege" | "injection"
    attack_type: str    # "sqli" | "xss" | "idor" | "auth_bypass" | "mass_assignment" |
                        # "rate_limit" | "business_logic" | "input_validation" | "info_disclosure"
    name: str
    description: str
    persona: str        # Which persona runs this: "admin", "user", "unauthenticated"
    target_field: str   # Specific field being tested — enables dedup fingerprint
    payload: Any        # Concrete value(s) to send
    http_method: str
    endpoint: str
    expected_result: str   # Plain English: "server returns 403, not 200"
    failure_signature: str # What the LLM judge looks for to confirm a bug:
                           # "status=200 AND response contains user_id != current_user_id"
    severity: str       # "critical" | "high" | "medium" | "low"
    dedup_fingerprint: str = ""  # f"{url_pattern}:{attack_type}:{target_field}"
