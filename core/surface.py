"""
core/surface.py — build the unified, testable Surface (list[Endpoint]) from an
OpenAPI spec, optionally merged with crawler-discovered shadow endpoints.

This replaces the old "append discovered endpoints to a description string"
hand-off: every operation in the spec becomes a structured, directly-executable
target with params, body schema and an auth-required flag.
"""
from __future__ import annotations

from typing import List, Optional

from core.models import Endpoint

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


def _resolve_ref(spec: dict, node):
    """Shallow local-$ref resolver (#/components/...)."""
    seen = 0
    while isinstance(node, dict) and "$ref" in node and seen < 10:
        ref = node["$ref"]
        if not ref.startswith("#/"):
            break
        cur = spec
        for part in ref[2:].split("/"):
            cur = cur.get(part, {}) if isinstance(cur, dict) else {}
        node = cur
        seen += 1
    return node


def _params_for(spec: dict, path_item: dict, op: dict) -> list:
    raw = list(path_item.get("parameters", []) or []) + list(op.get("parameters", []) or [])
    out = []
    for p in raw:
        p = _resolve_ref(spec, p)
        if not isinstance(p, dict):
            continue
        if p.get("in") == "body":
            continue   # Swagger 2.0 body param — handled by _body_schema
        out.append({
            "name": p.get("name"),
            "in": p.get("in"),
            "required": p.get("required", p.get("in") == "path"),
            # v3 puts type under schema; v2 puts it directly on the param
            "type": (p.get("schema") or {}).get("type", p.get("type", "string")),
        })
    return out


def _body_schema(spec: dict, path_item: dict, op: dict) -> Optional[dict]:
    # OpenAPI 3: requestBody.content[*].schema
    rb = _resolve_ref(spec, op.get("requestBody", {}))
    content = (rb or {}).get("content", {}) if isinstance(rb, dict) else {}
    for ctype in ("application/json", "application/*+json"):
        if ctype in content:
            return _resolve_ref(spec, content[ctype].get("schema", {}))
    for v in content.values():
        return _resolve_ref(spec, (v or {}).get("schema", {}))
    # Swagger 2.0: a parameter with in: body carries the schema (often a #/definitions ref).
    raw = list(path_item.get("parameters", []) or []) + list(op.get("parameters", []) or [])
    for p in raw:
        p = _resolve_ref(spec, p)
        if isinstance(p, dict) and p.get("in") == "body":
            return _resolve_ref(spec, p.get("schema", {})) or None
    return None


def _base_prefix(spec: dict) -> str:
    """Path prefix to prepend to each operation path (servers[0].url path / v2 basePath)."""
    from urllib.parse import urlparse as _up
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        u = (servers[0] or {}).get("url", "") if isinstance(servers[0], dict) else ""
        path = _up(u).path if "://" in u else u
        return (path or "").rstrip("/")
    if spec.get("basePath"):
        return str(spec["basePath"]).rstrip("/")
    return ""


def _request_content_type(spec: dict, op: dict) -> str:
    rb = _resolve_ref(spec, op.get("requestBody", {}))
    content = (rb or {}).get("content", {}) if isinstance(rb, dict) else {}
    for ctype in content:
        if "form-urlencoded" in ctype or "multipart" in ctype:
            return "form"
    return "json"


def _auth_required(spec: dict, op: dict, params: list) -> bool:
    if op.get("security") or spec.get("security"):
        return True
    for p in params:
        if p.get("in") == "header" and "auth" in str(p.get("name", "")).lower():
            return True
    return False


def sample_value_for(type_: Optional[str], name: str = ""):
    t = str(type_ or "string").lower()
    n = name.lower()
    if t in ("integer", "number"):
        return 1
    if t == "boolean":
        return True
    if t == "array":
        return []
    if t == "object":
        return {}
    if "email" in n:
        return "qa.tester@example.com"
    if "name" in n:
        return "QA Tester"
    return "qa_test"


def baseline_body(spec: dict, endpoint: Endpoint) -> dict:
    """A minimal, valid-looking body (required fields only) to use as a baseline."""
    schema = _resolve_ref(spec, endpoint.body_schema or {})
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties", {}) or {}
    required = set(schema.get("required", []) or [])
    body = {}
    for name in required:
        pdef = _resolve_ref(spec, props.get(name, {})) or {}
        body[name] = sample_value_for(pdef.get("type"), name)
    # if nothing is required, seed one benign string field so the request is non-empty
    if not body:
        for name, pdef in props.items():
            pdef = _resolve_ref(spec, pdef) or {}
            if name.lower() not in ("role", "admin", "permissions"):
                body[name] = sample_value_for(pdef.get("type"), name)
                break
    return body


def build_surface(spec: dict, base_url: str) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    paths = (spec or {}).get("paths", {}) or {}
    prefix = _base_prefix(spec or {})
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        # Apply servers[]/basePath prefix unless the path already carries it.
        full_path = path if (not prefix or path.startswith(prefix)) else prefix + path
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            params = _params_for(spec, item, op)
            endpoints.append(Endpoint(
                method=method.upper(),
                path_template=full_path,
                base_url=base_url,
                params=params,
                body_schema=_body_schema(spec, item, op),
                auth_required=_auth_required(spec, op, params),
                source="spec",
                responses=op.get("responses", {}) or {},
                summary=op.get("summary", op.get("operationId", "")),
                request_content_type=_request_content_type(spec, op),
            ))
    return endpoints
