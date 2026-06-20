"""
attacks/inject.py — shared helpers for placing a payload into a single
injection point (path param, query param, or a string body field) while keeping
everything else valid. Used by the sqli / xss / path_traversal plugins.
"""
from __future__ import annotations

from urllib.parse import quote

from core.models import Request

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def injectable_method(endpoint, allow_writes: bool = True) -> bool:
    """Whether it's safe to fire injection payloads at this endpoint.

    DELETE is never injected (too destructive). Other write methods require an
    explicit writes opt-in; safe methods (GET/HEAD) are always fair game.
    """
    m = endpoint.method.upper()
    if m == "DELETE":
        return False
    if m in WRITE_METHODS and not allow_writes:
        return False
    return True


def injection_points(endpoint, allow_writes: bool = True) -> list:
    """[(kind, param_name)] for every place a string payload can go.

    Path + query points are read-safe. Body points mutate the target, so they are
    only included when `allow_writes` is set (read-only default for real targets).
    """
    pts = [("path", p["name"]) for p in endpoint.path_params if p.get("name")]
    pts += [("query", p["name"]) for p in endpoint.query_params if p.get("name")]
    if allow_writes:
        schema = endpoint.body_schema if isinstance(endpoint.body_schema, dict) else {}
        for name, pdef in (schema.get("properties", {}) or {}).items():
            if str((pdef or {}).get("type", "string")).lower() in ("string", ""):
                pts.append(("body", name))
    return pts


def build_injection_request(ctx, kind: str, name: str, payload, label: str = "") -> Request:
    ep = ctx.endpoint
    base_body = dict(ctx.sample_body) if ctx.sample_body else None
    if kind == "path":
        url = ctx.url(**{name: payload})
        body = base_body if ep.method in WRITE_METHODS else None
    elif kind == "query":
        url = ctx.url()
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{name}={quote(str(payload))}"
        body = base_body if ep.method in WRITE_METHODS else None
    else:  # body
        body = dict(base_body or {})
        body[name] = payload
        url = ctx.url()
    return Request(method=ep.method, url=url, body=body, label=label or f"{kind}:{name}",
                   content_type=ep.request_content_type)
