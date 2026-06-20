"""
core/auth_adapters.py — declarative, browser-free authentication.

The make-or-break for "test behind login on ANY app": resolve an identity config
into a working `Identity` (cookies/headers) WITHOUT a browser whenever possible,
covering the schemes real apps actually use:

  type='bearer'         {token}                         -> Authorization: Bearer <token>
  type='api_key'        {key, header?}                  -> <header|X-API-Key>: <key>
  type='header'         {headers:{...}}                 -> raw headers
  type='session'        {cookies:{...}}                 -> raw cookies (paste storage_state)
  type='token_exchange' {token_url, creds, token_path?,  -> POST creds, JSONPath the token,
                          content_type?, header?, scheme?}   send it as a bearer/api-key
  type='form'           {username,password,login_url?}  -> handled by the browser path (qa/auth)

Also exposes `AuthScheme` (a small target-level descriptor) and helpers to infer
the scheme from a resolved identity or an OpenAPI `securitySchemes` block — used by
broken_auth to forge a *scheme-correct* invalid credential.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.models import Identity, Request


@dataclass
class AuthScheme:
    kind: str = "unknown"        # 'bearer' | 'cookie' | 'api_key' | 'basic' | 'none' | 'unknown'
    header: str = ""             # the credential header name (Authorization / X-API-Key / Cookie)
    cookie_name: str = ""        # the session cookie name, when kind == 'cookie'


def _dig(obj, path: str):
    """Extract a value by a dotted JSON path (e.g. 'data.access_token')."""
    cur = obj
    for part in (path or "").split("."):
        if not part:
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _find_token(obj):
    """Heuristic: locate a token-ish field in a JSON login response."""
    if isinstance(obj, dict):
        for k in ("access_token", "token", "jwt", "id_token", "accessToken", "authToken"):
            if isinstance(obj.get(k), str) and obj[k]:
                return obj[k]
        for v in obj.values():
            t = _find_token(v)
            if t:
                return t
    return None


def infer_form_type(cfg: dict) -> str:
    if cfg.get("type"):
        return str(cfg["type"]).lower()
    if cfg.get("token"):
        return "bearer"
    if cfg.get("key"):
        return "api_key"
    if cfg.get("headers"):
        return "header"
    if cfg.get("cookies"):
        return "session"
    if cfg.get("token_url"):
        return "token_exchange"
    return "form"   # username/password against a login page -> needs the browser


def needs_browser(cfg: dict) -> bool:
    return infer_form_type(cfg) == "form"


def resolve_identity(cfg: dict, base_url: str, http=None, log=print) -> Optional[Identity]:
    """Resolve a non-form auth config into an Identity. Returns None for form login
    (handled by the browser path) or on failure."""
    t = infer_form_type(cfg)
    name = cfg.get("name") or cfg.get("username") or "user"
    role = cfg.get("role", "user")
    owned = cfg.get("owned_resource_ids", {}) or {}

    def ident(headers=None, cookies=None):
        return Identity(name=name, role=role, headers=headers or {}, cookies=cookies or {},
                        owned_resource_ids=owned, description=cfg.get("description", ""))

    try:
        if t == "bearer":
            tok = cfg.get("token", "")
            scheme = cfg.get("scheme", "Bearer")
            return ident(headers={"Authorization": f"{scheme} {tok}".strip()})
        if t == "api_key":
            header = cfg.get("header", "X-API-Key")
            return ident(headers={header: cfg.get("key", "")})
        if t == "header":
            return ident(headers=dict(cfg.get("headers", {})))
        if t in ("session", "cookies"):
            return ident(cookies=dict(cfg.get("cookies", {})))
        if t == "token_exchange":
            if http is None:
                log("   token_exchange needs an http client; skipping")
                return None
            url = cfg["token_url"]
            if not url.startswith("http"):
                url = base_url.rstrip("/") + "/" + url.lstrip("/")
            ctype = cfg.get("content_type", "json")
            creds = cfg.get("creds") or {k: cfg[k] for k in ("username", "password") if k in cfg}
            req = Request(method="POST", url=url, body=creds, content_type=ctype, label="token-exchange")
            resp = http.send(req, None)
            if not resp.ok:
                log(f"   token_exchange to {url} failed ({resp.status})")
                return None
            tok = _dig(resp.body, cfg["token_path"]) if cfg.get("token_path") else _find_token(resp.body)
            if not tok:
                log("   token_exchange: no token found in the response")
                return None
            header = cfg.get("header", "Authorization")
            scheme = cfg.get("scheme", "Bearer")
            value = f"{scheme} {tok}".strip() if header.lower() == "authorization" else str(tok)
            return ident(headers={header: value})
    except Exception as e:
        log(f"   identity '{name}' adapter error: {e}")
        return None
    return None   # form -> browser path


def scheme_for_identity(idn: Identity) -> AuthScheme:
    """Infer the credential scheme from a resolved identity (for scheme-correct probes)."""
    for h in (idn.headers or {}):
        hl = h.lower()
        if hl == "authorization":
            return AuthScheme(kind="bearer", header=h)
        if hl in ("x-api-key", "api-key", "x-auth-token", "x-access-token"):
            return AuthScheme(kind="api_key", header=h)
    if idn.cookies:
        return AuthScheme(kind="cookie", header="Cookie",
                          cookie_name=next(iter(idn.cookies), ""))
    return AuthScheme(kind="unknown")


def scheme_from_spec(spec: dict) -> Optional[AuthScheme]:
    """Read components.securitySchemes (OpenAPI 3) to learn how the API authenticates."""
    comps = (spec or {}).get("components", {}) or {}
    schemes = comps.get("securitySchemes", {}) or {}
    for s in schemes.values():
        if not isinstance(s, dict):
            continue
        typ = str(s.get("type", "")).lower()
        if typ == "http" and str(s.get("scheme", "")).lower() == "bearer":
            return AuthScheme(kind="bearer", header="Authorization")
        if typ == "http" and str(s.get("scheme", "")).lower() == "basic":
            return AuthScheme(kind="basic", header="Authorization")
        if typ == "apikey" and str(s.get("in", "")).lower() == "header":
            return AuthScheme(kind="api_key", header=s.get("name", "X-API-Key"))
        if typ == "oauth2":
            return AuthScheme(kind="bearer", header="Authorization")
    return None
