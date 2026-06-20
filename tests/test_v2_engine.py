"""
tests/test_v2_engine.py — regression gate for the live v2 SecurityEngine.

No LLM, no browser: the planner/explainer are stubbed and identities are logged
in directly (cookies) / via the token-exchange adapter (bearer JWT). Asserts every
planted bug in target_app is caught with the right vuln class, that the read-only
default suppresses mutating probes, and that the scope guards hold — with NO false
positives on clean classes.

The full matrix is run ONCE (session-scoped) and shared across assertions; the
time-based SQLi/command-injection probes are the slow part, so we don't repeat them.
"""
from __future__ import annotations

import pytest

from agent.engine import SecurityEngine
from core.models import VulnClass


def _identities(target):
    admin_cookies = target.login("alice", "password123")
    user_cookies = target.login("bob", "password456")
    return [
        {"name": "admin", "role": "admin", "cookies": admin_cookies,
         "owned_resource_ids": {"notes": ["1"], "users": ["1"]}},
        {"name": "user", "role": "user", "cookies": user_cookies,
         "owned_resource_ids": {"notes": ["2"], "users": ["2"]}},
    ]


def _bearer_identity():
    # Exercises the token_exchange auth adapter end-to-end (POST creds -> JWT -> bearer).
    return [{"type": "token_exchange", "name": "jwtuser", "role": "user",
             "token_url": "/api/jwt/login", "content_type": "form",
             "creds": {"username": "alice", "password": "password123"}, "token_path": "token"}]


def _run(target, allow_writes: bool, with_bearer: bool):
    eng = SecurityEngine(
        spec_url=target.spec_url,
        description="A small app. Users should only see their own data; admins manage users.",
        base_url=target.base_url, crawl_ui=False,
        identities=_identities(target),
        auth_identities=_bearer_identity() if with_bearer else None,
        allow_writes=allow_writes,
        max_requests=4000,   # generous so every planted fixture is reached (real runs cap lower)
    )
    eng.planner.plan = lambda *a, **k: {}
    eng.explainer.enrich = lambda *a, **k: None
    return eng.run()


@pytest.fixture(scope="session")
def full_result(target_app):
    return _run(target_app, allow_writes=True, with_bearer=True)


@pytest.fixture(scope="session")
def readonly_result(target_app):
    return _run(target_app, allow_writes=False, with_bearer=False)


# --- the headline contract: every planted bug is caught -----------------------
def test_all_planted_bugs_caught(full_result):
    classes = {f["vuln_class"] for f in full_result["findings"]}
    expected = {
        VulnClass.IDOR.value, VulnClass.BROKEN_AUTH.value, VulnClass.MASS_ASSIGNMENT.value,
        VulnClass.SQLI.value, VulnClass.AUTHZ.value, VulnClass.XSS.value,
        VulnClass.SSTI.value, VulnClass.COMMAND_INJECTION.value, VulnClass.OPEN_REDIRECT.value,
        VulnClass.CORS.value, VulnClass.DATA_EXPOSURE.value, VulnClass.JWT.value,
    }
    missing = expected - classes
    assert not missing, f"planted bugs NOT caught: {missing}"


def test_authz_covers_vertical_and_horizontal(full_result):
    authz = [f for f in full_result["findings"] if f["vuln_class"] == VulnClass.AUTHZ.value]
    where = " ".join(f["endpoint_key"] for f in authz)
    assert "/admin/users" in where, f"vertical privilege-escalation missing ({where})"
    assert "/notes/" in where, f"horizontal object-level authz missing ({where})"


def test_graphql_introspection_caught(full_result):
    gql = [f for f in full_result["findings"] if f["source"] == "graphql_introspection"]
    assert gql, "GraphQL introspection-enabled not caught"
    assert all("graphql" in f["endpoint_key"].lower() for f in gql)


def test_jwt_finding_is_on_the_jwt_endpoint_not_broken_auth(full_result):
    """The JWT plugin must NOT fire on /orders (which accepts any token — that's broken_auth)."""
    jwt = [f for f in full_result["findings"] if f["vuln_class"] == VulnClass.JWT.value]
    assert jwt, "JWT signature flaw not caught"
    assert all("/api/jwt/me" in f["endpoint_key"] for f in jwt), \
        f"JWT false-positive on a non-JWT endpoint: {[f['endpoint_key'] for f in jwt]}"


def test_zero_false_positives_on_clean_classes(full_result):
    classes = [f["vuln_class"] for f in full_result["findings"]]
    # target_app has no path traversal and no SSRF/CSRF endpoints.
    assert VulnClass.PATH_TRAVERSAL.value not in classes
    assert VulnClass.SSRF.value not in classes
    # Every API finding is HIGH confidence from a deterministic oracle source.
    for f in full_result["findings"]:
        assert f["confidence"] == "high", f"non-high-confidence finding leaked: {f['title']}"
        assert f["source"], f"finding without a source plugin: {f['title']}"


def test_grade_reflects_critical_findings(full_result):
    assert full_result["grade"] in ("F", "D"), f"expected failing grade, got {full_result['grade']}"
    assert full_result["score"] < 60


# --- safety guards ------------------------------------------------------------
def test_read_only_default_skips_mutating_probes(readonly_result):
    classes = {f["vuln_class"] for f in readonly_result["findings"]}
    sources = {f["source"] for f in readonly_result["findings"]}
    assert VulnClass.MASS_ASSIGNMENT.value not in classes, "mass assignment ran without allow_writes"
    assert "stored_xss" not in sources, "stored_xss persisted a payload without allow_writes"
    # read-only detectors still work
    assert VulnClass.IDOR.value in classes
    assert VulnClass.BROKEN_AUTH.value in classes
    assert VulnClass.SQLI.value in classes
    assert VulnClass.AUTHZ.value in classes


def test_spec_url_local_file_read_blocked():
    from extractors.parser import OpenAPIParser
    with pytest.raises(ValueError):
        OpenAPIParser().load_spec("/etc/passwd")
    with pytest.raises(ValueError):
        OpenAPIParser().load_spec("../.env")


def test_spec_url_ssrf_host_blocked():
    from extractors.parser import OpenAPIParser
    p = OpenAPIParser(allowed_hosts={"127.0.0.1"})
    with pytest.raises(ValueError):
        p.load_spec("http://169.254.169.254/latest/meta-data/")


# --- flexibility: works without being handed the exact spec URL ---------------
def test_spec_auto_discovery(target_app):
    """With NO spec_url, the engine probes well-known locations and finds the surface."""
    eng = SecurityEngine(spec_url="", description="", base_url=target_app.base_url, crawl_ui=False)
    spec = eng._discover_spec()
    assert spec and spec.get("paths"), "auto-discovery failed to locate the OpenAPI spec"
    assert eng.spec_url.endswith("/openapi.json")


def test_swagger2_basepath_and_body():
    """Swagger 2.0: basePath is applied and an `in: body` param becomes the body schema."""
    from core.surface import build_surface
    v2 = {
        "swagger": "2.0",
        "basePath": "/api/v1",
        "definitions": {"User": {"type": "object", "properties": {"name": {"type": "string"}},
                                 "required": ["name"]}},
        "paths": {
            "/users": {
                "post": {
                    "parameters": [{"in": "body", "name": "body", "required": True,
                                    "schema": {"$ref": "#/definitions/User"}}],
                    "responses": {"200": {}},
                }
            }
        },
    }
    eps = build_surface(v2, "http://x")
    assert len(eps) == 1
    ep = eps[0]
    assert ep.path_template == "/api/v1/users", ep.path_template       # basePath applied
    assert isinstance(ep.body_schema, dict) and "name" in (ep.body_schema.get("properties") or {})


def test_login_page_guard():
    """A redirect-to-login response must not read as 'accessible' (no broken-auth FP)."""
    from attacks.broken_auth import is_login_page
    from core.models import Response
    login = Response(status=200, text='<form><input type="password" name="password"></form>',
                     body='<form><input type="password" name="password"></form>',
                     final_url="http://x/login")
    assert is_login_page(login) is True
    data = Response(status=200, body={"id": 1, "email": "a@b.c"}, final_url="http://x/users/1")
    assert is_login_page(data) is False


def test_bearer_and_apikey_adapters_are_browserless():
    from core.auth_adapters import resolve_identity, needs_browser
    b = resolve_identity({"type": "bearer", "token": "T", "name": "u"}, "http://x")
    assert b and b.headers.get("Authorization") == "Bearer T" and not b.is_anonymous
    k = resolve_identity({"type": "api_key", "key": "K", "header": "X-API-Key"}, "http://x")
    assert k and k.headers.get("X-API-Key") == "K"
    assert needs_browser({"username": "a", "password": "b"}) is True
    assert needs_browser({"type": "bearer", "token": "T"}) is False
