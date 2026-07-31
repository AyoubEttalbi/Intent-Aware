"""
tests/test_credential_hygiene.py — credentials must never reach a log line,
the job store, or the /status payload.

No LLM, no browser, no network.

Background: many SPA logins render `<form method="get">` and authenticate from a
JS onClick handler. When qa.auth falls through to the Enter-key fallback, the
browser performs a NATIVE GET submit and the password lands in the URL as
`/login?email=...&password=...`. Every message qa.auth._verify builds flows into
the job log, which api/main.py keeps in full and the UI renders verbatim.
"""
from __future__ import annotations

import asyncio
import json

from agent.engine import SecurityEngine
from core.models import (Confidence, Endpoint, Evidence, Finding, Request, Response,
                         Severity, VulnClass, redact_finding_dict)
from qa.auth import _safe_url, _verify

LEAKY_URL = "https://app.example.com/login?email=alice%40example.com&password=hunter2"
SECRET = "hunter2"


class _FakePage:
    def __init__(self, url: str):
        self.url = url


class _FakeContext:
    def __init__(self, cookies=None):
        self._cookies = cookies or []

    async def cookies(self):
        return self._cookies


def _verify_msg(url: str, auth: dict, login_url: str, cookies=None) -> tuple[bool, str]:
    return asyncio.run(_verify(_FakePage(url), _FakeContext(cookies), auth, login_url))


def test_safe_url_strips_the_query_string():
    assert _safe_url(LEAKY_URL) == "https://app.example.com/login"
    assert SECRET not in _safe_url(LEAKY_URL)


def test_safe_url_tolerates_empty_and_query_free_input():
    assert _safe_url("") == ""
    assert _safe_url(None) == ""
    assert _safe_url("https://app.example.com/x") == "https://app.example.com/x"


def test_failure_message_does_not_leak_the_password():
    """The native-GET-submit case: still on /login, creds now in the URL."""
    ok, msg = _verify_msg(LEAKY_URL, {}, "https://app.example.com/login")
    assert ok is False
    assert SECRET not in msg
    assert "alice" not in msg


def test_success_by_explicit_url_does_not_leak_the_password():
    ok, msg = _verify_msg(LEAKY_URL, {"success_url_contains": "login"},
                          "https://app.example.com/login")
    assert ok is True
    assert SECRET not in msg


def test_success_by_navigation_does_not_leak_the_password():
    ok, msg = _verify_msg("https://app.example.com/dashboard?token=s3cret",
                          {}, "https://app.example.com/login")
    assert ok is True
    assert "s3cret" not in msg


def test_cookie_success_reports_only_the_name():
    ok, msg = _verify_msg("https://app.example.com/login", {},
                          "https://app.example.com/login",
                          cookies=[{"name": "gcrm_access", "value": "SUPERSECRETVALUE"}])
    assert ok is True
    assert "gcrm_access" in msg
    assert "SUPERSECRETVALUE" not in msg


# --- persisted evidence (Job.results / Bug.reproduction_json / GET /status) ---

SESSION = "gcrm_access=eyJhbGciOi.SESSIONSECRET"
BEARER = "Bearer eyJhbGciOi.TOKENSECRET"


def _finding_with_credentials() -> Finding:
    req = Request(method="GET", url="https://app.example.com/api/notes/2",
                  headers={"Cookie": SESSION, "Authorization": BEARER,
                           "Accept": "application/json"})
    resp = Response(status=200, headers={"Set-Cookie": SESSION,
                                         "Content-Type": "application/json"},
                    body={"id": 2, "owner": "bob"})
    base = Request(method="GET", url="https://app.example.com/api/notes/1",
                   headers={"X-Api-Key": "SECRETAPIKEY"})
    return Finding(
        vuln_class=VulnClass.IDOR, severity=Severity.HIGH, confidence=Confidence.HIGH,
        title="IDOR", endpoint_key="GET /api/notes/{id}",
        evidence=Evidence(request=req, response=resp, baseline_request=base),
        source="idor")


def test_engine_finding_dict_masks_request_credentials():
    d = SecurityEngine._finding_dict(_finding_with_credentials())
    blob = json.dumps(d)
    for secret in ("SESSIONSECRET", "TOKENSECRET", "SECRETAPIKEY"):
        assert secret not in blob, f"{secret} leaked into the persisted finding"


def test_redaction_keeps_header_names_and_non_credential_values():
    d = redact_finding_dict(SecurityEngine._finding_dict(_finding_with_credentials()))
    headers = d["evidence"]["request"]["headers"]
    assert set(headers) == {"Cookie", "Authorization", "Accept"}, "names must survive"
    assert headers["Accept"] == "application/json", "non-credential values must survive"
    assert headers["Cookie"] == "<redacted>"


def test_redaction_covers_response_set_cookie():
    d = SecurityEngine._finding_dict(_finding_with_credentials())
    assert d["evidence"]["response"]["headers"]["Set-Cookie"] == "<redacted>"
    assert d["evidence"]["response"]["headers"]["Content-Type"] == "application/json"


def test_redaction_preserves_the_finding_body_evidence():
    """Redaction must not blank the actual proof of the bug."""
    d = SecurityEngine._finding_dict(_finding_with_credentials())
    assert d["evidence"]["response"]["body"] == {"id": 2, "owner": "bob"}
    assert d["vuln_class"] == "idor"


def test_status_payload_masks_the_captured_session_cookies():
    """`results.context.auth_cookies` is a LIVE session on the target, captured
    at login. It must not be served by the unauthenticated /status endpoint."""
    from api.main import _public_results

    stored = {"grade": "C",
              "context": {"target": "https://app.example.com",
                          "auth_cookies": {"gcrm_access": "eyJhbGciOi.LIVESESSION",
                                           "gcrm_refresh": "REFRESHSECRET"},
                          "auth_role": "admin"}}
    public = _public_results(stored)

    blob = json.dumps(public)
    assert "LIVESESSION" not in blob and "REFRESHSECRET" not in blob
    # Names stay so the report can still say WHICH cookies were held.
    assert set(public["context"]["auth_cookies"]) == {"gcrm_access", "gcrm_refresh"}
    assert public["context"]["auth_role"] == "admin"
    assert public["grade"] == "C"


def test_status_masking_does_not_mutate_the_stored_row():
    """resume_from_job_id reads the cookies back out of the stored results, so
    masking must be copy-on-write, not in-place."""
    from api.main import _public_results

    stored = {"context": {"auth_cookies": {"sid": "REALVALUE"}}}
    _public_results(stored)
    assert stored["context"]["auth_cookies"]["sid"] == "REALVALUE", (
        "masking mutated the stored row — server-side resume would break"
    )


def test_public_results_tolerates_missing_or_odd_shapes():
    from api.main import _public_results

    assert _public_results(None) is None
    assert _public_results({"grade": "A"}) == {"grade": "A"}
    assert _public_results({"context": {}}) == {"context": {}}
    assert _public_results({"context": "not-a-dict"}) == {"context": "not-a-dict"}


def test_redaction_is_safe_on_qa_findings_without_request_evidence():
    f = Finding(vuln_class=VulnClass.BROKEN_LINK, severity=Severity.LOW,
                confidence=Confidence.HIGH, title="dead link", endpoint_key="/x",
                evidence=Evidence(page_url="https://app.example.com/x",
                                  steps=["Open /x"]), source="qa.crawler")
    d = SecurityEngine._finding_dict(f)
    assert d["evidence"]["page_url"] == "https://app.example.com/x"
    assert d["evidence"]["request"] is None
