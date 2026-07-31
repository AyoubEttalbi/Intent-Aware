"""
authz_matrix._vertical must be differential — an admin-LOOKING path that anon can
already read is a public endpoint, not a privilege escalation.

Regression origin: Phase 7 (first real third-party target, OWASP Juice Shop) produced
two CRITICAL/HIGH false positives on `/rest/admin/application-version` and
`/rest/admin/application-configuration`. Both are public by design — anon receives a
byte-identical response — so no privilege boundary is crossed.

target_app could never surface this: its only admin path (`/admin/users`) checks login
but not role, so anon is always redirected (303). Every fixture case has anon blocked,
which is exactly the case the missing baseline handles correctly.

No LLM, no browser, no network — pure oracle logic.
"""
from __future__ import annotations

from attacks.authz_matrix import AuthzMatrixPlugin
from attacks.base import AttackContext
from core.models import Endpoint, Identity, Response


def _ctx(endpoint, responder):
    """Build an AttackContext whose send() is driven by `responder(identity)`."""
    # Identity.is_anonymous is derived: no headers and no cookies.
    anon = Identity(name="anon")
    jim = Identity(name="jim", role="user", headers={"Authorization": "Bearer jim-token"})
    sent = []

    def send(req, identity=None):
        who = identity.name if identity is not None else "anon"
        sent.append(who)
        return responder(who)

    ctx = AttackContext(endpoint=endpoint, identities=[anon, jim], send=send)
    return ctx, sent


def _endpoint(path="/rest/admin/application-configuration"):
    return Endpoint(method="GET", path_template=path, base_url="http://127.0.0.1:3000")


def test_public_admin_path_is_not_privilege_escalation():
    """Anon gets the SAME body as the non-admin -> public endpoint, no escalation."""
    body = {"config": {"application": {"name": "OWASP Juice Shop"}}}

    def responder(who):
        return Response(status=200, body=body)          # everyone sees the same thing

    ctx, _ = _ctx(_endpoint(), responder)
    findings = AuthzMatrixPlugin()._vertical(ctx, ctx.authed())
    assert findings == [], (
        "public admin-looking endpoint must not be reported as privilege escalation; "
        f"got: {[f.title for f in findings]}"
    )


def test_anon_blocked_but_non_admin_allowed_is_still_caught():
    """The target_app shape: anon redirected, non-admin gets data -> REAL escalation."""
    def responder(who):
        if who == "anon":
            return Response(status=303, body="")        # redirect to login
        return Response(status=200, body={"users": ["alice", "bob"]})

    ctx, _ = _ctx(_endpoint("/admin/users"), responder)
    findings = AuthzMatrixPlugin()._vertical(ctx, ctx.authed())
    assert len(findings) == 1, "real vertical escalation must still be caught"
    assert "Privilege escalation" in findings[0].title


def test_anon_gets_different_content_is_still_caught():
    """Anon reaches the path but sees a login page; the user sees real data -> escalation."""
    def responder(who):
        if who == "anon":
            return Response(status=200, body="<html>Please log in</html>")
        return Response(status=200, body={"users": ["alice", "bob"]})

    ctx, _ = _ctx(_endpoint("/admin/users"), responder)
    findings = AuthzMatrixPlugin()._vertical(ctx, ctx.authed())
    assert len(findings) == 1, (
        "a 200 login page for anon is not the same resource — this is still escalation"
    )
