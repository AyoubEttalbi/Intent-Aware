"""
broken_auth — endpoints that check for the PRESENCE of a credential but not its
VALIDITY, or that are reachable with no credentials at all.

Two effect oracles, both differential and low-false-positive:
  * anonymous access  — an endpoint that needs auth returns real data to anon.
  * invalid credential — anon is rejected/redirected, but a clearly-INVALID
    credential (forged in the scheme's real header: bearer / cookie / api-key) is
    ACCEPTED with a real (non-login) body.

"auth required" is derived BEHAVIOURALLY (authed identity gets data that anon does
not), so it works on spec-less apps too — not only when an OpenAPI `security` block
happens to declare it.
"""
from __future__ import annotations

import json
from typing import List

from attacks.base import AttackPlugin, AttackContext, register
from attacks.payloads import INVALID_TOKENS
from core.models import Request, Finding, Evidence, VulnClass, Severity, Confidence


def is_login_page(resp) -> bool:
    """A 200 that is actually a redirect-to-login / login form is NOT 'accessible'."""
    if resp is None:
        return False
    fu = (resp.final_url or "").lower()
    loc = (resp.redirect_location or "").lower()
    if any(s in fu or s in loc for s in ("/login", "/signin", "/sign-in", "/auth/", "/account/login")):
        return True
    txt = resp.haystack().lower()[:4000] if hasattr(resp, "haystack") else ""
    has_pw = ('type="password"' in txt or "type='password'" in txt or 'name="password"' in txt)
    return has_pw and ("<form" in txt or "login" in txt or "sign in" in txt)


def _same_body(a, b) -> bool:
    if a is None or b is None:
        return False
    try:
        sa, sb = json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True)
        return sa == sb and len(sa) > 2
    except Exception:
        return bool(a) and str(a) == str(b)


def _nonempty(body) -> bool:
    return body not in (None, "", {}, [])


def invalid_credentials(scheme) -> list:
    """Header dicts carrying a clearly-invalid credential. Always tries a bogus bearer
    (covers per-endpoint Authorization checks) plus the target's own scheme."""
    creds = [{"Authorization": tok} for tok in INVALID_TOKENS]
    kind = getattr(scheme, "kind", None)
    header = getattr(scheme, "header", "") or ""
    if kind == "cookie":
        name = getattr(scheme, "cookie_name", "") or "session"
        creds.append({"Cookie": f"{name}=qa_invalid_session_value"})
    elif kind == "api_key" and header:
        creds.append({header: "qa-invalid-api-key"})
    else:
        creds.append({"X-API-Key": "qa-invalid-api-key"})
    return creds


@register
class BrokenAuthPlugin(AttackPlugin):
    vuln_class = VulnClass.BROKEN_AUTH
    name = "broken_auth"
    identity_agnostic = True   # manages credentials internally; run once

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        anon = ctx.anon()
        url = ctx.url()

        base_req = Request(method=ep.method, url=url, strip_auth=True, label="no-credentials")
        base = ctx.send(base_req, anon)
        base_is_login = is_login_page(base)

        # A logged-in reference response (if available) — used to infer auth behaviourally.
        authed = next((i for i in ctx.identities if not i.is_anonymous), None)
        authed_resp = ctx.send(Request(ep.method, url, label=f"as {authed.name}"), authed) if authed else None

        auth_required = ep.auth_required
        if (not auth_required and authed_resp is not None and authed_resp.ok
                and _nonempty(authed_resp.body) and not is_login_page(authed_resp)):
            anon_blocked = (base.status in (401, 403) or base_is_login or base.redirected or not base.ok)
            if anon_blocked and not _same_body(base.body, authed_resp.body):
                auth_required = True   # authed gets data anon cannot → endpoint is gated

        # Oracle 1: anonymous access works on an auth-gated endpoint (anon got REAL data).
        if auth_required and base.ok and not base_is_login and _nonempty(base.body):
            return [Finding(
                vuln_class=VulnClass.AUTHZ, severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                title=f"Broken access control on {ep.key} — auth required but anonymous access works",
                endpoint_key=ep.key, identity="anon",
                detail=(f"This endpoint requires authentication, yet an anonymous request "
                        f"(no credentials) returns {base.status} with data."),
                evidence=Evidence(request=base_req, response=base,
                                  note="anonymous access to an auth-required endpoint"),
                source=self.name)]

        gated = base.status in (401, 403) or base_is_login or (
            base.redirected and "login" in (base.redirect_location or "").lower())
        if not gated:
            return []  # public, or ambiguous (404/5xx) — not a broken-auth signal

        # Oracle 2: a clearly-invalid credential is accepted.
        for cred in invalid_credentials(ctx.auth_scheme):
            req = Request(method=ep.method, url=url, headers=dict(cred), label="invalid-credential")
            r = ctx.send(req, anon)
            if r.ok and not is_login_page(r) and _nonempty(r.body):
                ctx.log(f"broken_auth: {ep.key} accepts an invalid credential ({r.status})")
                return [Finding(
                    vuln_class=self.vuln_class, severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    title=f"Broken authentication on {ep.key}",
                    endpoint_key=ep.key, identity="anon",
                    detail=(f"Requests with no credentials are rejected ({base.status}), but a "
                            f"clearly-invalid credential is ACCEPTED ({r.status}) and returns data. "
                            f"The endpoint checks that a credential is present, not that it is valid."),
                    evidence=Evidence(request=req, response=r,
                                      baseline_request=base_req, baseline_response=base,
                                      note="no-credentials baseline (rejected) vs invalid-credential (accepted)"),
                    source=self.name)]
        return []
