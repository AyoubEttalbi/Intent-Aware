"""
xss — reflected cross-site scripting.

Effect oracle: inject a uniquely-marked HTML payload; flag only if it comes back
UN-encoded in an HTML response (so it would actually execute). JSON APIs that
echo the string safely encoded are NOT flagged — keeps false positives low.
(Stored-XSS read-back is a planned follow-up once write+read chaining lands.)
"""
from __future__ import annotations

from typing import List

from attacks.base import AttackPlugin, AttackContext, register
from attacks.inject import injection_points, build_injection_request, injectable_method
from attacks.payloads import xss_probes
from core.models import Finding, Evidence, VulnClass, Severity, Confidence

MARKER = "QAxss9173"
MAX_POINTS = 6


@register
class XssPlugin(AttackPlugin):
    vuln_class = VulnClass.XSS
    name = "xss"
    identity_agnostic = True   # injection behaviour doesn't depend on who is logged in

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        if not injectable_method(ep, ctx.allow_writes):
            return []
        anon = ctx.acting()   # the identity we act as (anonymous or authenticated)
        for kind, name in injection_points(ep, ctx.allow_writes)[:MAX_POINTS]:
            for payload in xss_probes(MARKER):
                req = build_injection_request(ctx, kind, name, payload, label=f"xss:{kind}:{name}")
                r = ctx.send(req, anon)
                ctype = str(r.headers.get("content-type", "")).lower()
                if "html" in ctype and payload in r.haystack():
                    ctx.log(f"xss: {ep.key} reflects payload unencoded in {name}")
                    return [Finding(
                        vuln_class=self.vuln_class,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title=f"Reflected XSS on {ep.key} (parameter `{name}`)",
                        endpoint_key=ep.key,
                        identity=anon.name,
                        detail=(f"The payload injected into `{name}` is reflected un-encoded inside "
                                f"an HTML response, so an attacker-controlled script would execute "
                                f"in a victim's browser."),
                        evidence=Evidence(request=req, response=r, note="unencoded reflection in HTML response"),
                        source=self.name,
                    )]
        return []
