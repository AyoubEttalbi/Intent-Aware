"""
path_traversal — directory traversal / local file read.

Effect oracle: inject `../`-style payloads into parameters; flag only if the
response leaks a known system-file signature (e.g. /etc/passwd contents).
"""
from __future__ import annotations

from typing import List

from attacks.base import AttackPlugin, AttackContext, register
from attacks.inject import injection_points, build_injection_request, injectable_method
from attacks.payloads import PATH_TRAVERSAL_PROBES, TRAVERSAL_SIGNATURES
from core.models import Finding, Evidence, VulnClass, Severity, Confidence

MAX_POINTS = 6


@register
class PathTraversalPlugin(AttackPlugin):
    vuln_class = VulnClass.PATH_TRAVERSAL
    name = "path_traversal"
    identity_agnostic = True   # injection behaviour doesn't depend on who is logged in

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        if not injectable_method(ep, ctx.allow_writes):
            return []
        anon = ctx.acting()   # the identity we act as (anonymous or authenticated)
        for kind, name in injection_points(ep, ctx.allow_writes)[:MAX_POINTS]:
            for payload in PATH_TRAVERSAL_PROBES:
                req = build_injection_request(ctx, kind, name, payload, label=f"traversal:{kind}:{name}")
                r = ctx.send(req, anon)
                hay = r.haystack()
                sig = next((s for s in TRAVERSAL_SIGNATURES if s in hay), None)
                if sig:
                    ctx.log(f"path_traversal: {ep.key} param {name} read a system file")
                    return [Finding(
                        vuln_class=self.vuln_class,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        title=f"Path traversal on {ep.key} (parameter `{name}`)",
                        endpoint_key=ep.key,
                        identity=anon.name,
                        detail=(f"Injecting `{payload}` into `{name}` returned the contents of a "
                                f"system file (signature '{sig}'), so the parameter is used to build "
                                f"a filesystem path without sanitisation."),
                        evidence=Evidence(request=req, response=r, note=f"file signature: {sig}"),
                        source=self.name,
                    )]
        return []
