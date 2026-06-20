"""
sqli — SQL injection (error-based).

Effect oracle: inject SQL metacharacters into each parameter; if the response
body leaks a database error signature, the input reached a SQL engine unescaped.
(Low false-positive: a 404/200 with no SQL error does NOT flag — e.g. target_app,
which has no database, correctly yields nothing.)

NOTE: blind/time-based SQLi is a planned follow-up (disabled here to keep runs fast).
"""
from __future__ import annotations

from typing import List

from attacks.base import AttackPlugin, AttackContext, register
from attacks.inject import injection_points, build_injection_request, injectable_method
from attacks.payloads import SQLI_PROBES, SQL_ERROR_SIGNATURES, SQLI_TIME_PROBES, SQLI_TIME_THRESHOLD_MS
from core.models import Finding, Evidence, VulnClass, Severity, Confidence

MAX_POINTS = 6
MAX_PROBES = 4


@register
class SqliPlugin(AttackPlugin):
    vuln_class = VulnClass.SQLI
    name = "sqli"
    identity_agnostic = True   # injection behaviour doesn't depend on who is logged in

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        if not injectable_method(ep, ctx.allow_writes):
            return []
        anon = ctx.acting()   # the identity we act as (anonymous or authenticated)
        for kind, name in injection_points(ep, ctx.allow_writes)[:MAX_POINTS]:
            for payload in SQLI_PROBES[:MAX_PROBES]:
                req = build_injection_request(ctx, kind, name, payload, label=f"sqli:{kind}:{name}")
                r = ctx.send(req, anon)
                hay = r.haystack().lower()
                sig = next((s for s in SQL_ERROR_SIGNATURES if s in hay), None)
                if sig:
                    ctx.log(f"sqli: {ep.key} param {name} leaked SQL error '{sig}'")
                    return [Finding(
                        vuln_class=self.vuln_class,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        title=f"SQL injection on {ep.key} (parameter `{name}`)",
                        endpoint_key=ep.key,
                        identity=anon.name,
                        detail=(f"Injecting `{payload}` into `{name}` triggered a database error "
                                f"signature ('{sig}') in the response, proving the value reaches "
                                f"the SQL layer without proper escaping."),
                        evidence=Evidence(request=req, response=r, note=f"SQL error signature: {sig}"),
                        source=self.name,
                    )]
        # No error-based hit → try blind / time-based (only escalates when a probe is truly slow).
        return self._time_based(ctx, anon)

    def _time_based(self, ctx: AttackContext, actor) -> List[Finding]:
        ep = ctx.endpoint
        for kind, name in injection_points(ep, ctx.allow_writes)[:MAX_POINTS]:
            c1 = ctx.send(build_injection_request(ctx, kind, name, "1", label=f"time-control:{name}"), actor)
            for payload in SQLI_TIME_PROBES:
                t1 = ctx.send(build_injection_request(ctx, kind, name, payload, label=f"time:{name}"), actor)
                if t1.latency_ms >= SQLI_TIME_THRESHOLD_MS and t1.latency_ms > c1.latency_ms + 3000:
                    # Confirm on a re-test to rule out a one-off network fluke.
                    c2 = ctx.send(build_injection_request(ctx, kind, name, "1", label="time-control2"), actor)
                    t2 = ctx.send(build_injection_request(ctx, kind, name, payload, label="time2"), actor)
                    if t2.latency_ms >= SQLI_TIME_THRESHOLD_MS and t2.latency_ms > c2.latency_ms + 3000:
                        ctx.log(f"sqli: {ep.key} param {name} time-based blind delay confirmed")
                        return [Finding(
                            vuln_class=self.vuln_class, severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                            title=f"Blind SQL injection (time-based) on {ep.key} (parameter `{name}`)",
                            endpoint_key=ep.key, identity=actor.name,
                            detail=(f"A time-delay payload in `{name}` made the server pause "
                                    f"~{t1.latency_ms / 1000:.1f}s (control ~{c1.latency_ms:.0f}ms), reproduced "
                                    f"on re-test — the input is executed by the database."),
                            evidence=Evidence(
                                request=build_injection_request(ctx, kind, name, payload, label="time-based"),
                                response=t1, baseline_request=build_injection_request(ctx, kind, name, "1", label="control"),
                                baseline_response=c1, note="time-based blind SQLi (delay reproduced)"),
                            source=self.name)]
        return []
