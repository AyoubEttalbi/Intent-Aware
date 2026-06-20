"""
attacks/web_extra.py — additional OWASP-class detectors, each with an EFFECT oracle
tuned for near-zero false positives:

  cors_misconfig    — reflects an arbitrary Origin (esp. with credentials).
  security_headers  — passive: site is missing key hardening headers (reported once).
  open_redirect     — a redirect param sends the browser to an attacker host.
  ssti              — a template expression is evaluated server-side (uncommon product).
  command_injection — a shell metacharacter payload causes a reproducible time delay.
  secrets_exposure  — a response leaks a high-signal secret (AWS/Stripe/private key/…).
"""
from __future__ import annotations

import threading
from typing import List

from attacks.base import AttackPlugin, AttackContext, register
from attacks.inject import injection_points, build_injection_request, injectable_method
from attacks.payloads import (
    SSTI_PROBES, SSTI_EXPECTED, CMD_TIME_PROBES, CMD_TIME_THRESHOLD_MS,
    OPEN_REDIRECT_PARAMS, OPEN_REDIRECT_PAYLOADS, OPEN_REDIRECT_MARK_HOST,
    CORS_EVIL_ORIGIN, SECRET_PATTERNS,
)
from core.models import Request, Finding, Evidence, VulnClass, Severity, Confidence
from urllib.parse import urlparse, quote

MAX_POINTS = 6


# ---------------------------------------------------------------------------
@register
class CorsMisconfigPlugin(AttackPlugin):
    vuln_class = VulnClass.CORS
    name = "cors_misconfig"
    identity_agnostic = True

    def applies_to(self, ep) -> bool:
        return ep.method == "GET"

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        req = Request("GET", ctx.url(), headers={"Origin": CORS_EVIL_ORIGIN}, label="cors-probe")
        r = ctx.send(req, ctx.anon())
        if r.status == 0:
            return []
        h = {k.lower(): str(v) for k, v in (r.headers or {}).items()}
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "").lower() == "true"
        reflects = acao == CORS_EVIL_ORIGIN
        wildcard_creds = acao == "*" and acac
        if reflects or wildcard_creds:
            detail = (f"The endpoint reflects an arbitrary `Origin` ({CORS_EVIL_ORIGIN}) in "
                      f"Access-Control-Allow-Origin"
                      + (" with Access-Control-Allow-Credentials: true" if acac else "")
                      + ". A malicious site can read this endpoint's responses on behalf of a logged-in user.")
            return [Finding(
                vuln_class=self.vuln_class,
                severity=Severity.HIGH if (reflects and acac) else Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title=f"CORS misconfiguration on {ep.key}",
                endpoint_key=ep.key, identity="anon",
                detail=detail, evidence=Evidence(request=req, response=r, note=f"ACAO={acao} ACAC={acac}"),
                source=self.name)]
        return []


# ---------------------------------------------------------------------------
@register
class SecurityHeadersPlugin(AttackPlugin):
    vuln_class = VulnClass.SECURITY_HEADERS
    name = "security_headers"
    identity_agnostic = True

    def __init__(self):
        self._done = False
        self._lock = threading.Lock()

    def applies_to(self, ep) -> bool:
        return ep.method == "GET"

    def run(self, ctx: AttackContext) -> List[Finding]:
        with self._lock:        # report once for the whole site, not per endpoint
            if self._done:
                return []
            self._done = True
        r = ctx.send(Request("GET", ctx.url(), label="headers"), ctx.anon())
        if r.status == 0 or not r.headers:
            return []
        h = {k.lower(): str(v) for k, v in r.headers.items()}
        missing = []
        if "content-security-policy" not in h:
            missing.append("Content-Security-Policy (defence-in-depth against XSS/injection)")
        if "x-content-type-options" not in h:
            missing.append("X-Content-Type-Options: nosniff")
        if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
            missing.append("X-Frame-Options / CSP frame-ancestors (clickjacking)")
        if urlparse(ctx.endpoint.base_url).scheme == "https" and "strict-transport-security" not in h:
            missing.append("Strict-Transport-Security (HSTS)")
        if not missing:
            return []
        return [Finding(
            vuln_class=self.vuln_class, severity=Severity.LOW, confidence=Confidence.HIGH,
            title="Missing HTTP security headers", endpoint_key=ctx.endpoint.base_url, identity="anon",
            detail="The site is missing recommended hardening headers: " + "; ".join(missing) + ".",
            evidence=Evidence(request=Request("GET", ctx.url()), response=r,
                              note="headers absent on the main response"),
            source=self.name)]


# ---------------------------------------------------------------------------
@register
class OpenRedirectPlugin(AttackPlugin):
    vuln_class = VulnClass.OPEN_REDIRECT
    name = "open_redirect"
    identity_agnostic = True

    def applies_to(self, ep) -> bool:
        names = {str(p.get("name", "")).lower() for p in ep.query_params}
        names |= {str(p.get("name", "")).lower() for p in ep.path_params}
        return ep.method == "GET" and bool(names & OPEN_REDIRECT_PARAMS)

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        targets = [p.get("name") for p in (ep.query_params + ep.path_params)
                   if str(p.get("name", "")).lower() in OPEN_REDIRECT_PARAMS]
        for name in targets:
            for payload in OPEN_REDIRECT_PAYLOADS:
                # place the payload in the redirect param, keep everything else valid
                if name in {p.get("name") for p in ep.path_params}:
                    url = ctx.url(**{name: quote(payload, safe="")})
                else:
                    base = ctx.url()
                    sep = "&" if "?" in base else "?"
                    url = f"{base}{sep}{name}={quote(payload, safe='')}"
                r = ctx.send(Request("GET", url, label=f"open-redirect:{name}"), ctx.anon())
                loc = str((r.headers or {}).get("location", "")) or r.redirect_location
                if r.redirected and OPEN_REDIRECT_MARK_HOST in (loc or "") and \
                        (urlparse(loc).hostname or "").endswith(OPEN_REDIRECT_MARK_HOST):
                    return [Finding(
                        vuln_class=self.vuln_class, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                        title=f"Open redirect on {ep.key} (parameter `{name}`)",
                        endpoint_key=ep.key, identity="anon",
                        detail=(f"The `{name}` parameter controls a redirect target without validation: "
                                f"a request was 3xx-redirected to the attacker-controlled host "
                                f"{OPEN_REDIRECT_MARK_HOST}. Useful for phishing / OAuth token theft."),
                        evidence=Evidence(request=Request("GET", url, label=name), response=r,
                                          note=f"Location: {loc}"),
                        source=self.name)]
        return []


# ---------------------------------------------------------------------------
@register
class SstiPlugin(AttackPlugin):
    vuln_class = VulnClass.SSTI
    name = "ssti"
    identity_agnostic = True

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        if not injectable_method(ep, ctx.allow_writes):
            return []
        for kind, name in injection_points(ep, ctx.allow_writes)[:MAX_POINTS]:
            for payload in SSTI_PROBES:
                req = build_injection_request(ctx, kind, name, payload, label=f"ssti:{kind}:{name}")
                r = ctx.send(req, ctx.anon())
                hay = r.haystack()
                # evaluated result present AND the raw expression NOT echoed back verbatim
                if SSTI_EXPECTED in hay and payload not in hay:
                    return [Finding(
                        vuln_class=self.vuln_class, severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                        title=f"Server-side template injection on {ep.key} (parameter `{name}`)",
                        endpoint_key=ep.key, identity="anon",
                        detail=(f"The template expression `{payload}` was EVALUATED server-side "
                                f"(the response contains its computed result {SSTI_EXPECTED}). "
                                f"SSTI typically leads to remote code execution."),
                        evidence=Evidence(request=req, response=r,
                                          note=f"expression evaluated to {SSTI_EXPECTED}"),
                        source=self.name)]
        return []


# ---------------------------------------------------------------------------
@register
class CommandInjectionPlugin(AttackPlugin):
    vuln_class = VulnClass.COMMAND_INJECTION
    name = "command_injection"
    identity_agnostic = True

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        if not injectable_method(ep, ctx.allow_writes):
            return []
        for kind, name in injection_points(ep, ctx.allow_writes)[:MAX_POINTS]:
            control = ctx.send(build_injection_request(ctx, kind, name, "qa", label="cmd-control"), ctx.anon())
            for payload in CMD_TIME_PROBES:
                r1 = ctx.send(build_injection_request(ctx, kind, name, "qa" + payload, label=f"cmd:{name}"), ctx.anon())
                if r1.latency_ms >= CMD_TIME_THRESHOLD_MS and r1.latency_ms > control.latency_ms + 3000:
                    c2 = ctx.send(build_injection_request(ctx, kind, name, "qa", label="cmd-control2"), ctx.anon())
                    r2 = ctx.send(build_injection_request(ctx, kind, name, "qa" + payload, label="cmd2"), ctx.anon())
                    if r2.latency_ms >= CMD_TIME_THRESHOLD_MS and r2.latency_ms > c2.latency_ms + 3000:
                        return [Finding(
                            vuln_class=self.vuln_class, severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                            title=f"OS command injection (time-based) on {ep.key} (parameter `{name}`)",
                            endpoint_key=ep.key, identity="anon",
                            detail=(f"A shell payload in `{name}` caused a reproducible ~5s delay "
                                    f"(control ~{control.latency_ms:.0f}ms), proving the input is passed "
                                    f"to a system shell."),
                            evidence=Evidence(
                                request=build_injection_request(ctx, kind, name, "qa" + payload, label="cmd"),
                                response=r1, baseline_response=control,
                                note="time-based command injection (delay reproduced)"),
                            source=self.name)]
        return []


# ---------------------------------------------------------------------------
@register
class SecretsExposurePlugin(AttackPlugin):
    vuln_class = VulnClass.DATA_EXPOSURE
    name = "secrets_exposure"
    identity_agnostic = True

    def applies_to(self, ep) -> bool:
        return ep.method == "GET"

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        req = Request("GET", ctx.url(), label="secrets-scan")
        r = ctx.send(req, ctx.acting())
        if r.status == 0:
            return []
        hay = r.haystack()
        for label, rx in SECRET_PATTERNS:
            if rx.search(hay):
                return [Finding(
                    vuln_class=self.vuln_class, severity=Severity.HIGH, confidence=Confidence.HIGH,
                    title=f"Sensitive data exposure on {ep.key}: {label}",
                    endpoint_key=ep.key, identity=ctx.acting().name,
                    detail=(f"The response from {ep.key} contains what looks like a {label}. "
                            f"Secrets must never be returned to clients."),
                    evidence=Evidence(request=req, response=r, note=f"matched: {label}"),
                    source=self.name)]
        return []
