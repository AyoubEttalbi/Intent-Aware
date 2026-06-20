"""
stored_xss — persistent (stored) XSS verification.

Reflected XSS checks immediate echo; stored XSS is the dangerous multi-request
case: write a uniquely-marked script payload to a write endpoint, then read it
back from a related list/detail page and confirm it is rendered UN-escaped inside
HTML (so it would execute for every viewer). Runs per identity, so it also catches
stored XSS that only authenticated users can reach.
"""
from __future__ import annotations

from typing import List

from attacks.base import AttackPlugin, AttackContext, register
from core.models import Request, Finding, Evidence, VulnClass, Severity, Confidence

MARKER = "QAstoredXSS5731"
PAYLOAD = f"<script>{MARKER}</script>"


def _resource(path_template: str) -> str:
    parts = [p for p in path_template.split("/") if p and not p.startswith("{")]
    return parts[0] if parts else ""


@register
class StoredXssPlugin(AttackPlugin):
    vuln_class = VulnClass.XSS
    name = "stored_xss"

    def applies_to(self, endpoint) -> bool:
        return endpoint.method in ("POST", "PUT", "PATCH") and isinstance(endpoint.body_schema, dict)

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        if not ctx.allow_writes:
            return []   # persists a payload into the target — only with an explicit writes opt-in
        actor = ctx.acting()
        props = (ep.body_schema or {}).get("properties", {}) or {}
        str_fields = [n for n, p in props.items()
                      if str((p or {}).get("type", "string")).lower() in ("string", "")]
        if not str_fields:
            return []

        # 1. Write the marked payload.
        body = dict(ctx.sample_body or {})
        body[str_fields[0]] = PAYLOAD
        write = Request(ep.method, ctx.url(), body=body,
                        content_type=ep.request_content_type, label="stored-xss-write")
        w = ctx.send(write, actor)
        if w.status >= 400:
            return []   # write rejected (e.g. unauthenticated)

        # 2. Read it back from related list pages (no path id), as the same identity.
        resource = _resource(ep.path_template)
        for ge in ctx.surface:
            if ge.method != "GET" or ge.path_params or _resource(ge.path_template) != resource:
                continue
            r = ctx.send(Request("GET", ge.url_for({}), label=f"read-back {ge.path_template}"), actor)
            if "html" in str(r.headers.get("content-type", "")).lower() and PAYLOAD in r.haystack():
                return [Finding(
                    vuln_class=VulnClass.XSS, severity=Severity.HIGH, confidence=Confidence.HIGH,
                    title=f"Stored XSS: input to {ep.key} is rendered unescaped on {ge.key}",
                    endpoint_key=ep.key, identity=actor.name,
                    detail=(f"A script payload submitted to '{str_fields[0]}' via {ep.key} is later "
                            f"rendered UN-escaped inside the HTML of {ge.key} — it will execute in the "
                            f"browser of anyone who views that page."),
                    evidence=Evidence(request=write, response=r,
                                      note=f"payload persisted and reflected unescaped on {ge.path_template}"),
                    source=self.name)]
        return []
