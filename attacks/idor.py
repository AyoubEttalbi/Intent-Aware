"""
idor — horizontal access control / data isolation.

Effect oracle: fetch the resource for one id, then for neighbouring/foreign ids.
If the caller can read a DIFFERENT record's sensitive data (different email, etc.)
that it should not own, that's IDOR / missing object-level authorization.
"""
from __future__ import annotations

from typing import List

from attacks.base import AttackPlugin, AttackContext, register
from attacks.payloads import idor_candidates
from core.models import Request, Finding, Evidence, VulnClass, Severity, Confidence

SENSITIVE_FIELDS = {
    "email", "phone", "password", "passwd", "ssn", "address", "token",
    "api_key", "apikey", "secret", "credit_card", "iban", "dob", "salary",
}


def _resource_type(path_template: str) -> str:
    parts = [p for p in path_template.split("/") if p and not p.startswith("{")]
    return parts[-1] if parts else ""


def _candidates(ctx, orig: str) -> list:
    """Concrete foreign ids harvested live (handles UUID/slug) first, then guessed neighbours."""
    rtype = _resource_type(ctx.endpoint.path_template)
    harvested = [str(i) for i in (ctx.foreign_ids.get(rtype, []) or []) if str(i) != str(orig)]
    out, seen = [], set()
    for c in harvested + [str(x) for x in idor_candidates(orig)]:
        if c and c != str(orig) and c not in seen:
            seen.add(c)
            out.append(c)
    return out[:12]


def _sensitive(body) -> dict:
    """Extract {field: value} for sensitive keys from a dict or list-of-dicts."""
    out = {}
    items = body if isinstance(body, list) else [body]
    for it in items:
        if isinstance(it, dict):
            for k, v in it.items():
                if str(k).lower() in SENSITIVE_FIELDS:
                    out.setdefault(str(k).lower(), str(v))
    return out


@register
class IdorPlugin(AttackPlugin):
    vuln_class = VulnClass.IDOR
    name = "idor"

    def applies_to(self, endpoint) -> bool:
        return endpoint.method == "GET" and bool(endpoint.path_params)

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        anon = ctx.acting()   # the identity we act as (anonymous or authenticated)
        idp = next((p for p in ep.path_params if "id" in str(p.get("name", "")).lower()),
                   ep.path_params[0])
        name = idp["name"]
        # Prefer a harvested real id we know exists for this resource as the baseline.
        rtype = _resource_type(ep.path_template)
        harvested0 = (ctx.foreign_ids.get(rtype) or [None])[0]
        orig = str(ctx.sample_values.get(name) or harvested0 or "1")

        base_req = Request("GET", ctx.url(**{name: orig}), label=f"{name}={orig}")
        base = ctx.send(base_req, anon)
        if not base.ok:
            return []
        base_pii = _sensitive(base.body)
        if not base_pii:
            return []  # no sensitive data here → not a data-exposure target

        for cand in _candidates(ctx, orig):
            req = Request("GET", ctx.url(**{name: cand}), label=f"{name}={cand}")
            r = ctx.send(req, anon)
            if not r.ok:
                continue
            other = _sensitive(r.body)
            if other and other != base_pii:
                unauth = anon.is_anonymous
                ctx.log(f"idor: {ep.key} leaks foreign record {name}={cand}")
                return [Finding(
                    vuln_class=self.vuln_class,
                    severity=Severity.CRITICAL if unauth else Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title=f"IDOR / broken object-level authorization on {ep.key}",
                    endpoint_key=ep.key,
                    identity=anon.name,
                    detail=(f"By changing `{name}` from {orig} to {cand}, the caller "
                            f"{'(unauthenticated) ' if unauth else ''}reads another record's "
                            f"sensitive fields ({', '.join(sorted(other))}). Records are not "
                            f"scoped to their owner."),
                    evidence=Evidence(request=req, response=r,
                                      baseline_request=base_req, baseline_response=base,
                                      note=f"own record ({name}={orig}) vs foreign record ({name}={cand})"),
                    source=self.name,
                )]
        return []
