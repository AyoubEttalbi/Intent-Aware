"""
authz_matrix — multi-role access-control testing.

Runs the identity matrix against an endpoint to catch the two authorization bugs
anon-only testing structurally misses:

  * Vertical (privilege escalation): a non-admin authenticated user can reach an
    admin-restricted endpoint.
  * Horizontal (broken object-level auth): authenticated user A can read user B's
    private resource — and ONLY flagged when anon is blocked (otherwise it's plain
    IDOR, owned by the idor plugin, and not re-reported here).

Both oracles are differential and identity-grounded (low false positives).
"""
from __future__ import annotations

import json
import re
from typing import List

from attacks.base import AttackPlugin, AttackContext, register
from core.models import Request, Finding, Evidence, VulnClass, Severity, Confidence

ADMIN_PATH = re.compile(r"/(admin|manage|internal|superuser|root|backoffice)\b", re.I)


def _resource_type(path_template: str) -> str:
    parts = [p for p in path_template.split("/") if p and not p.startswith("{")]
    return parts[-1] if parts else ""


def _same_resource(a, b) -> bool:
    if a is None or b is None:
        return False
    try:
        sa, sb = json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True)
        return sa == sb and len(sa) > 2
    except Exception:
        return bool(a) and str(a) == str(b)


@register
class AuthzMatrixPlugin(AttackPlugin):
    vuln_class = VulnClass.AUTHZ
    name = "authz_matrix"
    identity_agnostic = True   # manages the identity matrix internally; run once

    def applies_to(self, endpoint) -> bool:
        return endpoint.method == "GET"   # focus reads for clean differential oracles

    def run(self, ctx: AttackContext) -> List[Finding]:
        authed = [i for i in ctx.identities if not i.is_anonymous]
        if not authed:
            return []
        return self._vertical(ctx, authed) + self._horizontal(ctx, authed)

    # --- vertical: admin-only endpoint reachable by a non-admin -------------
    def _vertical(self, ctx: AttackContext, authed: list) -> List[Finding]:
        ep = ctx.endpoint
        if not ADMIN_PATH.search(ep.path_template):
            return []
        for actor in [i for i in authed if i.role != "admin"]:
            req = Request(ep.method, ctx.url(), label=f"as {actor.name}")
            r = ctx.send(req, actor)
            if r.ok and r.body not in (None, "", {}, []):
                return [Finding(
                    vuln_class=VulnClass.AUTHZ, severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                    title=f"Privilege escalation: non-admin can access {ep.key}",
                    endpoint_key=ep.key, identity=actor.name,
                    detail=(f"This endpoint looks admin-restricted, but the non-admin user "
                            f"'{actor.name}' (role: {actor.role}) received {r.status} with data."),
                    evidence=Evidence(request=req, response=r,
                                      note=f"non-admin '{actor.name}' accessed an admin endpoint"),
                    source=self.name)]
        return []

    # --- horizontal: A reads B's resource (only when anon is blocked) -------
    def _horizontal(self, ctx: AttackContext, authed: list) -> List[Finding]:
        ep = ctx.endpoint
        if not ep.path_params:
            return []
        idp = next((p for p in ep.path_params if "id" in str(p.get("name", "")).lower()),
                   ep.path_params[0])
        name = idp["name"]
        rtype = _resource_type(ep.path_template)

        for owner in authed:
            for rid in (owner.owned_resource_ids or {}).get(rtype, []):
                url = ctx.url(**{name: rid})
                owner_resp = ctx.send(Request("GET", url, label=f"owner {owner.name}"), owner)
                if not owner_resp.ok:
                    continue
                # If anon already gets the SAME resource (not just a redirect-to-login 200), it's plain
                # IDOR, owned by the idor plugin — skip so we don't double-report.
                anon_resp = ctx.send(Request("GET", url, label="anon"), ctx.anon())
                if anon_resp.ok and _same_resource(anon_resp.body, owner_resp.body):
                    continue
                for actor in authed:
                    if actor.name == owner.name or actor.role == "admin":
                        continue
                    if rid in (actor.owned_resource_ids or {}).get(rtype, []):
                        continue
                    a_req = Request("GET", url, label=f"as {actor.name}")
                    a_resp = ctx.send(a_req, actor)
                    if a_resp.ok and _same_resource(a_resp.body, owner_resp.body):
                        return [Finding(
                            vuln_class=VulnClass.AUTHZ, severity=Severity.HIGH, confidence=Confidence.HIGH,
                            title=f"Broken object-level auth: {actor.name} can read {owner.name}'s {rtype} via {ep.key}",
                            endpoint_key=ep.key, identity=actor.name,
                            detail=(f"User '{actor.name}' (role: {actor.role}) retrieved {rtype} #{rid}, which "
                                    f"belongs to '{owner.name}'. Object ownership is not enforced for logged-in users."),
                            evidence=Evidence(
                                request=a_req, response=a_resp,
                                baseline_request=Request("GET", url, label=f"owner {owner.name}"),
                                baseline_response=owner_resp,
                                note=f"{actor.name} retrieved {owner.name}'s record"),
                            source=self.name)]
        return []
