"""
attacks/graphql.py — GraphQL surface checks.

GraphQL exposes its whole API behind a single POST /graphql whose operations live
in the request body, so the REST-shaped matrix can't see them. This plugin gives
the engine a GraphQL-aware probe:

  * introspection enabled — production servers should disable __schema introspection;
    if it answers, the full schema (and attack surface) is disclosed.
  * unauthenticated reach — the endpoint accepts anonymous queries (recorded as
    context for downstream reasoning).

Effect oracle: the response actually contains a populated `data.__schema`.
"""
from __future__ import annotations

from typing import List

from attacks.base import AttackPlugin, AttackContext, register
from core.models import Request, Finding, Evidence, VulnClass, Severity, Confidence

INTROSPECTION_QUERY = {
    "query": "query QA_Introspection { __schema { queryType { name } types { name } } }"
}


def is_graphql_endpoint(ep) -> bool:
    return ep.method in ("POST", "GET") and "graphql" in ep.path_template.lower()


@register
class GraphQLIntrospectionPlugin(AttackPlugin):
    vuln_class = VulnClass.DATA_EXPOSURE
    name = "graphql_introspection"
    identity_agnostic = True

    def applies_to(self, ep) -> bool:
        return is_graphql_endpoint(ep)

    def run(self, ctx: AttackContext) -> List[Finding]:
        ep = ctx.endpoint
        req = Request("POST", ctx.url(), body=INTROSPECTION_QUERY,
                      content_type="json", label="graphql-introspection")
        r = ctx.send(req, ctx.anon())
        data = r.body.get("data") if isinstance(r.body, dict) else None
        if isinstance(data, dict) and isinstance(data.get("__schema"), dict):
            schema = data["__schema"]
            n_types = len(schema.get("types", []) or [])
            return [Finding(
                vuln_class=self.vuln_class, severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                title=f"GraphQL introspection enabled on {ep.key}",
                endpoint_key=ep.key, identity="anon",
                detail=(f"The GraphQL endpoint answers introspection queries (it disclosed "
                        f"{n_types} schema type(s)) to an anonymous caller. Production servers "
                        f"should disable introspection — it hands an attacker the full API map."),
                evidence=Evidence(request=req, response=r, note="data.__schema returned to anon"),
                source=self.name)]
        return []
