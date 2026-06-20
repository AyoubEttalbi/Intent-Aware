"""
core/discovery.py — harvest real resource ids from the live app.

The flagship multi-role bug (user A reads user B's object) is undetectable if the
engine doesn't know which ids exist or who owns them — and a non-technical operator
won't hand-enter `owned_resource_ids`. So, before the attack matrix, probe the
collection (list) endpoints as each identity and:

  * record the ids each identity can see into its `owned_resource_ids` (additive —
    never overwrites operator-supplied values), enabling horizontal authz testing;
  * build a per-resource pool of REAL ids (incl. UUID/slug) to use as concrete
    foreign-id candidates for IDOR instead of blindly guessing 1/2/3.
"""
from __future__ import annotations

from core.models import Request

_ID_KEYS = ("id", "_id", "uuid", "slug", "pk", "key")
_LIST_WRAPPERS = ("data", "items", "results", "records", "rows", "list")
MAX_COLLECTIONS = 30
MAX_IDS_PER_RESOURCE = 25


def _resource_type(path_template: str) -> str:
    parts = [p for p in path_template.split("/") if p and not p.startswith("{")]
    return parts[-1] if parts else ""


def _rows(body, rtype: str) -> list:
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        if isinstance(body.get(rtype), list):
            return body[rtype]
        for w in _LIST_WRAPPERS:
            if isinstance(body.get(w), list):
                return body[w]
        # a single object response
        if any(k in body for k in _ID_KEYS):
            return [body]
    return []


def _ids_from_rows(rows, rtype: str) -> list:
    singular = rtype[:-1] if rtype.endswith("s") else rtype
    keys = set(_ID_KEYS) | {f"{singular}_id", f"{rtype}_id"}
    out = []
    for it in rows:
        if isinstance(it, dict):
            for k in keys:
                v = it.get(k)
                if isinstance(v, (str, int)) and str(v):
                    out.append(str(v))
                    break
    # de-dupe, preserve order
    seen, res = set(), []
    for v in out:
        if v not in seen:
            seen.add(v)
            res.append(v)
    return res[:MAX_IDS_PER_RESOURCE]


def harvest_resources(endpoints, identities, send, log=print) -> dict:
    """Populate identities' owned_resource_ids and return a foreign-id pool
    {resource_type: [ids]} aggregated across identities."""
    collections = [e for e in endpoints
                   if e.method == "GET" and not e.path_params][:MAX_COLLECTIONS]
    actors = [i for i in identities if not i.is_anonymous] or identities
    pool: dict = {}
    for ep in collections:
        rtype = _resource_type(ep.path_template)
        if not rtype:
            continue
        for actor in actors:
            r = send(Request("GET", ep.url_for({}), label=f"harvest {rtype} as {actor.name}"), actor)
            if not r.ok:
                continue
            ids = _ids_from_rows(_rows(r.body, rtype), rtype)
            if not ids:
                continue
            # additive: keep any operator-supplied ids, add discovered ones
            owned = actor.owned_resource_ids.setdefault(rtype, [])
            for i in ids:
                if i not in owned:
                    owned.append(i)
            bucket = pool.setdefault(rtype, [])
            for i in ids:
                if i not in bucket:
                    bucket.append(i)
    if pool:
        log(f"   harvested ids for: {', '.join(f'{k}({len(v)})' for k, v in pool.items())}")
    return pool
