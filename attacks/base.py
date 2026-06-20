"""
attacks/base.py — attack-plugin interface + registry.

Each plugin targets ONE vulnerability class and owns both its payloads and its
EFFECT oracle (it verifies real exploitation, not just "got 200"). A plugin
drives its own requests through ctx.send() so it can run differential oracles
(baseline vs attack) and multi-request chains.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from core.models import Endpoint, Identity, Request, Response, Finding


def default_param_value(param: dict) -> str:
    """A plausible value for a path/query param when the planner didn't supply one."""
    t = str(param.get("type", "string")).lower()
    name = str(param.get("name", "")).lower()
    if t in ("integer", "number") or name.endswith("id") or name == "id":
        return "1"
    if "email" in name:
        return "qa.tester@example.com"
    return "1"


@dataclass
class AttackContext:
    """Everything a plugin needs to run, provided by the engine."""
    endpoint: Endpoint
    identities: List[Identity]
    send: Callable[[Request, Optional[Identity]], Response]
    sample_values: dict = field(default_factory=dict)   # param-name -> valid value (LLM/heuristic)
    sample_body: dict = field(default_factory=dict)     # a baseline-valid request body
    log: Callable[[str], None] = lambda m: None
    actor: Optional[Identity] = None                    # the identity to act AS this run
    surface: list = field(default_factory=list)         # all discovered endpoints (for read-back)
    allow_writes: bool = False                          # may plugins mutate the target? (off by default)
    memory: object = None                               # RunContext (or None) for entity/fact write-back
    auth_scheme: object = None                          # AuthScheme: how the target authenticates
    foreign_ids: dict = field(default_factory=dict)     # {resource_type: [real ids]} harvested live

    def anon(self) -> Identity:
        for i in self.identities:
            if i.is_anonymous:
                return i
        return Identity(name="anon")

    def acting(self) -> Identity:
        """The identity to act as (defaults to anonymous)."""
        return self.actor or self.anon()

    def authed(self) -> List[Identity]:
        return [i for i in self.identities if not i.is_anonymous]

    def path_values(self, **overrides) -> dict:
        vals = {}
        for p in self.endpoint.path_params:
            name = p.get("name")
            vals[name] = self.sample_values.get(name, default_param_value(p))
        vals.update({k: v for k, v in overrides.items() if v is not None})
        return vals

    def url(self, **overrides) -> str:
        return self.endpoint.url_for(self.path_values(**overrides))


class AttackPlugin:
    vuln_class = None
    name = "base"
    identity_agnostic = False   # if True, run once (as anon) regardless of identity matrix

    def applies_to(self, endpoint: Endpoint) -> bool:
        return True

    def run(self, ctx: AttackContext) -> List[Finding]:
        raise NotImplementedError


# --- registry (populated by each plugin module at import time) ---
_REGISTRY: list = []


def register(plugin_cls):
    if plugin_cls not in _REGISTRY:
        _REGISTRY.append(plugin_cls)
    return plugin_cls


def all_plugins() -> List[AttackPlugin]:
    return [cls() for cls in _REGISTRY]
