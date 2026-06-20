"""
core/context.py — shared run memory ("what we know so far") for the whole engine.

Every brain call (security planner, QA planner, QA judge) receives a compact
brief() of accumulated knowledge so the LLM stops forgetting between steps:
learned facts about the app, what has already been tested, and what has already
been found. Serialisable so a run can be persisted and resumed.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RunContext:
    target: str = ""
    description: str = ""
    facts: list = field(default_factory=list)        # learned facts about the app
    tested: set = field(default_factory=set)         # keys already exercised (dedup)
    findings: list = field(default_factory=list)     # compact summaries of what was found
    entities: dict = field(default_factory=dict)     # {"users": ["1","2"], ...}
    notes: list = field(default_factory=list)
    auth_cookies: dict = field(default_factory=dict)  # session cookies captured at login (for API attacks)
    auth_role: str = ""                               # role of the authenticated identity

    # --- writes ----------------------------------------------------------
    def remember_fact(self, fact: str) -> None:
        f = (fact or "").strip()
        if f and f not in self.facts:
            self.facts.append(f)

    def remember_facts(self, facts) -> None:
        for f in (facts or []):
            self.remember_fact(str(f))

    def mark_tested(self, key: str) -> bool:
        """Mark a unit of work tested. Returns False if it was already tested."""
        if not key or key in self.tested:
            return False
        self.tested.add(key)
        return True

    def is_tested(self, key: str) -> bool:
        return key in self.tested

    def add_finding(self, finding) -> None:
        self.findings.append({
            "vuln_class": getattr(finding.vuln_class, "value", str(finding.vuln_class)),
            "severity": getattr(finding.severity, "value", str(finding.severity)),
            "title": finding.title,
            "where": finding.endpoint_key,
        })

    def add_entity(self, kind: str, value) -> None:
        bucket = self.entities.setdefault(kind, [])
        v = str(value)
        if v not in bucket:
            bucket.append(v)

    # --- read ------------------------------------------------------------
    def brief(self, max_chars: int = 2000) -> str:
        """A compact 'what we know' block to inject into LLM prompts."""
        lines = []
        if self.facts:
            lines.append("Known facts about this app:")
            lines += [f"- {f}" for f in self.facts[-12:]]
        if self.findings:
            lines.append("Issues already found (do NOT re-report or duplicate these):")
            lines += [f"- [{x['severity']}] {x['vuln_class']} @ {x['where']}: {x['title']}"
                      for x in self.findings[-15:]]
        if self.entities:
            lines.append("Known data/entities: "
                         + ", ".join(f"{k}={v}" for k, v in list(self.entities.items())[:8]))
        out = "\n".join(lines).strip()
        return out[:max_chars] if out else "(nothing learned yet)"

    # --- persistence -----------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "target": self.target, "description": self.description,
            "facts": self.facts, "tested": sorted(self.tested),
            "findings": self.findings, "entities": self.entities, "notes": self.notes,
            "auth_cookies": self.auth_cookies, "auth_role": self.auth_role,
        }

    @classmethod
    def from_dict(cls, d: dict | None) -> "RunContext":
        d = d or {}
        return cls(
            target=d.get("target", ""), description=d.get("description", ""),
            facts=list(d.get("facts", [])), tested=set(d.get("tested", [])),
            findings=list(d.get("findings", [])), entities=dict(d.get("entities", {})),
            notes=list(d.get("notes", [])),
            auth_cookies=dict(d.get("auth_cookies", {})), auth_role=d.get("auth_role", ""),
        )
