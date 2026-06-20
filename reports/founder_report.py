"""
reports/founder_report.py — founder-grade security report.

Consumes structured Findings (not loose dicts) and produces a report a
non-technical founder can act on: an A–F grade, an executive summary, confirmed
bugs separated from potential issues, and for every finding a plain-language
explanation, business impact, concrete fix, and a copy-pasteable curl repro.
"""
from __future__ import annotations

from datetime import datetime
from typing import List

from core.models import Finding, Evidence, Severity, Confidence, SEVERITY_ORDER, to_curl

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵", Severity.INFO: "⚪",
}


class FounderReport:
    def __init__(self, findings: List[Finding], base_url: str, coverage: dict | None = None):
        self.findings = sorted(findings, key=lambda f: -SEVERITY_ORDER[f.severity])
        self.base_url = base_url
        self.coverage = coverage or {}
        self.ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- scoring -------------------------------------------------------------
    _CONF_WEIGHT = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.5, Confidence.LOW: 0.25}
    _SEV_PENALTY = {Severity.CRITICAL: 40, Severity.HIGH: 18, Severity.MEDIUM: 7,
                    Severity.LOW: 2, Severity.INFO: 0}

    def _counts(self) -> dict:
        c = {s: 0 for s in Severity}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def _confirmed_counts(self) -> dict:
        """Severity counts restricted to CONFIRMED (HIGH-confidence) findings."""
        c = {s: 0 for s in Severity}
        for f in self.findings:
            if f.confidence == Confidence.HIGH:
                c[f.severity] += 1
        return c

    def _low_coverage(self) -> bool:
        return bool(self.coverage.get("low_coverage"))

    def score(self) -> int:
        # Penalty weighted by CONFIDENCE: unconfirmed 'needs review' items don't tank
        # the headline grade the way a proven exploit does.
        pen = sum(self._SEV_PENALTY[f.severity] * self._CONF_WEIGHT.get(f.confidence, 0.5)
                  for f in self.findings)
        return max(0, min(100, round(100 - pen)))

    def grade(self) -> str:
        # Grade is driven by CONFIRMED findings (proven by an effect oracle), not by
        # unconfirmed QA noise. Low coverage withholds a passing grade entirely.
        c = self._confirmed_counts()
        s = self.score()
        if c[Severity.CRITICAL]:
            return "F" if c[Severity.CRITICAL] > 1 else "D"
        if self._low_coverage():
            # We could not test enough to vouch for the app — never award A/B.
            return "C" if not c[Severity.HIGH] else "D"
        if c[Severity.HIGH] and s >= 70:
            return "C"
        if s >= 90:
            return "A"
        if s >= 80:
            return "B"
        if s >= 70:
            return "C"
        if s >= 55:
            return "D"
        return "F"

    # --- rendering -----------------------------------------------------------
    def markdown(self) -> str:
        confirmed = [f for f in self.findings if f.confidence == Confidence.HIGH]
        potential = [f for f in self.findings if f.confidence != Confidence.HIGH]
        c = self._counts()

        out = [
            "# 🛡️ Security & QA Report",
            f"**Target:** {self.base_url}  ",
            f"**Scanned:** {self.ts}  ",
            "",
        ]
        if self._low_coverage():
            notes = self.coverage.get("degraded") or []
            out += [
                "> ⚠️ **LOW COVERAGE — results are NOT conclusive.** The scanner could not exercise "
                "enough of this app to vouch for it; a clean result here means *\"not enough was tested\"*, "
                "not *\"secure\"*.",
            ]
            for n in notes[:6]:
                out.append(f">   - {n}")
            out.append("")
        out += [
            "## Executive summary",
            f"- **Overall grade: {self.grade()}** (score {self.score()}/100)",
            f"- **Confirmed issues:** {len(confirmed)} "
            f"(🔴 {c[Severity.CRITICAL]} critical · 🟠 {c[Severity.HIGH]} high · "
            f"🟡 {c[Severity.MEDIUM]} medium · 🔵 {c[Severity.LOW]} low)",
            f"- **Needs review:** {len(potential)}",
        ]
        if confirmed:
            out.append("")
            out.append("**Top priorities:**")
            for f in confirmed[:5]:
                out.append(f"- {_SEV_EMOJI[f.severity]} **{f.title}** — {f.explanation or f.detail}")

        out += ["", "---", "", "## 🚩 Confirmed issues"]
        if not confirmed:
            out.append("\n✅ No confirmed security issues found.")
        else:
            for i, f in enumerate(confirmed, 1):
                out.append(self._render(i, f))

        out += ["", "---", "", "## 🔍 Potential issues (need human review)"]
        if not potential:
            out.append("\n✅ Nothing flagged for review.")
        else:
            for i, f in enumerate(potential, 1):
                out.append(self._render(i, f))

        out += ["", "---", "", "## 📊 Coverage"]
        cov = self.coverage
        out.append(f"- Endpoints discovered: **{cov.get('endpoints_total', '?')}**")
        out.append(f"- Requests sent: **{cov.get('requests_sent', '?')}**")
        if cov.get("attack_classes"):
            out.append(f"- Attack classes run: {', '.join(cov['attack_classes'])}")
        if cov.get("identities"):
            out.append(f"- Roles / identities tested: {', '.join(cov['identities'])}")
        return "\n".join(out) + "\n"

    def _render(self, idx: int, f: Finding) -> str:
        ev = f.evidence or Evidence()
        req = ev.request
        what = f.explanation or f.detail
        lines = [
            "",
            f"### [{idx}] {_SEV_EMOJI[f.severity]} {f.title}",
            f"- **Severity:** {f.severity.value.upper()}  ·  **Confidence:** {f.confidence.value.upper()}"
            f"  ·  **Type:** {f.vuln_class.value}  ·  **Where:** `{f.endpoint_key}`"
            + (f"  ·  **As:** `{f.identity}`" if f.identity and f.identity != "anon" else ""),
        ]
        if what:
            lines.append(f"- **What we found:** {what}")
        if f.impact:
            lines.append(f"- **Why it matters:** {f.impact}")
        if f.fix:
            lines.append(f"- **How to fix:** {f.fix}")

        if req:  # API finding — request/response evidence + curl repro
            differential = ev.baseline_request is not None and ev.baseline_response is not None
            if differential:
                lines.append(f"- **Evidence:** baseline `{ev.baseline_request.label or 'baseline'}` "
                             f"→ {ev.baseline_response.status}; attack `{req.label or 'attack'}` "
                             f"→ {ev.response.status if ev.response else '?'} ({ev.note})")
            elif ev.response is not None:
                lines.append(f"- **Evidence:** {req.label or 'request'} → {ev.response.status} ({ev.note})")
            lines.append("- **Reproduce:**")
            lines.append("  ```bash")
            if differential:
                # The PROOF of an access-control bug is the differential — show both calls.
                lines.append("  # baseline (the legitimate request):")
                lines.append("  " + to_curl(ev.baseline_request))
                lines.append("  # attack (same resource reached without the right credentials):")
                lines.append("  " + to_curl(req))
            else:
                lines.append("  " + to_curl(req))
            lines.append("  ```")
        else:    # QA / UI finding — page, expected/actual, steps, screenshot
            if ev.page_url:
                lines.append(f"- **Page:** {ev.page_url}")
            if ev.expected:
                lines.append(f"- **Expected:** {ev.expected}")
            if ev.actual:
                lines.append(f"- **Actual:** {ev.actual}")
            if ev.steps:
                lines.append("- **Steps to reproduce:**")
                for i, s in enumerate(ev.steps, 1):
                    lines.append(f"  {i}. {s}")
            if ev.screenshot:
                lines.append(f"- **Screenshot:** `{ev.screenshot}`")
        lines.append("")
        return "\n".join(lines)

    def save(self, path: str = "latest_report.md") -> None:
        with open(path, "w") as fh:
            fh.write(self.markdown())
