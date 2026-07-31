"""
"Undocumented endpoint" only means something when a spec exists to be undocumented in.

Regression origin: Phase 7 (OWASP Juice Shop). With no OpenAPI spec discoverable
(/openapi.json returns the SPA's index.html), discovery yielded 0 endpoints — so every
endpoint the UI touched became an "Undocumented endpoint" finding whose detail asserted
it was "not declared in the OpenAPI spec". There was no spec. 9 of 11 findings were this,
each vacuously true and none actionable, which is exactly the report noise that erodes
founder trust.

The shadow endpoints must STILL join the attack surface — only the bogus finding is
suppressed. When a spec DOES exist, a UI-only endpoint is a genuine shadow-API finding
and must still be reported.

No LLM, no browser, no network — run_qa_crawl is stubbed.
"""
from __future__ import annotations

import agent.engine as engine_mod
from agent.engine import SecurityEngine
from core.models import Endpoint

SHADOW = {
    "GET /rest/admin/application-configuration": {},
    "GET /api/Challenges/": {},
}


def _engine(tmp_path):
    eng = SecurityEngine(base_url="http://127.0.0.1:3000", spec_url="",
                         description="shop", crawl_ui=True,
                         output_dir=str(tmp_path), log=lambda m: None)
    eng._deadline = None
    return eng


def _stub_crawl(monkeypatch):
    """Make qa.crawler.run_qa_crawl return our shadow map without touching a browser."""
    import qa.crawler as crawler_mod
    monkeypatch.setattr(crawler_mod, "run_qa_crawl",
                        lambda *a, **k: ([], dict(SHADOW), {}), raising=False)


def test_no_spec_means_no_undocumented_findings(tmp_path, monkeypatch):
    _stub_crawl(monkeypatch)
    eng = _engine(tmp_path)
    endpoints = []                      # discovery found nothing — there is no spec
    findings = eng._run_qa(endpoints)

    undoc = [f for f in findings if str(getattr(f.vuln_class, "value", f.vuln_class))
             == "undocumented_endpoint"]
    assert undoc == [], (
        "with no spec, every endpoint is trivially 'undocumented' — these are noise; "
        f"got: {[f.title for f in undoc]}"
    )
    # ...but the endpoints must still be testable, or we lose the whole attack surface.
    assert len(endpoints) == 2, "shadow endpoints must still join the attack surface"


def test_with_a_spec_a_ui_only_endpoint_is_still_reported(tmp_path, monkeypatch):
    _stub_crawl(monkeypatch)
    eng = _engine(tmp_path)
    endpoints = [Endpoint(method="GET", path_template="/api/Challenges/",
                          base_url="http://127.0.0.1:3000")]
    findings = eng._run_qa(endpoints)

    undoc = [f for f in findings if str(getattr(f.vuln_class, "value", f.vuln_class))
             == "undocumented_endpoint"]
    titles = [f.title for f in undoc]
    assert len(undoc) == 1, f"the one UI-only endpoint should be reported; got {titles}"
    assert "application-configuration" in titles[0]
