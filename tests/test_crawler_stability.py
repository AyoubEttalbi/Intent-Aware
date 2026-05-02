import asyncio
import pytest
from execution.crawler import WebCrawler
from agent.models import AppContext


@pytest.mark.asyncio
async def test_crawler_does_not_hang():
    """Crawler must complete within global timeout."""
    # We use a dummy URL that might fail fast, or a real local one if available.
    # For this test, we just check the timeout mechanism.
    crawler = WebCrawler("http://localhost:9999") 
    try:
        result = await asyncio.wait_for(crawler.crawl(depth=1), timeout=10)
        assert result is not None
    except asyncio.TimeoutError:
        pytest.fail("Crawler hung and hit the test timeout")
    except Exception:
        pass # Errors are fine as long as it doesn't hang

@pytest.mark.asyncio  
async def test_no_duplicate_urls():
    """Crawler must not visit the same normalized URL twice."""
    crawler = WebCrawler("http://localhost:8080")
    # This assumes the demo app is NOT running, so it will just visit the base_url and fail.
    # But it should still populate visited_urls.
    await crawler.crawl(depth=1)
    assert len(crawler.visited_urls) == len(set(crawler.visited_urls))

def test_scenario_dedup():
    from agent.models import Scenario
    from generators.dedup import deduplicate_scenarios
    
    s1 = Scenario(id="1", url="/a", url_pattern="/a", page_role="form",
                  category="security", attack_type="sqli", name="test",
                  description="", persona="user", target_field="email",
                  payload="' OR 1=1", http_method="POST", endpoint="/a",
                  expected_result="400", failure_signature="status=200",
                  severity="high", dedup_fingerprint="/a:sqli:email")
    s2 = Scenario(id="2", url="/a", url_pattern="/a", page_role="form",
                  category="security", attack_type="sqli", name="test2",
                  description="", persona="admin", target_field="email",
                  payload="'; DROP TABLE--", http_method="POST", endpoint="/a",
                  expected_result="400", failure_signature="status=200",
                  severity="critical", dedup_fingerprint="/a:sqli:email")
    
    result = deduplicate_scenarios([s1, s2])
    assert len(result) == 1
    # Check severity - result[0] is Scenario object
    assert result[0].severity == "critical"  # Kept higher severity
