from agent.models import Scenario

def deduplicate_scenarios(scenarios: list) -> list:
    """
    Remove duplicate scenarios by fingerprint.
    Fingerprint = url_pattern + attack_type + target_field
    When duplicates exist, keep the highest severity one.
    """
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    seen = {}

    for s in scenarios:
        # If s is a dict (from LLM) or a Scenario object
        if hasattr(s, 'dedup_fingerprint') and s.dedup_fingerprint:
            fp = s.dedup_fingerprint
        elif isinstance(s, dict):
            fp = s.get('dedup_fingerprint') or f"{s.get('url_pattern')}:{s.get('attack_type')}:{s.get('target_field')}"
        else:
            fp = f"{s.url_pattern}:{s.attack_type}:{s.target_field}"
            
        if fp not in seen:
            seen[fp] = s
        else:
            existing = seen[fp]
            existing_severity = existing.get('severity', 'low') if isinstance(existing, dict) else existing.severity
            current_severity = s.get('severity', 'low') if isinstance(s, dict) else s.severity
            
            if severity_rank.get(current_severity, 3) < severity_rank.get(existing_severity, 3):
                seen[fp] = s  # Keep higher severity

    result = list(seen.values())
    result.sort(key=lambda s: severity_rank.get(s.get('severity', 'low') if isinstance(s, dict) else s.severity, 3))
    return result
