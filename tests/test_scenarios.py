import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from extractors.parser import OpenAPIParser
from extractors.assumptions import AssumptionExtractor
from generators.scenarios import ScenarioGenerator

def test_scenario_generation():
    PETSTORE_URL = "https://petstore.swagger.io/v2/swagger.json"
    DESCRIPTION = "A pet store where users can manage pets, orders, and user accounts. Users should only see their own orders."

    print(f"--- Testing Scenario Generation for Petstore API ---")
    
    # 1. Parse
    parser = OpenAPIParser()
    spec = parser.load_spec(PETSTORE_URL)

    # 2. Extract Assumptions
    assumption_extractor = AssumptionExtractor()
    assumptions = assumption_extractor.extract(spec, DESCRIPTION)
    
    if not assumptions:
        print("❌ No assumptions extracted.")
        return

    # Pick the most critical assumption to target
    target_assumption = next((a for a in assumptions if a['risk_level'] == 'critical'), assumptions[0])
    print(f"🎯 Target Assumption: [{target_assumption['id']}] {target_assumption['description']}")

    # 3. Generate Scenarios
    generator = ScenarioGenerator()
    scenarios = generator.generate(target_assumption, spec)
    
    print(f"✅ Generated {len(scenarios)} adversarial scenarios:")
    for s in scenarios:
        print(f"  - [{s['id']}] {s['name']}")
        print(f"    Target: {s['method']} {s['endpoint']}")
        print(f"    Expected Failure: {s['expected_failure_type']}")
        print(f"    Risk Score: {s['risk_score']}")
        print("-" * 20)

if __name__ == "__main__":
    test_scenario_generation()
