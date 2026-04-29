import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from extractors.parser import OpenAPIParser
from extractors.intent import IntentExtractor
from extractors.assumptions import AssumptionExtractor

def test_petstore_extraction():
    PETSTORE_URL = "https://petstore.swagger.io/v2/swagger.json"
    DESCRIPTION = "A pet store where users can manage pets, orders, and user accounts. Users should only see their own orders."

    print(f"--- Testing extraction for Petstore API ---")
    
    # 1. Parse
    parser = OpenAPIParser()
    try:
        spec = parser.load_spec(PETSTORE_URL)
        print("✅ Spec parsed successfully.")
    except Exception as e:
        print(f"❌ Parser failed: {e}")
        return

    # 2. Extract Intent (requires API Key)
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("⚠️  Skipping LLM extraction (no API key found).")
        return

    intent_extractor = IntentExtractor()
    contracts = intent_extractor.extract(spec, DESCRIPTION)
    print(f"✅ Extracted {len(contracts)} contracts:")
    for c in contracts:
        print(f"  - [{c['id']}] {c['name']}: {c['description']}")

    # 3. Extract Assumptions
    assumption_extractor = AssumptionExtractor()
    assumptions = assumption_extractor.extract(spec, DESCRIPTION)
    print(f"✅ Extracted {len(assumptions)} assumptions:")
    for a in assumptions:
        print(f"  - [{a['id']}] ({a['risk_level']}) {a['description']}")

if __name__ == "__main__":
    test_petstore_extraction()
