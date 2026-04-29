import sys
import os
import json
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from agent.loop import AgentLoop

def main():
    # Use a real public API for testing
    # Note: Swagger Petstore is a live API, be careful not to spam it.
    PETSTORE_URL = "https://petstore.swagger.io/v2/swagger.json"
    DESCRIPTION = "A pet store where users can manage pets, orders, and user accounts. Users should only see their own orders."
    BASE_URL = "https://petstore.swagger.io/v2"

    loop = AgentLoop(PETSTORE_URL, DESCRIPTION, BASE_URL)
    
    # Run only 1 assumption for a quick test
    results = loop.run(max_assumptions=1)
    
    # Save results to a file for review
    with open("test_results.json", "w") as f:
        json_results = []
        for r in results:
            # Clean up response object for JSON serialization
            json_results.append(r)
        json.dump(json_results, f, indent=2)
    
    print(f"\nDetailed results saved to test_results.json")

if __name__ == "__main__":
    main()
