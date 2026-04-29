import os
import json
from datetime import datetime
from typing import List, Dict, Any

class ReportGenerator:
    def __init__(self, results: List[Dict[str, Any]], base_url: str):
        self.results = results
        self.base_url = base_url
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_markdown(self) -> str:
        confirmed_bugs = [r for r in self.results if r['check'].get('is_bug') and r['check'].get('confidence') != 'low']
        potential_issues = [r for r in self.results if r['check'].get('is_bug') and r['check'].get('confidence') == 'low']
        total_scenarios = len(self.results)
        
        report = f"""# Bug Report — Intent-Aware QA Agent
Generated at: {self.timestamp}
Target API: {self.base_url}

---

## 📊 Summary
- **Total Scenarios Run**: {total_scenarios}
- **Confirmed Bugs**: {len(confirmed_bugs)}
- **Potential Issues**: {len(potential_issues)}
- **Health Score**: {max(0, 100 - (len(confirmed_bugs) * 15))}%

---

## 🚩 Confirmed Bugs
"""
        if not confirmed_bugs:
            report += "\n✅ No confirmed bugs found."
        else:
            for i, bug in enumerate(confirmed_bugs):
                report += self._format_bug(i+1, bug)

        report += "\n---\n\n## 🔍 Potential Issues (Requires Review)\n"
        if not potential_issues:
            report += "\n✅ No potential issues detected."
        else:
            for i, bug in enumerate(potential_issues):
                report += self._format_bug(i+1, bug)

        return report

    def _format_bug(self, index: int, bug: Dict[str, Any]) -> str:
        return f"""
### [{index}] {bug['check'].get('reason', 'Unknown bug')}
- **Severity**: {bug['check'].get('severity', 'medium').upper()}
- **Confidence**: {bug['check'].get('confidence', 'medium').upper()}
- **Scenario**: {bug['scenario']['name']}
- **Endpoint**: `{bug['scenario']['method']} {bug['scenario']['endpoint']}`
- **Reproduction**:
  ```json
  {{
    "method": "{bug['scenario']['method']}",
    "url": "{self.base_url}{bug['scenario']['endpoint']}",
    "body": {json.dumps(bug['scenario'].get('body', {}))}
  }}
  ```
- **Response**:
  - Status: {bug['response']['status']}
  - Latency: {bug['response']['latency']:.2f}ms

---
"""

    def save_report(self, path: str = "latest_report.md"):
        md = self.generate_markdown()
        with open(path, "w") as f:
            f.write(md)
        print(f"✅ Report saved to {path}")

if __name__ == "__main__":
    print("Report Generator initialized.")
