import os
import json
import re
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from agent.llm import LLMClient
from agent.personas import PersonaManager

load_dotenv()

SCENARIO_GENERATOR_PROMPT = """You are a senior security QA engineer generating adversarial test scenarios.

You will receive:
- app_type: the kind of application
- tech_stack: technologies in use (informs payload selection)
- page_role: what this page does
- entity_type: the domain entity this page works with
- url_pattern: normalized URL (with {param} placeholders)
- url_params: list of path parameter names
- forms: structured list of forms with typed fields
- personas: available test personas
- known_routes: other routes in the app (for IDOR target selection)

OUTPUT: A JSON array of scenario objects. Each object MUST have all these fields:
{
  "id": "scen_001",
  "url": "<exact url>",
  "url_pattern": "<url with {param} placeholders>",
  "page_role": "<role>",
  "category": "functional|security|boundary|privilege|injection",
  "attack_type": "sqli|xss|idor|auth_bypass|mass_assignment|rate_limit|business_logic|input_validation|info_disclosure|csrf",
  "name": "Short name",
  "description": "What this tests and why it matters",
  "persona": "<persona name from personas list>",
  "target_field": "<field name being tested, or 'url_param' or 'header'>",
  "payload": "<concrete value or dict of field:value>",
  "http_method": "GET|POST|PUT|DELETE|PATCH",
  "endpoint": "<full endpoint URL>",
  "expected_result": "Plain English description of correct server behaviour",
  "failure_signature": "Exact condition that proves a bug: e.g. 'status=200 AND body contains email of different user'",
  "severity": "critical|high|medium|low"
}

SCENARIO SELECTION RULES:
1. For every form with an id/numeric field: generate an IDOR test using another user's ID.
2. For every text input: generate one injection test appropriate to the tech stack
   (SQL injection for SQL DBs, NoSQL injection for MongoDB, XSS for HTML-rendered fields).
3. For every numeric field with a min/max: generate boundary tests (min-1, max+1, 0, negative, float).
4. For every authenticated endpoint: generate an auth_bypass test using the unauthenticated persona.
5. For every admin-only route: generate a privilege escalation test using the regular_user persona.
6. For file upload fields: generate path traversal and malicious content type payloads.
7. For password fields: generate weak password and credential stuffing scenarios.
8. NEVER generate a scenario without a concrete payload. No "test with various inputs".
9. NEVER duplicate: if two forms have the same field name and attack type, generate ONE scenario.
10. Return ONLY the JSON array. No markdown, no explanation.

PAYLOAD SELECTION BY TECH STACK:
- FastAPI/Python: SQL injection: "' OR '1'='1"; SSTI: "{{7*7}}"
- Express/Node: NoSQL injection: {"$gt": ""}; prototype pollution
- Django: ORM injection patterns, CSRF bypass
- JWT auth: alg:none attack, expired token reuse
- File upload: ../../../etc/passwd, polyglot files
"""

def build_scenario_prompt(page_context, app_context) -> str:
    """Convert PageContext and AppContext into the prompt user message."""
    
    # Serialize forms with field details
    forms_data = []
    for form in page_context.forms:
        form_data = {
            "action": form["action"],
            "method": form["method"],
            "submit_label": form["submit_label"],
            "fields": [
                {
                    "name": f.name,
                    "type": f.field_type,
                    "label": f.label,
                    "required": f.required,
                    "options": f.options,
                    "validation": f.validation_hint,
                }
                for f in form["fields"]
            ]
        }
        forms_data.append(form_data)

    return json.dumps({
        "app_type": app_context.app_type,
        "tech_stack": app_context.tech_stack,
        "page_role": page_context.page_role,
        "entity_type": page_context.entity_type,
        "url_pattern": page_context.url,
        "url_params": page_context.url_params,
        "forms": forms_data,
        "personas": [p["name"] for p in app_context.personas],
        "known_routes": [
            {"method": r["method"], "path": r["path"]}
            for r in app_context.routes[:20]
        ],
    }, indent=2)

class ScenarioGenerator:
    def __init__(self):
        self.llm = LLMClient()

    def generate(self, prompt: str) -> List[Dict[str, Any]]:
        """
        Generates adversarial scenarios based on the provided prompt.
        """
        raw_data = self.llm.ask(
            system_prompt=SCENARIO_GENERATOR_PROMPT,
            user_prompt=prompt
        )

        if not raw_data:
            return []

        # If LLM returned a string (rare but possible if ask_json fails internally)
        if isinstance(raw_data, str):
            data = self._parse_json_list(raw_data)
        else:
            data = raw_data

        if not data:
            return []

        # LLM might return a list directly or a dict with a "scenarios" key
        if isinstance(data, list):
            return data
        return data.get("scenarios", [])

    def _parse_json_list(self, text: str) -> Optional[Any]:
        """Aggressively attempt to extract and repair JSON from potentially truncated text."""
        try:
            # 1. Clean up common LLM artifacts
            text = text.strip()
            text = re.sub(r'^```json\s*|\s*```$', '', text, flags=re.MULTILINE)
            
            # 2. Find the start of the first JSON structure
            start_idx = text.find('[')
            obj_start_idx = text.find('{')
            
            if start_idx == -1 and obj_start_idx == -1:
                return None
                
            # Prefer whichever comes first
            if start_idx == -1 or (obj_start_idx != -1 and obj_start_idx < start_idx):
                start_idx = obj_start_idx
            
            json_candidate = text[start_idx:]
            
            # 3. Try standard parsing first
            try:
                # Find the LAST closing bracket/brace
                last_bracket = json_candidate.rfind(']')
                last_brace = json_candidate.rfind('}')
                end_idx = max(last_bracket, last_brace)
                if end_idx != -1:
                    return json.loads(json_candidate[:end_idx+1])
            except:
                pass
                
            # 4. If that fails, it's likely truncated. Apply Deep Repair.
            repaired = self._try_repair_truncated_json(json_candidate)
            if repaired:
                try:
                    return json.loads(repaired)
                except:
                    # Final fallback: try to find the last complete object in a list
                    return self._extract_last_valid_json(repaired)
        except Exception:
            pass
        return None

    def _try_repair_truncated_json(self, text: str) -> Optional[str]:
        """Aggressively repair truncated JSON by balancing quotes and brackets."""
        if not text: return None
        
        # 1. Handle open quotes first
        # Count non-escaped quotes
        quotes = 0
        escaped = False
        for char in text:
            if char == '\\': escaped = not escaped
            elif char == '"' and not escaped: quotes += 1
            else: escaped = False
            
        if quotes % 2 != 0:
            text += '"'
            
        # 2. Balance brackets
        stack = []
        is_string = False
        escaped = False
        
        for char in text:
            if char == '\\': escaped = not escaped
            elif char == '"' and not escaped: is_string = not is_string
            elif not is_string:
                if char == '{': stack.append('}')
                elif char == '[': stack.append(']')
                elif char == '}': 
                    if stack and stack[-1] == '}': stack.pop()
                elif char == ']':
                    if stack and stack[-1] == ']': stack.pop()
            if char != '\\': escaped = False
            
        return text + "".join(reversed(stack))

    def _extract_last_valid_json(self, text: str) -> Optional[Any]:
        """Desperate attempt to find the last valid JSON object/list in a string."""
        # Try to backtrack from the end until something parses
        for i in range(len(text), 0, -1):
            try:
                return json.loads(text[:i])
            except:
                continue
        return None

if __name__ == "__main__":
    print("Scenario Generator updated.")
