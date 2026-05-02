import os
import json
import re
from typing import Dict, Any, List, Optional
from dotenv import load_dotenv
from agent.llm import LLMClient

load_dotenv()

ASSUMPTION_EXTRACTOR_PROMPT = """You are a senior QA architect extracting implicit behavioral assumptions from application context.

You will receive:
- endpoints: list of formal and discovered API endpoints
- ui_context: dict of pages discovered (URL -> page role, forms, entity type)
- app_context: routes, models, auth flow, personas, app type

Your job: identify IMPLICIT assumptions the application makes that could be violated.
These are NOT things the spec says explicitly — they are things the app ASSUMES are true
but doesn't enforce or test.

OUTPUT: JSON array of assumption objects:
{
  "id": "assume_001",
  "assumption": "Users can only view their own orders, not other users' orders",
  "derives_from": "UI has /orders/{id} page, app has User and Order models with ownership",
  "test_approach": "Access /orders/{other_user_order_id} as regular_user persona",
  "risk_if_violated": "Data leakage — users can see private order data of other customers",
  "severity": "critical",
  "relevant_pages": ["/orders/{id}"],
  "relevant_personas": ["regular_user", "unauthenticated"]
}

ASSUMPTION CATEGORIES TO LOOK FOR:
- Authorization: "Only admins can delete users" (if admin routes exist)
- Data isolation: "Users see only their own data" (if user-scoped entities exist)  
- Business logic: "Discount cannot exceed product price" (if pricing forms exist)
- State machine: "Cannot checkout with empty cart" (if checkout page exists)
- Rate limiting: "Password reset is rate-limited" (if auth forms exist)
- Cascading: "Deleting a user deletes their orders" (if relational models exist)
- Upload safety: "Uploaded files are validated before storage" (if upload forms exist)

Focus on HIGH-RISK assumptions. Return 5-15 assumptions maximum.
Return ONLY the JSON array."""

class AssumptionExtractor:
    def __init__(self):
        self.llm = LLMClient()

    def extract(self, endpoints: List[str], ui_context: Dict[str, Any], app_context: Any) -> List[Dict[str, Any]]:
        """
        Extracts implicit assumptions from spec, discovery and app context.
        """
        # AppContext might be a dataclass or a dict
        app_ctx_dict = app_context.__dict__ if hasattr(app_context, '__dict__') else app_context

        user_prompt = json.dumps({
            "endpoints": endpoints,
            "ui_context": ui_context,
            "app_context": {
                "app_type": app_ctx_dict.get("app_type"),
                "models": app_ctx_dict.get("models"),
                "routes": app_ctx_dict.get("routes"),
                "personas": [p["name"] for p in app_ctx_dict.get("personas", [])]
            }
        }, indent=2)

        data = self.llm.ask(
            system_prompt=ASSUMPTION_EXTRACTOR_PROMPT,
            user_prompt=user_prompt
        )

        if not data:
            return {"contracts": [], "assumptions": []}
            
        if isinstance(data, str):
            data = self._parse_json(data)
            if not data:
                return {"contracts": [], "assumptions": []}

        if isinstance(data, list):
            return {"contracts": [], "assumptions": data}
        return data
            
    def _parse_json(self, text: str) -> Optional[Any]:
        """Aggressively attempt to extract and repair JSON."""
        try:
            text = text.strip()
            text = re.sub(r'^```json\s*|\s*```$', '', text, flags=re.MULTILINE)
            start_idx = text.find('[')
            obj_start_idx = text.find('{')
            if start_idx == -1 and obj_start_idx == -1: return None
            if start_idx == -1 or (obj_start_idx != -1 and obj_start_idx < start_idx):
                start_idx = obj_start_idx
            json_candidate = text[start_idx:]
            
            # Try to find the end
            last_bracket = json_candidate.rfind(']')
            last_brace = json_candidate.rfind('}')
            end_idx = max(last_bracket, last_brace)
            if end_idx != -1:
                try: return json.loads(json_candidate[:end_idx+1])
                except: pass
                
            # Deep Repair
            repaired = self._try_repair_truncated_json(json_candidate)
            if repaired:
                try: return json.loads(repaired)
                except: pass
        except: pass
        return None

    def _try_repair_truncated_json(self, text: str) -> str:
        quotes = 0
        escaped = False
        for char in text:
            if char == '\\': escaped = not escaped
            elif char == '"' and not escaped: quotes += 1
            else: escaped = False
        if quotes % 2 != 0: text += '"'
        
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
