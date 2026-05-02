import os
import json
from pathlib import Path
from agent.llm import LLMClient
from agent.models import AppContext

# File extensions to read
SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".cs"}

# Directory names to skip entirely
SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv", 
             "dist", "build", ".next", "coverage", "migrations"}

# Filenames that are highest priority for route/auth/model info
PRIORITY_KEYWORDS = ["route", "router", "view", "controller", "model", 
                     "schema", "middleware", "auth", "permission", "main", "app", "index"]


SOURCE_ANALYSIS_PROMPT = """You are a senior software architect performing a security-focused code review.
Analyze the provided source code and return ONLY a valid JSON object with this exact structure:

{
  "routes": [
    {
      "method": "GET",
      "path": "/path",
      "auth_required": true,
      "roles": ["admin"],
      "description": "..."
    }
  ],
  "models": [],
  "auth_flow": {
    "login_path": null,
    "username_field": "email",
    "password_field": "password",
    "default_credentials": {
      "admin": {"username": "admin@example.com", "password": "admin123"}
    }
  },
  "app_type": "...",
  "personas": [
    {"name": "admin", "role": "admin", "can_access_patterns": ["*"]},
    {"name": "unauthenticated", "role": null, "can_access_patterns": []}
  ],
  "tech_stack": []
}

Strict Rules:
1. NO HALLUCINATIONS: Do not include ANY route, persona, or auth_path that is not explicitly defined in the provided source code.
2. If you don't find a dedicated login route, set "login_path" to null.
3. derive "app_type" from the business logic (e.g., "medical", "finance").
4. Return ONLY the JSON. No markdown backticks."""


class SourceAnalyzer:
    def __init__(self, source_dir: str):
        self.source_dir = Path(source_dir)
        self.llm = LLMClient()

    def analyze(self) -> AppContext:
        source_dump = self._collect_source_prioritized()
        
        raw = self.llm.ask_json(
            system_prompt=SOURCE_ANALYSIS_PROMPT,
            user_prompt=f"Source code:\n\n{source_dump}"
        )
        
        if not raw:
            return AppContext()

        ctx = AppContext(
            routes=raw.get("routes", []),
            models=raw.get("models", []),
            auth_flow=raw.get("auth_flow", {}),
            app_type=raw.get("app_type", "generic"),
            personas=raw.get("personas", []),
            tech_stack=raw.get("tech_stack", []),
        )

        # Always ensure unauthenticated persona exists
        has_unauth = any(p.get("role") is None for p in ctx.personas)
        if not has_unauth:
            ctx.personas.append({
                "name": "unauthenticated",
                "role": None,
                "can_access_patterns": []
            })

        return ctx

    def _collect_source_prioritized(self, char_limit: int = 40000) -> str:
        """
        Collect source files in priority order:
        1. Files matching PRIORITY_KEYWORDS in their name
        2. All other source files
        Truncate at char_limit total.
        """
        priority_files = []
        other_files = []

        for root, dirs, files in os.walk(self.source_dir):
            # Prune skip dirs in-place so os.walk doesn't descend into them
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            
            for filename in files:
                filepath = Path(root) / filename
                if filepath.suffix not in SOURCE_EXTENSIONS:
                    continue
                name_lower = filename.lower()
                if any(kw in name_lower for kw in PRIORITY_KEYWORDS):
                    priority_files.append(filepath)
                else:
                    other_files.append(filepath)

        collected = []
        total = 0

        for filepath in priority_files + other_files:
            if total >= char_limit:
                break
            try:
                content = filepath.read_text(errors="ignore")
                # Take first 3000 chars of each file — enough to see routes/models
                snippet = content[:3000]
                rel = filepath.relative_to(self.source_dir)
                entry = f"### {rel}\n{snippet}"
                collected.append(entry)
                total += len(entry)
            except Exception:
                continue

        return "\n\n".join(collected)
