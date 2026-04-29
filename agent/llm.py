import os
import json
import anthropic
from openai import OpenAI
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
from dotenv import load_dotenv

load_dotenv()

class LLMProvider(ABC):
    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000) -> str:
        pass

class ClaudeProvider(LLMProvider):
    def __init__(self, api_key: str, model: str = "claude-3-5-sonnet-20240620"):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}]
        )
        return response.content[0].text

class OllamaProvider(LLMProvider):
    def __init__(self, base_url: str, api_key: str = "ollama", model: str = "llama3"):
        # Ollama often uses OpenAI-compatible API
        self.client = OpenAI(base_url=base_url, api_key=api_key)
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            max_tokens=max_tokens
        )
        return response.choices[0].message.content

class LLMClient:
    def __init__(self):
        self.provider_name = os.getenv("LLM_PROVIDER", "claude").lower()
        self.provider = self._setup_provider()

    def _setup_provider(self) -> LLMProvider:
        if self.provider_name == "claude":
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not found in .env")
            return ClaudeProvider(api_key=api_key, model=os.getenv("CLAUDE_MODEL", "claude-3-5-sonnet-20240620"))
        
        elif self.provider_name == "ollama":
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
            api_key = os.getenv("OLLAMA_API_KEY", "ollama")
            model = os.getenv("OLLAMA_MODEL", "llama3")
            return OllamaProvider(base_url=base_url, api_key=api_key, model=model)
        
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider_name}")

    def ask(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000) -> str:
        return self.provider.generate(system_prompt, user_prompt, max_tokens)

    def ask_json(self, system_prompt: str, user_prompt: str, max_tokens: int = 4000, retries: int = 1) -> Dict[str, Any]:
        for attempt in range(retries + 1):
            raw_response = self.ask(system_prompt, user_prompt, max_tokens)
            try:
                # 1. Clean up potential markdown code blocks
                clean_response = raw_response.strip()
                if clean_response.startswith("```"):
                    # Remove first line (the ```json) and last line (the ```)
                    lines = clean_response.split("\n")
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].strip() == "```":
                        lines = lines[:-1]
                    clean_response = "\n".join(lines).strip()
                
                # 2. Extract content between first { and last }
                start = clean_response.find("{")
                end = clean_response.rfind("}") + 1
                if start == -1 or end == 0:
                    raise ValueError("No JSON object found in response")
                
                json_str = clean_response[start:end]
                
                # 3. Handle common small LLM errors (trailing commas, etc.)
                # This is a very basic fix, could be improved with regex
                # But for now, we'll try to load it as is
                return json.loads(json_str)
                
            except (json.JSONDecodeError, ValueError) as e:
                if attempt < retries:
                    print(f"⚠️ JSON parse failed (attempt {attempt+1}/{retries+1}), retrying with stronger emphasis...")
                    user_prompt += "\n\nIMPORTANT: Your previous response had a JSON syntax error. Please ensure the JSON is perfectly valid and has no trailing commas or missing delimiters."
                    continue
                
                print(f"❌ Error parsing JSON from LLM after {retries+1} attempts: {e}")
                preview = raw_response[:500] + "..." if len(raw_response) > 500 else raw_response
                print(f"🔍 Final raw response preview:\n{preview}")
                return {}
        return {}
