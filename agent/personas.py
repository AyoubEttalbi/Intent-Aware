from typing import Dict, Any, List, Optional
from dataclasses import dataclass

@dataclass
class Persona:
    name: str
    user_id: str
    role: str
    token: str
    description: str

class PersonaManager:
    def __init__(self):
        # In a real app, these would come from a config or the /analyze request
        self.personas: Dict[str, Persona] = {
            "ADMIN_ALICE": Persona(
                name="ADMIN_ALICE",
                user_id="1",
                role="admin",
                token="alice-token",
                description="Administrative user with full access."
            ),
            "USER_BOB": Persona(
                name="USER_BOB",
                user_id="2",
                role="user",
                token="bob-token",
                description="Regular user. Owns resources with ID 2."
            ),
            "USER_EVE": Persona(
                name="USER_EVE",
                user_id="3",
                role="user",
                token="eve-token",
                description="Another regular user. Owns resources with ID 3. Often used as an attacker."
            ),
            "GUEST": Persona(
                name="GUEST",
                user_id="anonymous",
                role="guest",
                token="",
                description="Unauthenticated visitor."
            )
        }

    def get_persona(self, name: str) -> Optional[Persona]:
        return self.personas.get(name)

    def get_all_personas(self) -> List[Persona]:
        return list(self.personas.values())

    def get_persona_context_for_llm(self) -> str:
        """Returns a string description of available personas for LLM prompting."""
        context = "Available Personas for Testing:\n"
        for p in self.personas.values():
            context += f"- {p.name} (ID: {p.user_id}, Role: {p.role}): {p.description}\n"
        return context

if __name__ == "__main__":
    pm = PersonaManager()
    print(pm.get_persona_context_for_llm())
