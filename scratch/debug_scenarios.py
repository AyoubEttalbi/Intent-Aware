import json
import asyncio
from agent.models import AppContext, PageContext, FormField
from generators.scenarios import ScenarioGenerator, build_scenario_prompt

# Mock AppContext
app_ctx = AppContext(
    app_type="vulnerability_demo",
    tech_stack=["FastAPI", "Python"],
    models=["UserResponse", "UpdateUserRequest"],
    routes=[{"method": "GET", "path": "/users/{user_id}"}],
    personas=[{"name": "admin"}, {"name": "regular_user"}],
    auth_flow={"login_url": None}
)

# Mock PageContext for the root page (has forms)
page_ctx = PageContext(
    url="http://localhost:8080/",
    title="Pet Clinic Dashboard",
    page_role="registration_dashboard",
    auth_required=False,
    entity_type="user",
    forms=[
        {
            "action": "",
            "method": "POST",
            "submit_label": "Register Now",
            "fields": [
                FormField(name="reg-name", field_type="text", label="Full Name", required=True, placeholder="", options=[], validation_hint=""),
                FormField(name="reg-email", field_type="email", label="Email", required=True, placeholder="", options=[], validation_hint=""),
                FormField(name="reg-pass", field_type="password", label="Password", required=True, placeholder="", options=[], validation_hint="")
            ]
        }
    ],
    url_params=[]
)

generator = ScenarioGenerator()
prompt = build_scenario_prompt(page_ctx, app_ctx)
print("--- PROMPT ---")
print(prompt)

scenarios = generator.generate(prompt)
print("\n--- GENERATED SCENARIOS ---")
print(json.dumps(scenarios, indent=2))
