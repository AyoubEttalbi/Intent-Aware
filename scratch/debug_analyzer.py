import json
from agent.source_analyzer import SourceAnalyzer

analyzer = SourceAnalyzer("target_app")
ctx = analyzer.analyze()
print(f"App Type: {ctx.app_type}")
print(f"Models: {ctx.models}")
print(f"Personas: {[p['name'] for p in ctx.personas]}")
print(f"Routes: {len(ctx.routes)}")
print(f"Auth Login URL: {ctx.auth_flow.get('login_url')}")
