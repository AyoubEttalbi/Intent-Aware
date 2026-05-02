import json
from typing import Dict, Any, List
from extractors.parser import OpenAPIParser
from extractors.intent import IntentExtractor
from extractors.assumptions import AssumptionExtractor
from generators.scenarios import ScenarioGenerator
from execution.runner import TestRunner
from detection.layer1_contract import Layer1ContractChecker
from detection.layer2_behavioral import Layer2BehavioralChecker
from detection.layer3_llm_judge import Layer3LLMJudge
from reports.generator import ReportGenerator
from agent.state_graph import StateGraph
from execution.crawler import WebCrawler
from agent.personas import PersonaManager
import asyncio

class AgentLoop:
    def __init__(self, spec_url: str, description: str, base_url: str):
        self.spec_url = spec_url
        self.description = description
        self.base_url = base_url
        
        self.parser = OpenAPIParser()
        self.intent_extractor = IntentExtractor()
        self.assumption_extractor = AssumptionExtractor()
        self.scenario_generator = ScenarioGenerator()
        self.runner = TestRunner(base_url)
        self.layer1 = Layer1ContractChecker({})
        self.layer2 = Layer2BehavioralChecker()
        self.llm_judge = Layer3LLMJudge()
        self.state_graph = StateGraph()
        self.crawler = WebCrawler(base_url)
        self.persona_manager = PersonaManager()
        
        self.results = []
        self.contracts = []

    def _build_persona(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        persona_name = scenario.get("persona_name") or scenario.get("persona", "GUEST")
        persona = self.persona_manager.get_persona(persona_name)
        
        return {
            "persona_name": persona_name,
            "role": persona.role if persona else "guest",
            "user_id": persona.user_id if persona else "anonymous",
            "description": persona.description if persona else "Unknown persona",
            "expected_failure_type": scenario.get("expected_failure_type", "none"),
            "test_type": "security" if scenario.get("expected_failure_type") in (
                "auth_bypass", "data_leak", "idor", "privilege_escalation", 
                "mass_assignment", "unauthorized_access", "cross_user_access"
            ) else "functional"
        }

    async def run(self, max_assumptions: int = 2, crawl_ui: bool = False, source_dir: str = "."):
        print(f"🚀 Starting analysis for: {self.base_url}")
        
        # --- Phase 0: Source Analysis ---
        print("🔍 Phase 0: Analyzing source code...")
        from agent.source_analyzer import SourceAnalyzer
        analyzer = SourceAnalyzer(source_dir)
        app_context = analyzer.analyze()
        print(f"   App type: {app_context.app_type}, "
                 f"Models: {app_context.models}, "
                 f"Personas: {[p['name'] for p in app_context.personas]}")

        # --- Phase 1: Discovery (Shadow Spec) ---
        endpoints = []
        ui_context = {}
        if crawl_ui:
            print("🕷️ Phase 1: Crawling UI for context and hidden endpoints...")
            try:
                from execution.crawler import WebCrawler
                crawler = WebCrawler(self.base_url, app_context=app_context)
                crawl_result = await crawler.crawl(depth=2)
                endpoints = crawl_result["endpoints"]
                ui_context = crawl_result["ui_context"]
                print(f"   Discovered {len(endpoints)} endpoints, "
                         f"{len(ui_context)} pages with context")
                
                for err in crawler.ui_errors:
                    self.results.append({
                        "scenario": {"name": "UI/QA Audit", "endpoint": "", "method": "CRAWL"},
                        "response": {"status": 0, "latency": 0},
                        "check": {"is_bug": True, "severity": "medium", "reason": f"UI Bug: {err}"}
                    })
            except Exception as e:
                print(f"⚠️ Discovery failed: {e}")

        # 1. Parse Spec
        spec = self.parser.load_spec(self.spec_url)
        
        # Reachability Check
        has_spec = bool(spec)
        has_discovery = bool(endpoints)
        
        if not has_spec and not has_discovery:
            print("❌ REACHABILITY FAILURE: No spec found and UI discovery failed.")
            print("⚠️ The agent will NOT proceed with hallucinated scenarios.")
            return self.results

        # Combine discovered info into description for intent extractor
        if endpoints:
            self.description += "\n\nAdditionally, the following endpoint interactions were discovered via UI crawling:\n" + "\n".join(endpoints)
        
        print("✅ Analysis context prepared.")

        # --- Phase 2: Extract Intent & Assumptions ---
        print("🧠 Phase 2: Extracting intent and assumptions...")
        self.contracts = self.intent_extractor.extract(spec, self.description)
        
        ui_context_summary = {
            url: {
                "role": ctx.page_role,
                "entity": ctx.entity_type,
                "forms": len(ctx.forms),
                "url_params": ctx.url_params,
            }
            for url, ctx in ui_context.items()
        }
        
        assumptions = self.assumption_extractor.extract(
            endpoints=endpoints or list(spec.get("paths", {}).keys()),
            ui_context=ui_context_summary,
            app_context=app_context,
        )
        print(f"✅ Found {len(self.contracts)} contracts and {len(assumptions)} assumptions.")

        # 3. Initialize Checkers
        self.layer1 = Layer1ContractChecker(spec)

        # --- Phase 3: Generate & Deduplicate Scenarios ---
        print("⚙️ Phase 3: Generating and deduplicating scenarios...")
        from generators.scenarios import build_scenario_prompt
        from generators.dedup import deduplicate_scenarios
        
        all_scenarios = []
        
        # If we have UI context, generate from it
        if ui_context:
            for url, page_ctx in ui_context.items():
                # Skip static/tech pages to save time
                if any(tech in url.lower() for tech in ["/docs", "openapi.json", "/redoc"]):
                    continue
                
                print(f"   - Thinking about {url}...")
                prompt = build_scenario_prompt(page_ctx, app_context)
                scenarios = self.scenario_generator.generate(prompt)
                if scenarios:
                    print(f"     ✅ Generated {len(scenarios)} scenarios")
                all_scenarios.extend(scenarios)
        else:
            # Fallback to old assumption-based generation if no UI crawl
            print("   - No UI context found, falling back to assumption-based generation...")
            for assumption in assumptions[:max_assumptions]:
                scenarios = self.scenario_generator.generate(json.dumps(assumption))
                all_scenarios.extend(scenarios)

        # Deduplicate before execution
        unique_scenarios = deduplicate_scenarios(all_scenarios)
        print(f"   Generated {len(all_scenarios)} raw scenarios → "
                 f"{len(unique_scenarios)} after dedup")

        # --- Phase 4: Execution ---
        count = 0
        for scenario in unique_scenarios[:max_assumptions * 5]: # Arbitrary limit
            count += 1
            method = scenario.get('http_method') or scenario.get('method')
            endpoint = scenario.get('endpoint')
            
            if self.state_graph.is_explored(method, endpoint, scenario.get('payload') or scenario.get('body')):
                continue

            print(f"   [{count}] Executing: {scenario.get('name')} -> {method} {endpoint}")
            response = self.runner.execute(scenario)
            self.state_graph.mark_explored(method, endpoint, scenario.get('payload') or scenario.get('body'))

            result = self.layer1.check(scenario, response)
            
            if not result.get("is_bug"):
                result = self.layer2.check(scenario, response, self.results)

            is_security_test = scenario.get("attack_type") in ("auth_bypass", "idor", "privilege_escalation") or \
                               scenario.get("expected_failure_type") in ("auth_bypass", "idor", "data_leak")
            
            if not result.get("is_bug") and not (is_security_test and response.status_code in (401, 403, 404)):
                persona = self._build_persona(scenario)
                judge_result = self.llm_judge.judge(
                    contract={"all_contracts": self.contracts}, 
                    scenario=scenario, 
                    response=response,
                    persona=persona
                )
                if judge_result.get("is_bug"):
                    result = {
                        "is_bug": True,
                        "severity": judge_result.get("severity", "medium"),
                        "reason": judge_result.get("reasoning", "LLM Judge detected a violation."),
                        "bug_type": judge_result.get("bug_type", "unknown")
                    }
            
            outcome = {
                "scenario": scenario,
                "response": {
                    "status": response.status_code,
                    "latency": response.latency_ms
                },
                "check": result
            }
            
            self.results.append(outcome)
            if result.get("is_bug"):
                print(f"   🚩 BUG FOUND: {result['reason']}")
            else:
                pass

        print(f"\n✨ Analysis complete. Found {len([r for r in self.results if r['check']['is_bug']])} potential bugs.")
        
        report_gen = ReportGenerator(self.results, self.base_url)
        report_gen.save_report()
        
        return self.results

if __name__ == "__main__":
    print("Agent Loop updated.")
