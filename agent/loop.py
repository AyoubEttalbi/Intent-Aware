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
        self.layer1 = Layer1ContractChecker({}) # Updated in run()
        self.layer2 = Layer2BehavioralChecker()
        self.llm_judge = Layer3LLMJudge()
        self.state_graph = StateGraph()
        self.crawler = WebCrawler(base_url)
        
        self.results = []

        self.contracts = []


    def run(self, max_assumptions: int = 2, crawl_ui: bool = False):
        print(f"🚀 Starting analysis for: {self.base_url}")
        
        # 0. Discovery (Shadow Spec)
        discovered_endpoints = []
        if crawl_ui:
            print("🔍 Discovery Phase: Crawling UI for hidden endpoints...")
            try:
                discovered_endpoints = asyncio.run(self.crawler.crawl(depth=1))
                print(f"✅ Discovered {len(discovered_endpoints)} endpoint interactions.")
                
                # Report unique UI Errors found during crawl
                for err in self.crawler.ui_errors:
                    self.results.append({
                        "scenario": {"name": "UI/QA Audit", "endpoint": "", "method": "CRAWL"},
                        "response": {"status": 0, "latency": 0},
                        "check": {"is_bug": True, "severity": "medium", "reason": f"UI Bug: {err}"}
                    })
            except Exception as e:
                print(f"⚠️ Discovery failed: {e}")

        # 1. Parse Spec
        spec = self.parser.load_spec(self.spec_url)
        
        # 1b. Merge Shadow Spec into analysis context
        # We append discovered endpoints to the description so the LLM knows they exist
        if discovered_endpoints:
            self.description += "\n\nAdditionally, the following endpoint interactions were discovered via UI crawling:\n" + "\n".join(discovered_endpoints)
        
        print("✅ Analysis context prepared.")

        # 2. Extract Intent & Assumptions
        self.contracts = self.intent_extractor.extract(spec, self.description)
        assumptions = self.assumption_extractor.extract(spec, self.description)
        print(f"✅ Found {len(self.contracts)} contracts and {len(assumptions)} assumptions.")

        # 3. Initialize Checkers
        self.layer1 = Layer1ContractChecker(spec)

        # 4. Process Assumptions
        count = 0
        for assumption in assumptions[:max_assumptions]:
            count += 1
            print(f"\n[{count}] Targeting Assumption: {assumption['description']}")
            
            scenarios = self.scenario_generator.generate(assumption, spec)
            print(f"   Generated {len(scenarios)} scenarios.")

            for scenario in scenarios:
                if self.state_graph.is_explored(scenario['method'], scenario['endpoint'], scenario.get('body')):
                    print(f"   ⏭️ Skipping already explored: {scenario['method']} {scenario['endpoint']}")
                    continue

                print(f"   - Executing: {scenario['name']} ({scenario['method']} {scenario['endpoint']})")
                response = self.runner.execute(scenario)
                self.state_graph.mark_explored(scenario['method'], scenario['endpoint'], scenario.get('body'))

                result = self.layer1.check(scenario, response)
                
                if not result.get("is_bug"):
                    result = self.layer2.check(scenario, response, self.results)

                if not result.get("is_bug"):
                    judge_result = self.llm_judge.judge(
                        contract={"all_contracts": self.contracts}, 
                        scenario=scenario, 
                        response=response
                    )
                    if judge_result.get("is_bug"):
                        result = {
                            "is_bug": True,
                            "severity": judge_result.get("severity", "medium"),
                            "reason": judge_result.get("reasoning", "LLM Judge detected a violation.")
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
                    print(f"   ✅ Passed.")

        print(f"\n✨ Analysis complete. Found {len([r for r in self.results if r['check']['is_bug']])} potential bugs.")
        
        # 5. Generate Report
        report_gen = ReportGenerator(self.results, self.base_url)
        report_gen.save_report()
        
        return self.results

if __name__ == "__main__":
    # Example usage (commented out)
    # loop = AgentLoop("https://petstore.swagger.io/v2/swagger.json", "Pet store API", "https://petstore.swagger.io/v2")
    # loop.run(max_assumptions=2)
    print("Agent Loop initialized.")
