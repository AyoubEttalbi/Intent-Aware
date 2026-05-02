import requests
import time
import sys
import os
import argparse
import json
from agent.llm import LLMClient
from dotenv import load_dotenv

load_dotenv()

def get_smart_description(url: str) -> str:
    """Uses the LLM to research/infer the purpose of the site and key security risks."""
    llm = LLMClient()
    prompt = f"""
    I am about to run an autonomous security audit on this URL: {url}
    
    Based on the URL name and common industry knowledge:
    1. What is the likely purpose of this site?
    2. What are the top 3 high-impact security intents I should verify? (e.g. data isolation, role-based access, payment security)
    3. Suggest a 2-3 sentence description for the agent to use as its 'ground truth' rules.
    
    Return a JSON object with: {{"likely_purpose": "...", "top_risks": ["...", "..."], "agent_description": "..."}}
    """
    
    print(f"🧠 Researching target: {url}...")
    result = llm.ask_json(
        system_prompt="You are a senior security researcher and pentester.",
        user_prompt=prompt
    )
    return result.get("agent_description", "A web application requiring security and functional audit.")

def probe_for_spec(base_url: str) -> str:
    """Tries to find an OpenAPI spec in common locations."""
    common_paths = [
        "/openapi.json",
        "/swagger.json",
        "/api/v1/openapi.json",
        "/api/openapi.json",
        "/docs/openapi.json"
    ]
    
    print(f"🔍 Probing for OpenAPI spec at {base_url}...")
    for path in common_paths:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200 and ("openapi" in resp.text.lower() or "swagger" in resp.text.lower()):
                print(f"✅ Found spec at: {url}")
                return url
        except:
            continue
    
    print("⚠️ No public OpenAPI spec found. Relying on UI Discovery (Crawling).")
    return None

def main():
    parser = argparse.ArgumentParser(description="Run the Intent-Aware Agent on a real-world URL.")
    parser.add_argument("url", help="The base URL of the target application (e.g., https://example.com)")
    parser.add_argument("--assumptions", type=int, default=3, help="Max assumptions to test")
    parser.add_argument("--no-crawl", action="store_true", help="Disable UI crawling")
    
    args = parser.parse_args()
    base_url = args.url.rstrip("/")

    # 1. Smart Research
    description = get_smart_description(base_url)
    print(f"🤖 Smart Agent Description: {description}")

    # 2. Spec Probing
    spec_url = probe_for_spec(base_url)

    # 3. Check if Agent API is running
    print("📡 Connecting to Agent API on port 8000...")
    try:
        requests.get("http://localhost:8000/", timeout=2)
    except:
        print("❌ Agent API is not running. Please start it with: python3 -m uvicorn api.main:app --port 8000")
        return

    # 4. Trigger Analysis
    print(f"\n🕵️ Triggering Analysis for {base_url}...")
    payload = {
        "spec_url": spec_url or f"{base_url}/openapi.json", # Fallback if probing failed
        "description": description,
        "base_url": base_url,
        "max_assumptions": args.assumptions,
        "crawl_ui": not args.no_crawl
    }
    
    response = requests.post("http://localhost:8000/analyze", json=payload)
    if response.status_code != 200:
        print(f"❌ Failed to submit job: {response.text}")
        return

    job_id = response.json()["job_id"]
    print(f"✅ Job submitted: {job_id}")
    
    # 5. Polling
    print("⏳ Analyzing (this may take a few minutes)...")
    last_status = None
    while True:
        try:
            status_resp = requests.get(f"http://localhost:8000/status/{job_id}", timeout=5)
            data = status_resp.json()
            status = data["status"]
            
            if status != last_status:
                print(f"\nStatus: {status.upper()}")
                last_status = status
            
            if status == "completed":
                print("\n✨ Analysis Complete!")
                break
            elif status == "failed":
                print(f"\n❌ Analysis Failed: {data.get('error')}")
                break
            
            time.sleep(10)
            print(".", end="", flush=True)
        except Exception as e:
            print(f"\n⚠️ Polling error: {e}")
            time.sleep(5)

    # 6. Show results
    if os.path.exists("latest_report.md"):
        print("\n" + "="*50)
        print("📊 FINAL AUDIT REPORT SUMMARY")
        print("="*50)
        with open("latest_report.md", "r") as f:
            lines = f.readlines()
            # Just show the summary and the bug titles
            for line in lines[:30]:
                print(line.strip())
            print("\n... (Full report saved to latest_report.md)")
        print("="*50)

if __name__ == "__main__":
    main()
