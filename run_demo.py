import subprocess
import time
import requests
import sys
import os

def main():
    print("🚀 Starting Demo: Intent-Aware Agent vs Vulnerable Target App")

    # 1. Start the Target App in the background
    print("📦 Starting Target App on port 8080...")
    target_process = subprocess.Popen(
        [sys.executable, "target_app/main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # 2. Wait for it to be ready
    time.sleep(3)
    try:
        requests.get("http://localhost:8080/")
        print("✅ Target App is ready.")
    except Exception as e:
        print(f"❌ Failed to start Target App: {e}")
        target_process.terminate()
        return

    # 3. Start the Agent API in the background
    print("🤖 Starting Agent API on port 8000...")
    agent_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.main:app", "--port", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # 4. Wait for it to be ready
    time.sleep(3)
    try:
        requests.get("http://localhost:8000/")
        print("✅ Agent API is ready.")
    except Exception as e:
        print(f"❌ Failed to start Agent API: {e}")
        target_process.terminate()
        agent_process.terminate()
        return

    # 5. Trigger an analysis
    print("\n🕵️ Triggering Analysis...")
    payload = {
        "spec_url": "http://localhost:8080/openapi.json",
        "description": "A user management and ordering system. Users should only see their own data and cannot escalate privileges.",
        "base_url": "http://localhost:8080",
        "source_dir": "target_app",
        "max_assumptions": 3,
        "crawl_ui": True
    }
    
    response = requests.post("http://localhost:8000/analyze", json=payload)
    if response.status_code == 200:
        job_id = response.json()["job_id"]
        print(f"✅ Job submitted: {job_id}")
        
        # Poll for status
        print("⏳ Analyzing (this may take a minute)...")
        while True:
            status_resp = requests.get(f"http://localhost:8000/status/{job_id}")
            status = status_resp.json()["status"]
            if status == "completed":
                print("\n✨ Analysis Complete!")
                break
            elif status == "failed":
                print(f"\n❌ Analysis Failed: {status_resp.json().get('error')}")
                break
            time.sleep(5)
            print(".", end="", flush=True)

    # 6. Show results
    print("\n📑 Results summary:")
    # We can check the latest report markdown file
    if os.path.exists("latest_report.md"):
        with open("latest_report.md", "r") as f:
            print("-" * 30)
            print(f.read())
            print("-" * 30)

    # 7. Cleanup
    print("\n🛑 Cleaning up processes...")
    target_process.terminate()
    agent_process.terminate()
    print("Done.")

if __name__ == "__main__":
    main()
