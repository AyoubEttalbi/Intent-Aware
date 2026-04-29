import sys
import os
import asyncio
import subprocess
import time
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

from execution.crawler import WebCrawler

async def test_crawler():
    print("🚀 Starting Target App for Crawler Test...")
    target_process = subprocess.Popen(
        [sys.executable, "target_app/main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for app to be ready
    time.sleep(2)
    
    BASE_URL = "http://localhost:8080"
    crawler = WebCrawler(BASE_URL)
    
    print(f"🕵️  Crawl started on {BASE_URL}...")
    endpoints = await crawler.crawl(depth=1)
    
    print("\n" + "="*50)
    print("🛰️  DISCOVERED ENDPOINTS (SHADOW SPEC)")
    print("="*50)
    
    if not endpoints:
        print("❌ No endpoints discovered. Make sure the target app has clickable elements that trigger API calls.")
    else:
        for i, endpoint in enumerate(sorted(endpoints)):
            print(f"{i+1}. {endpoint}")
            
    print("="*50)
    
    # Cleanup
    target_process.terminate()
    print("\n✅ Test complete.")

if __name__ == "__main__":
    asyncio.run(test_crawler())
