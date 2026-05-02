import time
from agent.llm import LLMClient

def test_speed():
    print("🤖 Initializing LLM Client...")
    try:
        llm = LLMClient()
    except Exception as e:
        print(f"❌ Failed to initialize LLM: {e}")
        return

    print(f"📡 Provider: {llm.provider_name}")
    print(f"🧠 Model: {llm.provider.model}")
    print("-" * 40)

    # Test 1: Simple Prompt
    print("⏳ Test 1: Simple short prompt...")
    start_time = time.perf_counter()
    response = llm.ask(
        system_prompt="You are a helpful assistant.",
        user_prompt="Say 'Hello, World!' and nothing else.",
        max_tokens=50
    )
    end_time = time.perf_counter()
    latency = end_time - start_time
    
    print(f"✅ Response received in {latency:.2f} seconds.")
    print(f"💬 Output: {response.strip()}")
    print("-" * 40)

    # Test 2: Complex Prompt (Simulating Scenario Generation)
    print("⏳ Test 2: Complex JSON generation prompt (simulating Agent workload)...")
    complex_system = "You are a security auditor. Output ONLY valid JSON."
    complex_user = """Analyze this endpoint and generate 3 security test scenarios.
Endpoint: POST /api/login
Body: {"username": "str", "password": "str"}
App Type: user management

Return a JSON list of objects, each containing: 'id', 'name', 'attack_type', 'payload'.
"""
    start_time = time.perf_counter()
    response = llm.ask(
        system_prompt=complex_system,
        user_prompt=complex_user,
        max_tokens=1000
    )
    end_time = time.perf_counter()
    latency = end_time - start_time
    
    print(f"✅ Response received in {latency:.2f} seconds.")
    print(f"📏 Output length: {len(response)} characters.")
    print("-" * 40)
    
    print("💡 Analysis:")
    if latency > 30:
        print("⚠️ Your LLM is responding very slowly (>30s per request).")
        print("   Since the Agent makes 5-10 requests per analysis, this is why the demo takes several minutes.")
        print("   Consider switching to a faster model (like Llama3 8B) or a different provider if this is too slow.")
    else:
        print("✅ The LLM speed looks healthy.")

if __name__ == "__main__":
    test_speed()
