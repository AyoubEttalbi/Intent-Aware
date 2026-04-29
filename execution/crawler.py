import asyncio
import json
from playwright.async_api import async_playwright
from typing import Set, Dict, List, Any
from urllib.parse import urljoin, urlparse
from datetime import datetime
from agent.llm import LLMClient

class WebCrawler:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.discovered_endpoints = set()
        self.visited_urls = set()
        self.ui_errors = set() # Changed to set for deduplication
        self.domain = urlparse(base_url).netloc
        self.llm = LLMClient()
        # Setup file logging
        with open("crawler_log.txt", "w") as f:
            f.write(f"--- Crawler Log for {base_url} ---\n")

    async def crawl(self, depth: int = 2) -> List[str]:
        """
        Crawls the web UI and discovers API endpoints from network traffic.
        """
        async with async_playwright() as p:
            self._log_action("🚀 Playwright started. Launching browser...")
            browser = await p.chromium.launch(headless=False, slow_mo=500)
            context = await browser.new_context()
            page = await context.new_page()
            self._log_action("✅ Browser & Page ready.")

            # Create a visual log overlay
            await page.add_init_script("""
                const div = document.createElement('div');
                div.id = 'agent-log';
                div.style.position = 'fixed';
                div.style.bottom = '10px';
                div.style.right = '10px';
                div.style.backgroundColor = 'rgba(0,0,0,0.85)';
                div.style.color = 'white';
                div.style.padding = '12px';
                div.style.borderRadius = '8px';
                div.style.zIndex = '10000';
                div.style.fontSize = '12px';
                div.style.fontFamily = 'Inter, system-ui, sans-serif';
                div.style.maxWidth = '320px';
                div.style.boxShadow = '0 4px 15px rgba(0,0,0,0.3)';
                div.style.border = '1px solid #444';
                div.innerHTML = '<b style="color: #4ade80">🤖 Intent-Aware Agent</b><br><div id="log-content" style="margin-top: 5px; color: #ccc">Initializing...</div>';
                document.documentElement.appendChild(div);
                
                window.updateAgentStatus = (msg) => {
                    let content = document.getElementById('log-content');
                    if (!content) {
                        const div = document.createElement('div');
                        div.id = 'agent-log';
                        div.style.position = 'fixed';
                        div.style.bottom = '10px';
                        div.style.right = '10px';
                        div.style.backgroundColor = 'rgba(0,0,0,0.85)';
                        div.style.color = 'white';
                        div.style.padding = '12px';
                        div.style.borderRadius = '8px';
                        div.style.zIndex = '10000';
                        div.style.fontSize = '12px';
                        div.style.fontFamily = 'Inter, system-ui, sans-serif';
                        div.style.maxWidth = '320px';
                        div.style.boxShadow = '0 4px 15px rgba(0,0,0,0.3)';
                        div.style.border = '1px solid #444';
                        div.innerHTML = '<b style="color: #4ade80">🤖 Intent-Aware Agent</b><br><div id="log-content" style="margin-top: 5px; color: #ccc"></div>';
                        document.documentElement.appendChild(div);
                        content = document.getElementById('log-content');
                    }
                    if (content) content.innerText = msg;
                };
            """)

            # Listener for network requests
            def handle_request(request):
                url = request.url
                if request.resource_type in ["fetch", "xhr"]:
                    self.discovered_endpoints.add(f"{request.method} {url}")

            page.on("request", handle_request)
            page.on("console", lambda msg: self.ui_errors.add(f"Console {msg.type}: {msg.text}") if msg.type == "error" else None)
            page.on("pageerror", lambda err: self.ui_errors.add(f"JS Exception: {err.message}"))
            page.on("response", lambda res: self.ui_errors.add(f"Broken Resource: {res.url} (Status {res.status})") if res.status >= 400 else None)

            self._log_action(f"🕵️ Starting UI Discovery at {self.base_url}")
            await self._visit_url(page, self.base_url, depth)
            
            # --- FINAL SUMMARY LOGGING ---
            self._log_action("\n" + "="*50)
            self._log_action("📊 DISCOVERY SUMMARY")
            self._log_action("="*50)
            
            self._log_action(f"\n📂 SHADOW SPEC (Discovered API Endpoints: {len(self.discovered_endpoints)})")
            for endpoint in sorted(list(self.discovered_endpoints)):
                self._log_action(f"  - {endpoint}")
            
            self._log_action(f"\n🚩 UI BUG AUDIT (Unique Issues: {len(self.ui_errors)})")
            for err in sorted(list(self.ui_errors)):
                self._log_action(f"  - {err}")
            
            self._log_action("\n" + "="*50)
            self._log_action("🏁 Discovery loop finished.")

            print("🏁 Discovery complete. Results appended to crawler_log.txt")
            await page.evaluate("if(window.updateAgentStatus) window.updateAgentStatus('🏁 Discovery Complete!')")
            await asyncio.sleep(5)
            await browser.close()
            
        return list(self.discovered_endpoints)

    def _log_action(self, msg: str):
        with open("crawler_log.txt", "a") as f:
            f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")

    async def _get_inputs_for_button(self, button_el) -> List[Dict[str, Any]]:
        """Finds inputs associated with a specific button (in same form or container)."""
        inputs = await button_el.evaluate_handle("""el => {
            const form = el.closest('form');
            if (form) return Array.from(form.querySelectorAll('input, textarea, select'));
            const container = el.closest('div') || el.parentElement;
            return Array.from(container.querySelectorAll('input, textarea, select'));
        }""")
        
        elements = await inputs.get_properties()
        context = []
        for prop in elements.values():
            el = prop.as_element()
            if el and await el.is_visible():
                info = await el.evaluate("""el => {
                    return {
                        tag: el.tagName,
                        type: el.type || 'text',
                        name: el.name || '',
                        id: el.id || '',
                        placeholder: el.placeholder || '',
                        label: document.querySelector(`label[for="${el.id}"]`)?.innerText || ''
                    }
                }""")
                context.append({"element": el, "info": info})
        return context

    async def _fill_form_smartly(self, page, form_context: List[Dict[str, Any]]):
        """Uses LLM to decide what to fill in the form fields."""
        if not form_context:
            return

        fields_desc = [f"{c['info']['tag']} (name={c['info']['name']}, type={c['info']['type']}, placeholder={c['info']['placeholder']}, label={c['info']['label']})" for c in form_context]
        
        self._log_action(f"🧠 Contextual Fill: Analyzing {len(form_context)} related fields...")
        await page.evaluate("if(window.updateAgentStatus) window.updateAgentStatus('🧠 Analyzing related fields...')")

        prompt = f"""
        I am an autonomous QA agent targeting a button. I found these associated inputs:
        {json.dumps(fields_desc, indent=2)}

        Suggest realistic/adversarial test values.
        Return a JSON object: {{"name_or_id": "value_to_type"}}.
        """
        
        suggestions = self.llm.ask_json(
            system_prompt="You are a QA expert. Suggest input values.",
            user_prompt=prompt
        )

        self._log_action(f"🤖 LLM Suggested Values: {json.dumps(suggestions)}")

        for item in form_context:
            info = item['info']
            el = item['element']
            key = info['name'] or info['id']
            val = suggestions.get(key) or suggestions.get(info['placeholder']) or "test"
            try:
                self._log_action(f"  ⌨️  Filling '{key}' -> '{val}'")
                await el.fill(str(val))
                await el.evaluate("el => el.style.backgroundColor = '#fff9c4'")
            except: pass

    async def _visit_url(self, page, url: str, depth: int):
        if depth < 0 or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        self._log_action(f"📍 Visiting: {url} (Depth: {depth})")

        try:
            await page.goto(url, wait_until="networkidle", timeout=15000)
            path = urlparse(url).path or "/"
            await page.evaluate(f"if(window.updateAgentStatus) window.updateAgentStatus('📍 At: {path}')")
            
            i = 0
            while True:
                elements = await page.query_selector_all("a, button")
                if i >= len(elements):
                    break
                
                el = elements[i]
                i += 1

                if not await el.is_visible():
                    continue

                text = (await el.inner_text()).strip() or "[Icon]"
                tag = await el.evaluate("el => el.tagName")
                
                await el.evaluate("el => el.style.outline = '3px solid #f87171'")
                safe_text = text[:20].replace("'", "\\'")
                await page.evaluate(f"if(window.updateAgentStatus) window.updateAgentStatus('🎯 Targeting: {safe_text}')")
                await asyncio.sleep(0.3)

                if tag == "A":
                    href = await el.get_attribute("href")
                    if href:
                        full_url = urljoin(url, href)
                        if urlparse(full_url).netloc == self.domain and full_url not in self.visited_urls:
                            self._log_action(f"🖱️ Clicking <{tag}>: '{text}' -> {full_url}")
                            try:
                                await el.click()
                                await page.wait_for_load_state("networkidle", timeout=5000)
                                await self._visit_url(page, page.url, depth - 1)
                                await page.goto(url, wait_until="networkidle")
                            except: pass
                else:
                    related_inputs = await self._get_inputs_for_button(el)
                    if related_inputs:
                        self._log_action(f"✨ Found {len(related_inputs)} inputs for button '{text}'.")
                        await self._fill_form_smartly(page, related_inputs)

                    self._log_action(f"🖱️ Clicking <{tag}>: '{text}'")
                    try:
                        await el.click()
                        await asyncio.sleep(1)
                    except: pass
                
                try: await el.evaluate("el => el.style.outline = ''")
                except: pass

        except Exception as e:
            self._log_action(f"⚠️ Error at {url}: {e}")

if __name__ == "__main__":
    async def main():
        crawler = WebCrawler("http://localhost:8080")
        endpoints = await crawler.crawl(depth=1)
        print(f"✅ Discovered {len(endpoints)} endpoints.")

    asyncio.run(main())

