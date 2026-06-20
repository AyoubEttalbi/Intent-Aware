"""
qa/ — the smart, LLM-driven QA crawler.

Behaves like a human QA engineer: explores every page, understands each screen's
intent, generates and runs concrete test cases (happy / negative / boundary /
validation), captures evidence (screenshots, console/JS/network errors), and
reports professional bug reports. Also captures a "shadow spec" of the real API
calls the UI makes, which is fed back into the security attack matrix.
"""
