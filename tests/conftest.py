"""
tests/conftest.py — shared fixtures for the v2 engine test-suite.

Boots the bundled `target_app` on localhost (no LLM, no browser) so the
deterministic security core can be exercised fast and offline. Helpers log in
real sessions via httpx so identity-aware tests don't need Playwright.
"""
from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TargetApp:
    def __init__(self, port: int):
        self.port = port
        self.base_url = f"http://127.0.0.1:{port}"
        self.spec_url = f"{self.base_url}/openapi.json"

    def login(self, username: str, password: str) -> dict:
        """Form-login and return the session cookie dict (no browser)."""
        with httpx.Client(base_url=self.base_url, follow_redirects=False) as c:
            r = c.post("/login", data={"username": username, "password": password})
            cookies = {k: v for k, v in r.cookies.items()}
            return cookies


@pytest.fixture(scope="session")
def target_app():
    """Start target_app bound to 127.0.0.1 on a free port; tear down by pid."""
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "target_app.main:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(PROJECT_ROOT),
    )
    app = TargetApp(port)
    # wait for readiness
    deadline = time.time() + 30
    ready = False
    while time.time() < deadline:
        try:
            if httpx.get(app.spec_url, timeout=2).status_code == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.3)
    if not ready:
        proc.terminate()
        raise RuntimeError("target_app failed to start")
    yield app
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
