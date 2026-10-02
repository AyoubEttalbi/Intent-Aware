"""
tests/test_visible_chrome.py — the visible-browser launcher for watch mode.

Each `ensure_visible_chrome()` launches a FRESH Windows Chrome (never reuses:
a reused window could host the user's real tabs) on a random loopback port
with a fresh native profile, and returns a VisibleBrowser the caller must
release. No network, no browser, no subprocess: urlopen/Popen/mkdtemp are
stubbed. Never launches anything real.
"""
from __future__ import annotations

import io
import urllib.error

import pytest

from qa import visible_chrome as vc


def _resp_ok():
    return io.BytesIO(b'{"Browser": "Chrome/1.0", "webSocketDebuggerUrl": "ws://x"}')


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("VISIBLE_CHROME_BIN", str(tmp_path / "chrome.exe"))
    monkeypatch.setenv("VISIBLE_CHROME_HOST", "127.0.0.1")
    monkeypatch.setattr(vc.os.path, "isfile", lambda _p: True)


def test_windows_host_override_and_default(monkeypatch):
    assert vc._windows_host() == "127.0.0.1"
    monkeypatch.setenv("VISIBLE_CHROME_HOST", "127.0.0.2")
    assert vc._windows_host() == "127.0.0.2"
    monkeypatch.delenv("VISIBLE_CHROME_HOST")
    assert vc._windows_host() == "127.0.0.1"


def _popen_ok(monkeypatch, seen, port="45678"):
    class _P:
        def __init__(self, *a, **k):
            seen.append(a[0])
            err = k.get("stderr")
            if err is not None:
                err.write(f"DevTools listening on ws://127.0.0.1:{port}/devtools/browser/x\n")
                err.flush()

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(vc.subprocess, "Popen", _P)


def test_launch_returns_releasable_browser(monkeypatch):
    monkeypatch.setattr(vc.urllib.request, "urlopen", lambda *a, **k: _resp_ok())
    seen = []
    _popen_ok(monkeypatch, seen)
    monkeypatch.setattr(vc, "_windows_temp", lambda: "C:\\Temp")
    monkeypatch.setattr(vc.time, "sleep", lambda _s: None)
    vb = vc.ensure_visible_chrome(log=lambda *_a: None)
    assert vb is not None
    assert vb.endpoint == "http://127.0.0.1:45678"
    assert "--remote-debugging-address=127.0.0.1" in seen[0]
    assert "--remote-debugging-port=0" in seen[0]
    assert any(str(a).startswith("--user-data-dir=C:\\Temp\\") for a in seen[0])
    assert "\\" in vb.profile and "/" not in vb.profile.replace("C:\\", "")


def test_no_reuse_second_launch_gets_new_profile(monkeypatch):
    monkeypatch.setattr(vc.urllib.request, "urlopen", lambda *a, **k: _resp_ok())
    seen = []
    _popen_ok(monkeypatch, seen)
    monkeypatch.setattr(vc, "_windows_temp", lambda: "C:\\Temp")
    monkeypatch.setattr(vc.time, "sleep", lambda _s: None)
    vb1 = vc.ensure_visible_chrome(log=lambda *_a: None)
    vb2 = vc.ensure_visible_chrome(log=lambda *_a: None)
    assert vb1 is not None and vb2 is not None
    prof1 = [a for a in seen[0] if str(a).startswith("--user-data-dir=")][0]
    prof2 = [a for a in seen[1] if str(a).startswith("--user-data-dir=")][0]
    assert prof1 != prof2


def test_strict_probe_rejects_junk(monkeypatch):
    monkeypatch.setattr(vc.urllib.request, "urlopen",
                        lambda *a, **k: io.BytesIO(b'"Browser" mentioned but no JSON'))
    assert vc.probe_cdp("127.0.0.1", 19222) is False


def test_no_binary_means_no_browser(monkeypatch):
    monkeypatch.setattr(vc.os.path, "isfile", lambda _p: False)
    launched = []
    monkeypatch.setattr(vc.subprocess, "Popen",
                        lambda *a, **k: launched.append(a))
    assert vc.ensure_visible_chrome(log=lambda *_a: None) is None
    assert launched == []


def test_non_exe_override_ignored(monkeypatch):
    monkeypatch.setenv("VISIBLE_CHROME_BIN", "/tmp/evil.sh")
    monkeypatch.setattr(vc.os.path, "isfile", lambda _p: False)
    assert vc._chrome_binary() is None


def test_release_terminates_and_cleans(monkeypatch, tmp_path):
    profile = tmp_path / "prof"
    profile.mkdir()

    class _P:
        terminated = False
        killed = False
        pid = 424242

        def terminate(self):
            _P.terminated = True

        def wait(self, timeout=None):
            return 0

        def kill(self):
            _P.killed = True

    def _fake_run(cmd, **kw):
        if cmd[0] == "taskkill.exe":
            assert "/T" in cmd and "/F" in cmd

            class _R:
                returncode = 0
                stdout = ""

            return _R()
        if cmd[0] == "powershell.exe":
            seen.append("powershell")

            class _R:
                returncode = 0
                stdout = ""

            return _R()
        assert cmd[0] == "wslpath"

        class _R:
            returncode = 0
            stdout = str(profile)

        return _R()

    monkeypatch.setattr(vc.subprocess, "run", _fake_run)
    vb = vc.VisibleBrowser(endpoint="http://127.0.0.1:1", proc=_P(),
                           profile="C:\\Temp\\ia-visible-chrome-1")
    vc.release_visible_chrome(vb, log=lambda *_a: None)
    assert _P.terminated
    assert not profile.exists()
