"""
qa/visible_chrome.py — launch a FRESH, visible browser for watch mode.

WSL has no display, so the Linux browser can never be seen. Instead we drive
the user's real Windows Chrome over CDP: a window pops on their desktop and
the crawl plays in it live.

Security posture (reviewed — do not weaken casually):
  * NEVER reuse an existing debuggable window: it could host the user's real
    tabs. Every call launches a fresh profile on a random loopback port.
  * Loopback only: --remote-debugging-address=127.0.0.1, probe 127.0.0.1 only
    (verified: this WSL forwards localhost to Windows, and Chrome binds the
    debug port to loopback regardless).
  * Fresh NATIVE profile under Windows %TEMP% (a WSL /tmp path is meaningless
    to chrome.exe and could fall back to the real profile).
  * Fixed argv (binary allowlist + int port); no user input reaches the command.
  * The caller MUST release_visible_chrome() in a finally: terminate + rmtree.
  * Any failure returns None — callers degrade to headless, a scan never dies
    for a window. Set VISIBLE_CHROME_BIN to override the browser path.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

class VisibleBrowser:
    """A launched visible browser. Release with release_visible_chrome()."""

    def __init__(self, endpoint: str, proc, profile: str):
        self.endpoint = endpoint
        self.proc = proc
        self.profile = profile


# Only ever these exact binaries (fixed flags below — no user input reaches argv).
_WINDOWS_BROWSERS = [
    r"/mnt/c/Program Files/Google/Chrome/Application/chrome.exe",
    r"/mnt/c/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    r"/mnt/c/Program Files/Microsoft/Edge/Application/msedge.exe",
]


def _chrome_binary() -> str | None:
    override = os.getenv("VISIBLE_CHROME_BIN")
    if override and override.lower().endswith(".exe") and os.path.isfile(override):
        return override
    for cand in _WINDOWS_BROWSERS:
        if os.path.isfile(cand):
            return cand
    return None


def _windows_temp() -> str | None:
    """Native Windows temp dir (chrome.exe cannot use WSL /tmp paths)."""
    try:
        proc = subprocess.run(["cmd.exe", "/c", "echo", "%TEMP%"],
                              capture_output=True, text=True, timeout=15)
    except (FileNotFoundError, PermissionError, OSError, subprocess.TimeoutExpired):
        return None
    tmp = (proc.stdout or "").strip()
    return tmp or None


def _windows_host() -> str:
    """Address of the Windows host as seen from WSL (loopback forwards)."""
    return os.getenv("VISIBLE_CHROME_HOST") or "127.0.0.1"


_DEVTOOLS_RE = re.compile(r"DevTools listening on ws://[^:/]+:(\d+)")


def probe_cdp(host: str, port: int, timeout: float = 3.0) -> bool:
    """True when a REAL debuggable browser answers (strict JSON, both keys)."""
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/json/version",
                                    timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return False
    return isinstance(data, dict) and "Browser" in data and "webSocketDebuggerUrl" in data


def ensure_visible_chrome(log=print) -> VisibleBrowser | None:
    """Launch a fresh visible Chrome; return it, or None (caller goes headless)."""
    binary = _chrome_binary()
    if not binary:
        log("   visible browser unavailable (no Windows Chrome found); continuing headless.")
        return None
    win_tmp = _windows_temp()
    if not win_tmp:
        log("   visible browser unavailable (Windows temp dir unreachable); continuing headless.")
        return None
    port = None
    host = _windows_host()
    # Uniqueness beyond the ephemeral port (parallel scans): pid + randomness,
    # so two launches never share a profile dir.
    # Native backslashes: chrome.exe chokes on WSL-joined mixed-slash paths.
    profile = (win_tmp.rstrip("\\") + "\\ia-visible-chrome-"
               f"{os.getpid()}-{secrets.token_hex(4)}")
    # Port 0: Chrome picks a free port itself and prints
    # "DevTools listening on ws://…:<port>" to stderr — no guessing across
    # the WSL/Windows port namespaces (a WSL-free port may be taken on Windows).
    args = [binary, f"--remote-debugging-address={host}",
            "--remote-debugging-port=0", "--no-first-run",
            "--no-default-browser-check", f"--user-data-dir={profile}", "about:blank"]
    err_fd, err_path = tempfile.mkstemp(prefix="ia-chrome-err-")
    os.close(err_fd)
    log(f"   visible browser: launching {os.path.basename(binary)} (dedicated debug profile).")
    try:
        with open(err_path, "w") as err_file:
            proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err_file,
                                    stdin=subprocess.DEVNULL, start_new_session=True)
    except (FileNotFoundError, PermissionError, OSError) as e:
        log(f"   visible browser unavailable (launch failed: {e}); continuing headless.")
        return None
    deadline = time.monotonic() + 25.0
    while time.monotonic() < deadline:
        try:
            with open(err_path) as f:
                announced = _DEVTOOLS_RE.search(f.read())
        except OSError:
            announced = None
        if announced:
            port = int(announced.group(1))
            if probe_cdp(host, port):
                try:
                    os.unlink(err_path)
                except OSError:
                    pass
                log(f"👁️ visible browser ready at http://{host}:{port} — watch it work.")
                return VisibleBrowser(endpoint=f"http://{host}:{port}", proc=proc,
                                      profile=profile)
        time.sleep(0.5)
    log("   visible browser unavailable (CDP port never answered); continuing headless "
        f"(chrome log kept at {err_path}).")
    _terminate(proc, profile, log)
    return None


def _kill_profile_processes(marker: str) -> None:
    """taskkill every Windows chrome whose command line carries our unique
    profile marker. Popen.pid is a WSL-side PID — useless to taskkill — so we
    match by the per-launch profile dir name instead."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", marker or ""):
        return
    try:
        ps = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process -Filter \"name = 'chrome.exe'\" | "
             "Where-Object { $_.CommandLine -like '*" + marker + "*' } | "
             "Select-Object -ExpandProperty ProcessId"],
            capture_output=True, text=True, timeout=30)
    except Exception:
        return
    for line in (ps.stdout or "").splitlines():
        pid = line.strip()
        if pid.isdigit():
            try:
                subprocess.run(["taskkill.exe", "/PID", pid, "/T", "/F"],
                               capture_output=True, timeout=20)
            except Exception:
                pass


def _terminate(proc, profile: str, log=print) -> None:
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    except Exception:
        pass
    # Popen hunts WSL-side PIDs; the real Windows tree is found by profile.
    _kill_profile_processes(os.path.basename(profile.replace("\\", "/")))
    # Profile lives on the Windows side; translate back for removal. A raw
    # Windows path is meaningless to rmtree from WSL, so without a successful
    # translation we warn instead of pretending to clean up. Windows releases
    # file locks asynchronously after the kill — retry a few times.
    wsl_profile = None
    try:
        out = subprocess.run(["wslpath", "-u", profile], capture_output=True,
                             text=True, timeout=15)
        if out.returncode == 0 and out.stdout.strip():
            wsl_profile = out.stdout.strip()
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass
    removed = False
    if wsl_profile:
        for _ in range(4):
            shutil.rmtree(wsl_profile, ignore_errors=True)
            if not os.path.exists(wsl_profile):
                removed = True
                break
            time.sleep(1)
    if not removed:
        log(f"   warning: visible-browser profile may remain ({profile}) — "
            "delete it manually from Windows %TEMP% if present.")


def release_visible_chrome(vb: VisibleBrowser | None, log=print) -> None:
    """Terminate a launched browser and remove its profile. Never touches
    anything we did not launch (only VisibleBrowser handles are tracked)."""
    if vb is None:
        return
    _terminate(vb.proc, vb.profile, log)
    log("   visible browser closed.")
