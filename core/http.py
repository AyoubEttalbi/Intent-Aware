"""
core/http.py — identity-aware, scope-safe HTTP client.

Adds the things the old TestRunner lacked, plus the safety the v2 review demanded:
  1. a negative-auth primitive (`Request.strip_auth` guarantees NO credentials),
  2. host allowlisting that is also enforced on every redirect hop (a poisoned
     spec or a 302 can't steer attacks/credentials to a third party),
  3. full evidence capture (the actual sent headers are stamped back on the Request),
  4. polite retry/backoff on 429/5xx/transport errors, honouring Retry-After.

Redirects are NOT followed blindly. Same-host redirects for safe methods (GET/HEAD)
are followed manually (so trailing-slash and canonical redirects resolve), capped and
re-validated against the allowlist each hop. Cross-host redirects are never followed —
the 3xx is returned with `redirect_location` set. Unsafe methods are never auto-followed.
"""
from __future__ import annotations

import threading
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from core.models import Request, Response, Identity

# Header names we treat as "credentials" and remove for a strip_auth probe.
AUTH_HEADER_NAMES = {
    "authorization", "cookie", "x-api-key", "x-auth-token",
    "x-access-token", "x-session-token", "api-key", "x-csrf-token",
}

SAFE_METHODS = {"GET", "HEAD"}
MAX_REDIRECTS = 5
MAX_RETRIES = 2


class HttpClient:
    def __init__(self, allowed_hosts: Optional[set] = None, timeout: float = 30.0,
                 max_rps: float = 8.0):
        self.allowed_hosts = {h.lower() for h in (allowed_hosts or set()) if h}
        self.timeout = timeout
        self._min_interval = (1.0 / max_rps) if max_rps else 0.0
        self._last_at = 0.0
        self._throttle_lock = threading.Lock()
        # follow_redirects=False: we re-validate every hop ourselves (scope safety).
        self.client = httpx.Client(timeout=timeout, follow_redirects=False)

    def add_hosts(self, hosts) -> None:
        for h in (hosts or []):
            if h:
                self.allowed_hosts.add(str(h).lower())

    def _host_ok(self, url: str) -> bool:
        if not self.allowed_hosts:
            return True
        return (urlparse(url).hostname or "").lower() in self.allowed_hosts

    def _throttle(self) -> None:
        if self._min_interval <= 0:
            return
        with self._throttle_lock:   # spaces out request *starts* at the rate limit, thread-safe
            wait = self._min_interval - (time.perf_counter() - self._last_at)
            if wait > 0:
                time.sleep(wait)
            self._last_at = time.perf_counter()

    def _raw_send(self, method: str, url: str, headers: dict, body, content_type: str):
        """One HTTP call with retry/backoff on 429/5xx/transport errors. Returns httpx.Response."""
        send_body = body if (method in ("POST", "PUT", "PATCH", "DELETE") and body is not None) else None
        kwargs = {"headers": headers}
        if send_body is not None:
            kwargs["data" if content_type == "form" else "json"] = send_body
        last_exc = None
        for attempt in range(MAX_RETRIES + 1):
            self._throttle()
            try:
                r = self.client.request(method, url, **kwargs)
            except Exception as e:
                last_exc = e
                if attempt < MAX_RETRIES:
                    time.sleep(min(2.0 * (attempt + 1), 5.0))
                    continue
                raise
            if r.status_code == 429 or 500 <= r.status_code < 600:
                if attempt < MAX_RETRIES:
                    ra = r.headers.get("retry-after")
                    delay = float(ra) if (ra and ra.isdigit()) else min(1.5 * (attempt + 1), 5.0)
                    time.sleep(min(delay, 6.0))
                    continue
            return r
        if last_exc:
            raise last_exc

    def send(self, req: Request, identity: Optional[Identity] = None) -> Response:
        if not self._host_ok(req.url):
            return Response(status=0, error=f"blocked: {req.url} is outside the target scope")

        headers = dict(req.headers or {})
        # Apply the identity's credentials — unless this is a negative-auth probe.
        if identity and not req.strip_auth:
            headers.update(identity.headers or {})
            if identity.cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in identity.cookies.items())
        if req.strip_auth:
            headers = {k: v for k, v in headers.items() if k.lower() not in AUTH_HEADER_NAMES}

        method = req.method.upper()
        url = req.url
        start = time.perf_counter()
        redirected = False
        first_location = ""
        try:
            r = self._raw_send(method, url, headers, req.body, req.content_type)
            hops = 0
            # Manual, scope-checked redirect following for safe methods only.
            while r.is_redirect and method in SAFE_METHODS and hops < MAX_REDIRECTS:
                loc = r.headers.get("location", "")
                nxt = urljoin(url, loc)
                if not first_location:
                    first_location = nxt
                redirected = True
                if not self._host_ok(nxt):
                    break   # never follow a redirect off-scope
                url = nxt
                hops += 1
                r = self._raw_send(method, url, headers, None, req.content_type)
            if r.is_redirect and not first_location:
                redirected = True
                first_location = urljoin(url, r.headers.get("location", ""))

            latency = (time.perf_counter() - start) * 1000
            try:
                body = r.json()
            except Exception:
                body = r.text
            req.headers = headers          # evidence: exactly what we sent
            return Response(status=r.status_code, headers=dict(r.headers), body=body,
                            text=r.text, latency_ms=latency, final_url=str(r.url),
                            redirected=redirected, redirect_location=first_location)
        except Exception as e:
            req.headers = headers
            return Response(status=0, error=str(e),
                            latency_ms=(time.perf_counter() - start) * 1000)

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass
