"""Web security primitives: CSP/nonces, response headers, CSRF, rate limiting.

Stdlib-only, in-memory, Pi-friendly. Covers the web-facing half of the OWASP
Top 10 (see SECURITY.md for the full mapping):

- A01 Broken Access Control  -> HMAC CSRF tokens on state-changing form posts,
                                strict security headers (frame-ancestors none)
- A03 Injection / XSS        -> Content-Security-Policy with per-response
                                script nonces (no unsafe-inline scripts)
- A04 Insecure Design        -> login rate limiting + temporary lockout
- A05 Security Misconfig      -> hardened default response headers
- A07 Auth Failures          -> brute-force lockout (with A04)
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from hashlib import sha256


# -- CSP nonce + security headers ----------------------------------------

def new_nonce() -> str:
    return secrets.token_urlsafe(16)


def content_security_policy(nonce: str) -> str:
    # Scripts must carry the per-response nonce -> injected inline scripts are
    # blocked. Styles allow 'unsafe-inline' (inline style attributes only;
    # far lower risk than script). Everything else is same-origin; data: is
    # permitted for images so the embedded logo/QR render offline.
    return (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )


def apply_security_headers(resp, nonce: str, secure: bool):
    resp.headers.setdefault("Content-Security-Policy", content_security_policy(nonce))
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(self)"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    # Don't let evidence responses linger in shared caches.
    resp.headers.setdefault("Cache-Control", "no-store")
    if secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


# -- CSRF (HMAC double-submit tied to the session token) -----------------

def csrf_token(session_token: str, key: bytes) -> str:
    """Deterministic CSRF token bound to the session token. An attacker can't
    forge it without the (HttpOnly) session cookie, so cross-site form posts
    fail. Stateless — nothing to store server-side."""
    if not session_token:
        return ""
    return hmac.new(key, ("csrf:" + session_token).encode(), sha256).hexdigest()


def csrf_valid(session_token: str, provided: str, key: bytes) -> bool:
    if not session_token or not provided:
        return False
    return hmac.compare_digest(csrf_token(session_token, key), provided)


# -- Login rate limiting / lockout ---------------------------------------

class LoginRateLimiter:
    """Per-(username, ip) sliding window with temporary lockout.

    Gating happens *before* the expensive PBKDF2 verify, so it also blunts a
    CPU-exhaustion DoS against the 1 GB Pi.
    """

    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(username: str, ip: str) -> str:
        return f"{(username or '').lower()}|{ip or ''}"

    def locked(self, username: str, ip: str) -> bool:
        now = time.time()
        with self._lock:
            hits = [t for t in self._fails.get(self._key(username, ip), []) if now - t < self.window]
            self._fails[self._key(username, ip)] = hits
            return len(hits) >= self.max_attempts

    def record_failure(self, username: str, ip: str) -> None:
        with self._lock:
            self._fails.setdefault(self._key(username, ip), []).append(time.time())

    def reset(self, username: str, ip: str) -> None:
        with self._lock:
            self._fails.pop(self._key(username, ip), None)

    def retry_after(self, username: str, ip: str) -> int:
        now = time.time()
        with self._lock:
            hits = self._fails.get(self._key(username, ip), [])
            if not hits:
                return 0
            return max(0, int(self.window - (now - min(hits))))
