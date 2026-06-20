#!/usr/bin/env python3
"""Mock HTTP HA1 backend for the auth-deadlock integration test.

Responds to ``GET /sip/auth/<username>`` with the HA1 hex string

    MD5(username:REALM:PASSWORD)

so siphon's ``auth.backend: http`` (``ha1: true``) accepts the digest that SIPp
computes for ``<username>:secret`` against siphon's ``example.com`` challenge.

An artificial per-request ``AUTH_DELAY_MS`` widens the window during which a SIP
handler is parked inside the blocking HA1 fetch. On a *buggy* build (handler
stays attached to the interpreter while blocking) that is exactly when the
free-threaded-CPython GC stop-the-world collides and the engine deadlocks; on
the *fixed* build (``py.detach()`` around the blocking call) the registrations
all complete. The server is threaded so concurrent fetches don't serialise here
— we want many handlers blocked in siphon at once.
"""
import hashlib
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REALM = os.environ.get("AUTH_REALM", "example.com")
PASSWORD = os.environ.get("AUTH_PASSWORD", "secret")
DELAY_MS = int(os.environ.get("AUTH_DELAY_MS", "0"))
PORT = int(os.environ.get("AUTH_PORT", "8080"))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        username = self.path.rstrip("/").rsplit("/", 1)[-1]
        if DELAY_MS:
            time.sleep(DELAY_MS / 1000.0)
        ha1 = hashlib.md5(
            f"{username}:{REALM}:{PASSWORD}".encode()
        ).hexdigest().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(ha1)))
        self.end_headers()
        self.wfile.write(ha1)

    def log_message(self, *args):
        pass  # keep the test output quiet


if __name__ == "__main__":
    print(
        f"mock-http-auth: realm={REALM} delay_ms={DELAY_MS} port={PORT}",
        flush=True,
    )
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
