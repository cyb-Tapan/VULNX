"""
conftest.py

Spins up a small local HTTP server (127.0.0.1, random port) as an
intentionally vulnerable test fixture. All VULNX integration tests run
only against this local fixture — never against a public website, per
PHASE 13's requirement.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

CANARY_CONTENT = "VULNX_TRAVERSAL_CANARY file contents"


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence test server logs
        pass

    def _send(self, body: str, status: int = 200, content_type: str = "text/html"):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parts = urlsplit(self.path)
        qs = parse_qs(parts.query)
        path = parts.path

        if path == "/":
            self._send(
                """
                <html><body>
                <a href="/search">search</a>
                <a href="/echo">echo</a>
                <form action="/login" method="POST">
                  <input name="username">
                  <input name="password" type="password">
                </form>
                <form action="/upload" method="POST" enctype="multipart/form-data">
                  <input type="file" name="avatar" accept="image/png">
                </form>
                <script src="/app.js"></script>
                </body></html>
                """
            )
            return

        if path == "/app.js":
            self._send('fetch("/api/internal/users"); var x = "/api/widgets";', content_type="application/javascript")
            return

        if path == "/search":
            q = qs.get("q", [""])[0]
            if "'" in q:
                self._send("Warning: mysqli_query(): You have an error in your SQL syntax", status=500)
            else:
                self._send(f"<html><body>Results for {q}</body></html>")
            return

        if path == "/noreflect":
            q = qs.get("q", [""])[0]
            self._send("<html><body>Thanks for your search.</body></html>")
            return

        if path == "/echo":
            x = qs.get("x", [""])[0]
            self._send(f"<html><body>You said: {x}</body></html>")
            return

        if path == "/download":
            f = qs.get("file", [""])[0]
            if f.endswith("vulnx_canary.txt"):
                self._send(CANARY_CONTENT)
            else:
                self._send("file not found", status=404)
            return

        if path == "/redirect-offsite":
            self.send_response(302)
            self.send_header("Location", "http://example.org/")
            self.end_headers()
            return

        if path == "/redirect-onsite":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        if path == "/secure":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session=abc123; Secure; HttpOnly; SameSite=Lax")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("Strict-Transport-Security", "max-age=63072000")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "geolocation=()")
            body = b"<html><body>secure</body></html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self._send("not found", status=404)

    def do_POST(self):
        self._send("ok")


@pytest.fixture(scope="session")
def fixture_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    yield base_url
    server.shutdown()
    server.server_close()
