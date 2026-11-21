"""A tiny local web app with planted runtime problems, for testing runtime.py. Standard library only.

Planted: user B can read user A's order (IDOR) and the response leaks a password hash; any signed-in user reaches the
admin route; sign-in has no rate limit; /broken throws a page error; /wide overflows a phone screen; /a11y has an image without alt text, an unnamed small button and a clickable div; malformed JSON returns a Python traceback; CORS trusts any origin with
credentials; no security headers; the payment webhook accepts unsigned events.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKENS = {"Bearer tok-a": "a", "Bearer tok-b": "b", "Bearer tok-admin": "admin"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def who(self):
        return TOKENS.get(self.headers.get("Authorization", ""))

    def send(self, code, body, ctype="application/json"):
        data = (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            return self.send(200, "<html><body>Shop</body></html>", "text/html")
        if self.path == "/broken":
            return self.send(200, "<html><body>Cart<script>window.addEventListener('load', () => { null.total })</script></body></html>", "text/html")
        if self.path == "/wide":
            return self.send(200, '<html><head><meta name="viewport" content="width=device-width"></head><body><div style="width:900px">Wide table</div></body></html>', "text/html")
        if self.path == "/a11y":
            return self.send(200, '<html><head><meta name="viewport" content="width=device-width"></head><body><img src="/x.png">'
                             '<button style="width:30px;height:30px"></button><div onclick="go()">Buy</div></body></html>', "text/html")
        if self.path == "/pay":
            return self.send(200, "<html><body><button id=pay onclick=\"location.href='/paid'\">Pay</button></body></html>", "text/html")
        if self.path == "/paid":
            return self.send(200, "<html><body>Payment received</body></html>", "text/html")
        if self.path.startswith("/api/orders/"):
            if not self.who():
                return self.send(401, {"error": "sign in"})
            return self.send(200, {"id": 1, "owner": "a", "total": 40, "owner_user": {"email": "a@test.local", "password_hash": "$2b$10$abc"}})
        if self.path == "/api/admin/users":
            if not self.who():
                return self.send(401, {"error": "sign in"})
            return self.send(200, [{"email": "a@test.local"}])
        return self.send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode()
        if self.path == "/api/login":
            return self.send(401, {"error": "wrong email or password"})
        if self.path == "/api/orders":
            try:
                json.loads(raw)
            except ValueError:
                return self.send(500, 'Traceback (most recent call last):\n  File "app.py", line 12\njson.decoder.JSONDecodeError', "text/plain")
            return self.send(201, {"ok": True})
        if self.path == "/api/webhooks/stripe":
            return self.send(200, {"received": True})
        return self.send(404, {"error": "not found"})


def start():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"
