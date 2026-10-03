"""Local-only HTTP adapter. Run: python3 app.py"""

import json
import os
import threading
import time
from collections import defaultdict, deque
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from auth import AuthError, AuthStore

ROOT = Path(__file__).resolve().parent
COOKIE = "no1_refresh"
MAX_BODY = 4096


class RateLimiter:
    def __init__(self, limit=20, window=60, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self.attempts = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, ip):
        now = self.clock()
        with self.lock:
            for key in list(self.attempts):
                if not self.attempts[key] or self.attempts[key][-1] <= now - self.window:
                    del self.attempts[key]
            queue = self.attempts[ip]
            while queue and queue[0] <= now - self.window:
                queue.popleft()
            if len(queue) >= self.limit:
                return False
            queue.append(now)
            return True


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, format, *args):
        # Request bodies, headers, cookies and tokens are deliberately never logged.
        pass

    def reply(self, status, payload, cookie=None, mime="application/json; charset=utf-8"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        if status == 401:
            self.send_header("WWW-Authenticate", "Bearer")
        if status == 429:
            self.send_header("Retry-After", "60")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def refresh_cookie(self, token="", age=0):
        cookie = SimpleCookie()
        cookie[COOKIE] = token
        cookie[COOKIE]["path"] = "/api/auth"
        cookie[COOKIE]["httponly"] = True
        cookie[COOKIE]["samesite"] = "Strict"
        cookie[COOKIE]["max-age"] = max(0, age)
        # For an HTTPS reverse proxy set COOKIE_SECURE=1 and APP_ORIGIN accordingly.
        if self.server.cookie_secure:
            cookie[COOKIE]["secure"] = True
        return cookie.output(header="").strip()

    def read_refresh(self):
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            return cookie[COOKIE].value if COOKIE in cookie else ""
        except CookieError:
            return ""

    def check_host(self):
        if self.headers.get("Host") != urlsplit(self.server.origin).netloc:
            raise AuthError(403, "请从应用的本机地址打开页面。")

    def body(self):
        # Requiring same-origin POSTs + JSON prevents cross-site form submissions.
        if self.headers.get("Origin") != self.server.origin:
            raise AuthError(403, "请求来源不匹配。")
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise AuthError(403, "不允许跨站请求。")
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise AuthError(415, "请求必须使用 JSON。")
        if self.headers.get("Transfer-Encoding"):
            raise AuthError(400, "不支持此请求编码。")
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            raise AuthError(400, "请求长度无效。") from None
        if length < 0 or length > MAX_BODY:
            raise AuthError(413, "请求内容过大或长度缺失。")
        try:
            result = json.loads(self.rfile.read(length))
            if not isinstance(result, dict):
                raise ValueError
            return result
        except (ValueError, UnicodeDecodeError):
            raise AuthError(400, "JSON 格式无效。") from None

    def do_GET(self):
        try:
            self.check_host()
            path = urlsplit(self.path).path
            if path == "/api/me":
                header = self.headers.get("Authorization", "")
                kind, _, token = header.partition(" ")
                if kind.lower() != "bearer":
                    raise AuthError(401, "请先登录。")
                self.reply(200, {"user": self.server.store.current_user(token)})
            elif path in ("/", "/static/app.js", "/static/style.css"):
                files = {"/": ("index.html", "text/html; charset=utf-8"),
                         "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
                         "/static/style.css": ("style.css", "text/css; charset=utf-8")}
                file, mime = files[path]
                self.reply(200, (ROOT / "static" / file).read_bytes(), mime=mime)
            else:
                self.reply(404, {"error": "页面不存在。"})
        except AuthError as error:
            self.reply(error.status, {"error": error.message})

    def do_POST(self):
        path = urlsplit(self.path).path
        try:
            self.check_host()
            routes = ("/api/auth/register", "/api/auth/login", "/api/auth/refresh", "/api/auth/logout")
            if path not in routes:
                raise AuthError(404, "接口不存在。")
            body = self.body()
            # Logout is exempt so a rate-limited user can still revoke their session.
            if path != "/api/auth/logout" and not self.server.limiter.allow(self.client_address[0]):
                raise AuthError(429, "操作太频繁，请稍后重试。")
            store = self.server.store
            if path == "/api/auth/register":
                user = store.register(body.get("email"), body.get("password"))
                self.reply(201, {"user": user, "message": "注册成功，请登录。"})
            elif path == "/api/auth/login":
                payload, refresh, age = store.login(body.get("email"), body.get("password"))
                store.logout(self.read_refresh())
                self.reply(200, payload, self.refresh_cookie(refresh, age))
            elif path == "/api/auth/refresh":
                payload, refresh, age = store.refresh(self.read_refresh())
                self.reply(200, payload, self.refresh_cookie(refresh, age))
            else:
                store.logout(self.read_refresh())
                self.reply(200, {"message": "已退出登录。"}, self.refresh_cookie())
        except AuthError as error:
            clear = self.refresh_cookie() if path == "/api/auth/refresh" and error.status == 401 else None
            self.reply(error.status, {"error": error.message}, clear)
        except (OSError, TimeoutError):
            self.reply(400, {"error": "请求读取失败。"})


def make_server(store, port=8000, origin=None, cookie_secure=False):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.store = store
    server.origin = origin or f"http://127.0.0.1:{server.server_port}"
    server.cookie_secure = cookie_secure
    server.limiter = RateLimiter()
    return server


if __name__ == "__main__":
    store = AuthStore(os.environ.get("AUTH_DB", str(ROOT / "data" / "auth.sqlite3")))
    server = make_server(store, int(os.environ.get("PORT", "8000")),
                         os.environ.get("APP_ORIGIN"), os.environ.get("COOKIE_SECURE") == "1")
    print(f"No.1 登录示例已启动：{server.origin} （Ctrl+C 停止）", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
