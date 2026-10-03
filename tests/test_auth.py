import concurrent.futures
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from app import RateLimiter, make_server
from auth import ACCESS_TTL, SESSION_TTL, AuthError, AuthStore, password_matches, token_hash

PASSWORD = "sample-password-2026"


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = 1000000
        self.store = AuthStore(Path(self.temp.name) / "db.sqlite3", lambda: self.now)
        self.store.register("User@example.com", PASSWORD)

    def tearDown(self):
        self.temp.cleanup()

    def login(self):
        return self.store.login("user@example.com", PASSWORD)

    def denied(self, call, status=401):
        with self.assertRaises(AuthError) as error:
            call()
        self.assertEqual(error.exception.status, status)

    def test_credentials_are_salted_and_public_user_is_safe(self):
        self.store.register("other@example.com", PASSWORD)
        with self.store.db() as db:
            hashes = [row[0] for row in db.execute("SELECT password_hash FROM users")]
        self.assertNotEqual(*hashes)
        self.assertNotIn(PASSWORD, "".join(hashes))
        self.assertTrue(password_matches(PASSWORD, hashes[0]))
        data, _, _ = self.login()
        self.assertEqual(set(data["user"]), {"id", "email"})

    def test_duplicate_email_and_invalid_inputs(self):
        self.denied(lambda: self.store.register("USER@example.com", PASSWORD), 409)
        for email, password in [("invalid", PASSWORD), ("new@example.com", "short"), (None, PASSWORD), ("new@example.com", 123)]:
            self.denied(lambda: self.store.register(email, password), 400)

    def test_wrong_and_unknown_password_share_error(self):
        messages = []
        for email in ["user@example.com", "unknown@example.com"]:
            with self.assertRaises(AuthError) as error:
                self.store.login(email, "wrong-password-2026")
            messages.append((error.exception.status, error.exception.message))
        self.assertEqual(messages[0], messages[1])

    def test_tokens_stored_only_as_hashes_and_correct_identity(self):
        data, refresh, _ = self.login()
        with self.store.db() as db:
            access_row = db.execute("SELECT hash FROM access_tokens").fetchone()[0]
            refresh_row = db.execute("SELECT hash FROM refresh_tokens").fetchone()[0]
        self.assertEqual(access_row, token_hash(data["access_token"]))
        self.assertEqual(refresh_row, token_hash(refresh))
        self.assertNotEqual(access_row, data["access_token"])
        self.assertNotEqual(refresh_row, refresh)
        self.assertEqual(self.store.current_user(data["access_token"])["email"], "user@example.com")
        self.denied(lambda: self.store.current_user("x" * 43))
        self.denied(lambda: self.store.current_user("bad unicode 密码"))

    def test_access_expiry_and_refresh(self):
        data, refresh, _ = self.login()
        self.now += ACCESS_TTL
        self.denied(lambda: self.store.current_user(data["access_token"]))
        fresh, _, _ = self.store.refresh(refresh)
        self.assertEqual(self.store.current_user(fresh["access_token"])["email"], "user@example.com")

    def test_rotation_invalidates_old_access_and_replay_revokes_family(self):
        data, old_refresh, _ = self.login()
        fresh, new_refresh, _ = self.store.refresh(old_refresh)
        self.denied(lambda: self.store.current_user(data["access_token"]))
        self.denied(lambda: self.store.refresh(old_refresh))
        # Revocation must persist even though the replay raises an exception.
        self.denied(lambda: self.store.current_user(fresh["access_token"]))
        self.denied(lambda: self.store.refresh(new_refresh))

    def test_simultaneous_refresh_cannot_issue_two_active_pairs(self):
        _, refresh, _ = self.login()
        barrier = threading.Barrier(2)
        def compete():
            barrier.wait()
            try:
                return self.store.refresh(refresh)
            except AuthError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: compete(), range(2)))
        successful = [r for r in results if r]
        self.assertEqual(len(successful), 1)
        self.denied(lambda: self.store.current_user(successful[0][0]["access_token"]))

    def test_absolute_session_expiry(self):
        _, refresh, _ = self.login()
        self.now += SESSION_TTL - 10
        data, fresh, age = self.store.refresh(refresh)
        self.assertEqual(age, 10)
        self.assertEqual(data["expires_in"], 10)
        self.now += 10
        self.denied(lambda: self.store.refresh(fresh))
        self.denied(lambda: self.store.current_user(data["access_token"]))

    def test_logout_and_session_isolation(self):
        first, refresh, _ = self.login()
        second, second_refresh, _ = self.login()
        self.store.logout(refresh)
        self.store.logout(refresh)
        self.denied(lambda: self.store.current_user(first["access_token"]))
        self.denied(lambda: self.store.refresh(refresh))
        self.assertEqual(self.store.current_user(second["access_token"])["email"], "user@example.com")
        self.store.logout(second_refresh)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.store = AuthStore(Path(cls.temp.name) / "http.sqlite3")
        cls.server = make_server(cls.store, port=0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def call(self, method, path, body=None, extra=None):
        headers = {"Origin": self.server.origin, "Content-Type": "application/json"}
        headers.update(extra or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        connection.request(method, path, json.dumps(body) if body is not None else None, headers)
        response = connection.getresponse()
        status, result_headers, data = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return status, result_headers, data

    def test_browser_flow_cookie_flags_no_store_and_revocation(self):
        status, _, _ = self.call("POST", "/api/auth/register", {"email": "browser@example.com", "password": PASSWORD})
        self.assertEqual(status, 201)
        status, headers, raw = self.call("POST", "/api/auth/login", {"email": "browser@example.com", "password": PASSWORD})
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        cookie = headers["Set-Cookie"]
        for flag in ["HttpOnly", "SameSite=Strict", "Path=/api/auth"]:
            self.assertIn(flag, cookie)
        data = json.loads(raw)
        self.assertNotIn("refresh_token", data)
        cookie_pair = cookie.split(";", 1)[0]
        auth = {"Authorization": "Bearer " + data["access_token"]}
        self.assertEqual(self.call("GET", "/api/me", extra=auth)[0], 200)
        status, headers, raw = self.call("POST", "/api/auth/refresh", {}, {"Cookie": cookie_pair})
        self.assertEqual(status, 200)
        self.assertEqual(self.call("GET", "/api/me", extra=auth)[0], 401)
        fresh_auth = {"Authorization": "Bearer " + json.loads(raw)["access_token"]}
        fresh_cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, headers, _ = self.call("POST", "/api/auth/logout", {}, {"Cookie": fresh_cookie})
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        self.assertEqual(self.call("GET", "/api/me", extra=fresh_auth)[0], 401)

    def test_request_validation_and_static_allowlist(self):
        for headers, expected in [({"Origin": "https://attacker.example"}, 403),
                                  ({"Origin": ""}, 403),
                                  ({"Content-Type": "text/plain"}, 415),
                                  ({"Host": "attacker.example"}, 403)]:
            self.assertEqual(self.call("POST", "/api/auth/refresh", {}, headers)[0], expected)
        self.assertEqual(self.call("GET", "/api/me")[0], 401)
        self.assertEqual(self.call("GET", "/auth.py")[0], 404)
        self.assertEqual(self.call("GET", "/data/auth.sqlite3")[0], 404)
        self.assertEqual(self.call("GET", "/")[0], 200)
        self.assertEqual(self.call("GET", "/static/app.js")[0], 200)
        self.assertEqual(self.call("POST", "/api/auth/refresh", [1, 2])[0], 400)
        self.assertEqual(self.call("POST", "/api/auth/refresh", {"data": "x" * 5000})[0], 413)

    def test_secure_cookie_option(self):
        self.server.cookie_secure = True
        try:
            self.call("POST", "/api/auth/register", {"email": "secure@example.com", "password": PASSWORD})
            status, headers, _ = self.call("POST", "/api/auth/login", {"email": "secure@example.com", "password": PASSWORD})
            self.assertEqual(status, 200)
            self.assertIn("Secure", headers["Set-Cookie"])
        finally:
            self.server.cookie_secure = False


class LimitTests(unittest.TestCase):
    def test_limit_recovers_after_window_and_is_per_ip(self):
        now = [0]
        limiter = RateLimiter(limit=2, window=60, clock=lambda: now[0])
        self.assertTrue(limiter.allow("one"))
        self.assertTrue(limiter.allow("one"))
        self.assertFalse(limiter.allow("one"))
        self.assertTrue(limiter.allow("two"))
        now[0] = 60
        self.assertTrue(limiter.allow("one"))


if __name__ == "__main__":
    unittest.main()
