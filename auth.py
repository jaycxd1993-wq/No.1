"""Password verification and database-backed, revocable token sessions."""

import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

SCRYPT_N, SCRYPT_R, SCRYPT_P = 32768, 8, 3
ACCESS_TTL = 15 * 60
SESSION_TTL = 7 * 24 * 60 * 60


class AuthError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message
        super().__init__(message)


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                            maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def password_matches(password, encoded):
    # This application writes one version of the hash format; parameters are explicit.
    _, n, r, p, salt, expected = encoded.split("$")
    actual = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt),
                            n=int(n), r=int(r), p=int(p),
                            maxmem=64 * 1024 * 1024, dklen=32).hex()
    return hmac.compare_digest(actual, expected)


def token_hash(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def valid_token(token):
    return isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is not None


def credentials(email, password):
    if not isinstance(email, str) or not isinstance(password, str):
        raise AuthError(400, "邮箱和密码必须是文本。")
    email = email.strip().lower()
    if len(email) > 254 or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+", email):
        raise AuthError(400, "请输入有效邮箱。")
    if not 12 <= len(password) <= 128 or len(password.encode("utf-8")) > 1024:
        raise AuthError(400, "密码需要 12–128 个字符。")
    return email, password


class AuthStore:
    def __init__(self, path, clock=time.time):
        self.path, self.clock = Path(path), clock
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # A dummy hash keeps unknown-user logins on the password verification path.
        self.dummy_hash = password_hash(secrets.token_urlsafe(24))
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL, created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
                    expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS access_tokens (
                    hash TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id),
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    hash TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id),
                    used INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS access_session ON access_tokens(session_id);
                CREATE INDEX IF NOT EXISTS refresh_session ON refresh_tokens(session_id);
            """)
        self.path.chmod(0o600)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def register(self, email, password):
        email, password = credentials(email, password)
        user = {"id": secrets.token_hex(16), "email": email}
        encoded = password_hash(password)
        try:
            with self.db() as db:
                db.execute("INSERT INTO users VALUES (?, ?, ?, ?)",
                           (user["id"], email, encoded, int(self.clock())))
        except sqlite3.IntegrityError:
            raise AuthError(409, "此邮箱已注册。") from None
        return user

    def _issue(self, db, session_id, session_expiry):
        now = int(self.clock())
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        expiry = min(now + ACCESS_TTL, session_expiry)
        db.execute("INSERT INTO access_tokens VALUES (?, ?, ?)",
                   (token_hash(access), session_id, expiry))
        db.execute("INSERT INTO refresh_tokens(hash, session_id) VALUES (?, ?)",
                   (token_hash(refresh), session_id))
        return {"access_token": access, "token_type": "Bearer",
                "expires_in": expiry - now}, refresh, session_expiry - now

    def login(self, email, password):
        email, password = credentials(email, password)
        with self.db() as db:
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        matches = password_matches(password, user["password_hash"] if user else self.dummy_hash)
        if not user or not matches:
            raise AuthError(401, "邮箱或密码不正确。")
        now, session_id = int(self.clock()), secrets.token_hex(16)
        with self.db() as db:
            db.execute("INSERT INTO sessions(id, user_id, expires_at) VALUES (?, ?, ?)",
                       (session_id, user["id"], now + SESSION_TTL))
            result = self._issue(db, session_id, now + SESSION_TTL)
        result[0]["user"] = {"id": user["id"], "email": user["email"]}
        return result

    def current_user(self, access):
        if not valid_token(access):
            raise AuthError(401, "请先登录，或续期后重试。")
        with self.db() as db:
            user = db.execute("""
                SELECT u.id, u.email FROM access_tokens a
                JOIN sessions s ON s.id = a.session_id JOIN users u ON u.id = s.user_id
                WHERE a.hash = ? AND a.expires_at > ?
                    AND s.expires_at > ? AND s.revoked = 0
            """, (token_hash(access), self.clock(), self.clock())).fetchone()
        if not user:
            raise AuthError(401, "请先登录，或续期后重试。")
        return dict(user)

    def refresh(self, refresh):
        if not valid_token(refresh):
            raise AuthError(401, "登录已失效，请重新登录。")
        result = None
        with self.db() as db:
            # Serialize competing refreshes so a token is consumed exactly once.
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""
                SELECT r.used, s.* FROM refresh_tokens r
                JOIN sessions s ON s.id = r.session_id WHERE r.hash = ?
            """, (token_hash(refresh),)).fetchone()
            if row and row["used"]:
                # Commit revocation BEFORE raising outside the transaction.
                db.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (row["id"],))
            elif row and not row["revoked"] and row["expires_at"] > self.clock():
                db.execute("UPDATE refresh_tokens SET used = 1 WHERE hash = ?", (token_hash(refresh),))
                db.execute("DELETE FROM access_tokens WHERE session_id = ?", (row["id"],))
                result = self._issue(db, row["id"], row["expires_at"])
        if result is None:
            raise AuthError(401, "登录已失效，请重新登录。")
        return result

    def logout(self, refresh):
        # Logout is idempotent and also recognizes already-used refresh tokens.
        if valid_token(refresh):
            with self.db() as db:
                db.execute("""UPDATE sessions SET revoked = 1 WHERE id IN
                    (SELECT session_id FROM refresh_tokens WHERE hash = ?)""", (token_hash(refresh),))
