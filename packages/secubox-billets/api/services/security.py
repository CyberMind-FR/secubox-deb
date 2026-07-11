# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Author auth primitives: argon2id password hashing, signed session tokens,
double-submit CSRF, TOTP verification, and an in-memory login rate limiter.

argon2 hashing/verification is CPU-bound (tens of ms) — callers on the async
aggregator loop MUST run `hash_password`/`verify_password` via
`asyncio.to_thread` so they never stall the shared event loop."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner

_ph = PasswordHasher()  # argon2id defaults
SESSION_MAX_AGE = 12 * 3600
_SESSION_SALT = "billets.session.v1"


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _ph.check_needs_rehash(stored_hash)
    except Exception:
        return False


# ── signed session tokens ────────────────────────────────────────────────
def _signer(secret: str) -> TimestampSigner:
    return TimestampSigner(secret, salt=_SESSION_SALT)


def issue_session(secret: str, author_id: str) -> str:
    return _signer(secret).sign(author_id.encode("utf-8")).decode("ascii")


def read_session(secret: str, token: str, *, max_age: int = SESSION_MAX_AGE) -> str | None:
    try:
        raw = _signer(secret).unsign(token, max_age=max_age)
        return raw.decode("utf-8")
    except (BadSignature, SignatureExpired, Exception):
        return None


# ── CSRF (double-submit) ─────────────────────────────────────────────────
def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_ok(cookie_value: str | None, form_value: str | None) -> bool:
    if not cookie_value or not form_value:
        return False
    return hmac.compare_digest(cookie_value, form_value)


# ── TOTP ─────────────────────────────────────────────────────────────────
def verify_totp(secret: str | None, code: str | None) -> bool:
    """True when no TOTP is enrolled (secret None) or the code is valid."""
    if not secret:
        return True
    if not code:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


# ── ip hashing (never store raw IPs) ─────────────────────────────────────
def hash_ip(ip: str, salt: str) -> str:
    return hashlib.blake2b(f"{salt}\x1f{ip}".encode("utf-8"), digest_size=16).hexdigest()


# ── login rate limiter (in-memory sliding window) ────────────────────────
@dataclass
class RateLimiter:
    """Per-key sliding window. In-memory (single-process aggregator); resets on
    restart — acceptable for brute-force slowdown, not a durable quota."""
    max_events: int
    window_s: int
    _hits: dict[str, list[float]] = field(default_factory=dict)

    def check_and_add(self, key: str, *, now: float | None = None) -> bool:
        t = time.time() if now is None else now
        bucket = [x for x in self._hits.get(key, []) if x > t - self.window_s]
        if len(bucket) >= self.max_events:
            self._hits[key] = bucket
            return False
        bucket.append(t)
        self._hits[key] = bucket
        return True


def get_secret() -> str:
    """Runtime signing secret: env override, else the persisted module secret,
    else a fresh ephemeral one (dev). Production ships a stable secret file."""
    env = os.environ.get("BILLETS_SECRET")
    if env:
        return env
    path = os.environ.get("BILLETS_SECRET_FILE", "/etc/secubox/secrets/billets")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = fh.read().strip()
            if data:
                return data
    except OSError:
        pass
    return secrets.token_urlsafe(48)
