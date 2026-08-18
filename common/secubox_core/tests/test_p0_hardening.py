# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Non-regression tests for the P0 hardening batch (#942).

Every test here MUST fail on the pre-#942 code. They pin the five active
faults found by the SwitchSBX audit
(`docs/superpowers/specs/2026-07-31-switchsbx-audit.md` §B):

- A  a `scope` token is accepted as a full access token
- B  the default session validator is permissive (`lambda jti: True`)
- E  the JWT secret silently falls back to `CHANGEME_INSECURE`
- B' there is no shared session store, so revocation never reaches the
     modules that run in their own process (44 of them on gk2)
"""
import importlib
import json
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from secubox_core import auth, user_store


def _write_user(p: Path, **fields):
    base = {
        "username": "admin",
        "email": "a@b.c",
        "role": "admin",
        "enabled": True,
        "password_hash": PasswordHasher().hash("GoodPass!42xyz"),
        "must_change_password": False,
        "totp": None,
        "google": None,
        "services": [],
        "created": "2026-05-13T00:00:00+00:00",
        "last_login": None,
    }
    base.update(fields)
    p.write_text(json.dumps({"version": 2, "users": [base], "groups": []}))


@pytest.fixture
def enabled_admin(tmp_path: Path, monkeypatch):
    p = tmp_path / "users.json"
    _write_user(p)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    # A dev workstation cannot read /etc/secubox/secubox.conf (0640
    # secubox:secubox), and get_config() raises PermissionError before the
    # env fallback is reached. Neutralise the file lookup so the tests
    # exercise auth, not the local file permissions.
    monkeypatch.setattr(auth, "get_config", lambda section: {})
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret-do-not-use-in-prod-please")
    yield


class _Req:
    """Minimal stand-in for fastapi.Request (cookies + headers only)."""

    def __init__(self, cookies=None):
        self.cookies = cookies or {}
        self.headers = {}


# ── A — scope tokens must never open a full session ──────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["mfa-challenge", "set-password", "totp-enroll"])
async def test_scope_token_is_rejected_by_require_jwt(enabled_admin, monkeypatch, scope):
    """A scope token is an INTENT, not an access token.

    `mfa-challenge` is minted after the password check but BEFORE the TOTP
    check. Accepting it as a bearer token is a 2FA bypass with the password
    alone. `set-password` is minted against an EMPTY password.
    """
    # Session accepted — we are testing the scope gate, not the session gate.
    monkeypatch.setattr(auth, "_session_validator", lambda jti: True)
    tok = auth.create_token("admin", scope=scope, expires_in=300)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=tok)
    with pytest.raises(HTTPException) as exc:
        await auth.require_jwt(_Req(), creds)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_plain_token_still_accepted(enabled_admin, monkeypatch):
    """The gate must reject scope tokens WITHOUT breaking ordinary ones."""
    monkeypatch.setattr(auth, "_session_validator", lambda jti: True)
    tok = auth.create_token("admin")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=tok)
    payload = await auth.require_jwt(_Req(), creds)
    assert payload["sub"] == "admin"
    assert "scope" not in payload


@pytest.mark.asyncio
async def test_verify_endpoint_rejects_scope_token(enabled_admin, monkeypatch):
    """`/auth/verify` is the nginx auth_request target — same rule applies."""
    monkeypatch.setattr(auth, "_session_validator", lambda jti: True)
    tok = auth.create_token("admin", scope="mfa-challenge", expires_in=300)
    with pytest.raises(HTTPException) as exc:
        await auth.verify(_Req(cookies={auth.SESSION_COOKIE: tok}))
    assert exc.value.status_code == 401


# ── B — the default session validator must be fail-closed ────────────────
def test_default_session_validator_is_fail_closed(tmp_path, monkeypatch):
    """A freshly imported secubox_core.auth must NOT accept unknown sessions.

    Only `secubox-auth` ever calls `set_session_validator()`. Every module
    served on its own socket keeps the default — 44 of them on gk2. With a
    permissive default, logout and revocation are inert there.
    """
    monkeypatch.setenv("SECUBOX_AUTH_SESSIONS", str(tmp_path / "sessions.json"))
    fresh = importlib.reload(auth)
    try:
        assert fresh._session_validator("some-jti-that-was-never-issued") is False
    finally:
        importlib.reload(auth)


# ── B' — a shared session store, readable by every module ────────────────
def test_shared_session_store_exists():
    from secubox_core import sessions  # noqa: F401


def test_session_store_accepts_a_known_jti(tmp_path, monkeypatch):
    store = tmp_path / "sessions.json"
    store.write_text(json.dumps([{"id": "abc123", "username": "admin"}]))
    monkeypatch.setenv("SECUBOX_AUTH_SESSIONS", str(store))
    from secubox_core import sessions
    sessions.invalidate_cache()
    assert sessions.is_valid("abc123") is True
    assert sessions.is_valid("not-in-the-file") is False


def test_session_store_sees_revocation_without_restart(tmp_path, monkeypatch):
    """Revocation must land without bouncing 144 services."""
    store = tmp_path / "sessions.json"
    store.write_text(json.dumps([{"id": "abc123"}]))
    monkeypatch.setenv("SECUBOX_AUTH_SESSIONS", str(store))
    from secubox_core import sessions
    sessions.invalidate_cache()
    assert sessions.is_valid("abc123") is True
    store.write_text(json.dumps([]))          # logout
    sessions.invalidate_cache()               # stands in for the mtime tick
    assert sessions.is_valid("abc123") is False


@pytest.mark.parametrize("body", ["", "{ not json", "null"])
def test_session_store_fails_closed_on_unreadable_file(tmp_path, monkeypatch, body):
    """Corrupt or missing store ⇒ deny. Never the reverse."""
    store = tmp_path / "sessions.json"
    store.write_text(body)
    monkeypatch.setenv("SECUBOX_AUTH_SESSIONS", str(store))
    from secubox_core import sessions
    sessions.invalidate_cache()
    assert sessions.is_valid("anything") is False


def test_session_store_fails_closed_when_file_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_AUTH_SESSIONS", str(tmp_path / "nope.json"))
    from secubox_core import sessions
    sessions.invalidate_cache()
    assert sessions.is_valid("anything") is False


# ── E — no silent insecure JWT secret ────────────────────────────────────
def test_missing_jwt_secret_raises(monkeypatch, tmp_path):
    """Booting with no secret must fail loudly, not sign with a known string."""
    monkeypatch.delenv("SECUBOX_JWT_SECRET", raising=False)
    monkeypatch.setattr(auth, "get_config", lambda section: {})
    with pytest.raises(RuntimeError):
        auth._secret()


def test_insecure_placeholder_is_gone():
    src = Path(auth.__file__).read_text()
    assert "CHANGEME_INSECURE" not in src
