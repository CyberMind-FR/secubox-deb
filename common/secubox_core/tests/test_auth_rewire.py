"""Tests for the rewired secubox_core.auth (user_store delegate + jti + scope)."""
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
        "password_hash": None,
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
def good_admin(tmp_path: Path, monkeypatch):
    h = PasswordHasher().hash("GoodPass!42xyz")
    p = tmp_path / "users.json"
    _write_user(p, password_hash=h)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret-do-not-use-in-prod-please")
    yield


def test_check_password_delegates_to_user_store(good_admin):
    assert auth._check_password("admin", "GoodPass!42xyz") is True
    assert auth._check_password("admin", "wrong") is False
    assert auth._check_password("ghost", "anything") is False


def test_create_token_includes_jti(good_admin):
    tok = auth.create_token("admin")
    payload = auth._decode_token(tok)
    assert "jti" in payload
    assert len(payload["jti"]) >= 8


def test_create_token_includes_scope_when_given(good_admin):
    tok = auth.create_token("admin", scope="set-password", expires_in=900)
    payload = auth._decode_token(tok)
    assert payload["scope"] == "set-password"


class _Req:
    """Minimal stand-in for fastapi.Request.

    `require_jwt` gained a mandatory `request` argument with SSO-lite (#400)
    so it can fall back to the session cookie; these three tests still called
    it the old way and had been failing ever since. Surfaced while working on
    #942 (a PermissionError on /etc/secubox/secubox.conf used to mask the
    TypeError on dev workstations).
    """

    def __init__(self, cookies=None):
        self.cookies = cookies or {}
        self.headers = {}


@pytest.mark.asyncio
async def test_require_jwt_rejects_unknown_jti(good_admin, monkeypatch):
    auth.set_session_validator(lambda jti: False)  # all jti unknown
    tok = auth.create_token("admin")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=tok)
    with pytest.raises(HTTPException) as ei:
        await auth.require_jwt(_Req(), creds)
    assert ei.value.status_code == 401


@pytest.mark.asyncio
async def test_require_jwt_accepts_known_jti(good_admin):
    auth.set_session_validator(lambda jti: True)
    tok = auth.create_token("admin")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=tok)
    out = await auth.require_jwt(_Req(), creds)
    assert out["sub"] == "admin"


@pytest.mark.asyncio
async def test_require_jwt_rejects_disabled_user(tmp_path: Path, monkeypatch):
    h = PasswordHasher().hash("GoodPass!42xyz")
    p = tmp_path / "users.json"
    _write_user(p, password_hash=h, enabled=False)
    monkeypatch.setattr(user_store, "USERS_PATH", p)
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret")
    auth.set_session_validator(lambda jti: True)
    tok = auth.create_token("admin")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=tok)
    with pytest.raises(HTTPException):
        await auth.require_jwt(_Req(), creds)
