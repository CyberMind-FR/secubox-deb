"""End-to-end auth flows: password + TOTP + set-password + disable."""
import json
from pathlib import Path

import pyotp
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    # Configure paths
    users_path = tmp_path / "users.json"
    sessions_path = tmp_path / "sessions.json"
    audit_path = tmp_path / "audit.log"
    pending_path = tmp_path / "totp-pending.json"

    # Pre-seed admin with password set, no TOTP yet (will trigger enrollment branch).
    pw_hash = PasswordHasher().hash("GoodPass!42xyz")
    users_path.write_text(json.dumps({
        "version": 2,
        "users": [{
            "username": "admin",
            "email": "a@b.c",
            "role": "admin",
            "enabled": True,
            "password_hash": pw_hash,
            "must_change_password": False,
            "totp": None,
            "google": None,
            "services": [],
            "created": "2026-05-13T00:00:00+00:00",
            "last_login": None,
        }],
        "groups": [],
    }))
    sessions_path.write_text("[]")
    pending_path.write_text("{}")

    monkeypatch.setenv("USERS_FILE", str(users_path))
    monkeypatch.setenv("SECUBOX_AUTH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SECUBOX_AUTH_SESSIONS", str(sessions_path))
    monkeypatch.setenv("SECUBOX_AUTH_AUDIT", str(audit_path))
    monkeypatch.setenv("SECUBOX_AUTH_TOTP_PENDING", str(pending_path))
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret")

    # Point user_store at the temp file
    from secubox_core import user_store
    monkeypatch.setattr(user_store, "USERS_PATH", users_path)

    # Re-import the app for a clean state
    import importlib
    from api import main as auth_main
    importlib.reload(auth_main)

    return TestClient(auth_main.app), users_path, sessions_path


def test_admin_password_login_returns_enrollment_token(client):
    c, users_path, _ = client
    r = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    assert r.status_code == 200
    body = r.json()
    assert body.get("enrollment_required") is True
    assert "enrollment_token" in body


def test_wrong_password_returns_401(client):
    c, *_ = client
    r = c.post("/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_disabled_user_blocked(client):
    c, users_path, sessions_path = client
    # disable admin
    doc = json.loads(users_path.read_text())
    doc["users"][0]["enabled"] = False
    users_path.write_text(json.dumps(doc))
    r = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    assert r.status_code == 401


def test_full_totp_enrollment_then_login(client):
    c, users_path, sessions_path = client

    # 1. Login → enrollment_token
    r1 = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    enroll_tok = r1.json()["enrollment_token"]

    # 2. Enroll → secret + QR
    r2 = c.post("/auth/totp/enroll", headers={"Authorization": f"Bearer {enroll_tok}"})
    assert r2.status_code == 200
    secret = r2.json()["secret"]
    assert "otpauth_uri" in r2.json()

    # 3. Confirm with wrong code → 401, pending kept
    r3 = c.post(
        "/auth/totp/confirm",
        json={"code": "000000"},
        headers={"Authorization": f"Bearer {enroll_tok}"},
    )
    assert r3.status_code == 401

    # 4. Confirm with correct code → access_token + backup codes
    code = pyotp.TOTP(secret).now()
    r4 = c.post(
        "/auth/totp/confirm",
        json={"code": code},
        headers={"Authorization": f"Bearer {enroll_tok}"},
    )
    assert r4.status_code == 200
    assert "access_token" in r4.json()
    assert len(r4.json()["backup_codes"]) == 10

    # 5. Next login now gets mfa_required
    r5 = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    assert r5.status_code == 200
    assert r5.json()["mfa_required"] is True
