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


def test_admin_login_session_when_totp_not_required(client, monkeypatch):
    """require_admin_totp=false → admin logs in with password only (no enrollment)."""
    c, _users_path, _ = client
    from api import main as auth_main
    monkeypatch.setattr(
        auth_main, "get_config",
        lambda section="": {"require_admin_totp": False} if section == "auth" else {},
    )
    r = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    assert r.status_code == 200
    body = r.json()
    assert body.get("access_token"), body
    assert not body.get("enrollment_required")


def test_admin_totp_forced_when_config_errors(client, monkeypatch):
    """Fail-secure: a get_config error keeps admin enrollment mandatory."""
    c, _users_path, _ = client
    from api import main as auth_main

    def _boom(section=""):
        raise RuntimeError("config unreadable")

    monkeypatch.setattr(auth_main, "get_config", _boom)
    r = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    assert r.status_code == 200
    assert r.json().get("enrollment_required") is True


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


def test_auth_preflight_endpoint(client, monkeypatch):
    c, *_ = client
    # Force unsynced
    from api import ntp_health
    monkeypatch.setattr(ntp_health, "probe", lambda: {"synced": False, "error": "no chronyc"})
    monkeypatch.setattr(ntp_health, "recommended_totp_window", lambda: 3)
    r = c.get("/auth/preflight")
    assert r.status_code == 200
    body = r.json()
    assert body["ntp"]["synced"] is False
    assert body["totp_window"] == 3
    assert body["identity_fallback"] in (True, False)


def test_totp_widened_window_accepts_drifted_code(client, monkeypatch):
    """With NTP degraded (window=3), a code from a step ~60s in the past still validates."""
    import time as _time
    import pyotp
    c, users_path, _ = client

    # Enroll admin
    r1 = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    enroll_tok = r1.json()["enrollment_token"]
    r2 = c.post("/auth/totp/enroll", headers={"Authorization": f"Bearer {enroll_tok}"})
    secret = r2.json()["secret"]
    code = pyotp.TOTP(secret).now()
    c.post("/auth/totp/confirm", json={"code": code},
           headers={"Authorization": f"Bearer {enroll_tok}"})

    # Degrade NTP and present a code from 60s ago
    from api import ntp_health
    monkeypatch.setattr(ntp_health, "recommended_totp_window", lambda: 3)
    r3 = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    mfa_tok = r3.json()["mfa_token"]
    drifted_code = pyotp.TOTP(secret).at(int(_time.time()) - 60)
    r4 = c.post("/auth/login/mfa", json={"code": drifted_code},
                headers={"Authorization": f"Bearer {mfa_tok}"})
    assert r4.status_code == 200
    assert "access_token" in r4.json()

    # Same drifted code resubmitted should be refused (replay protection).
    # Re-login to get a fresh mfa_token (the previous one may be consumed).
    r_replay_pw = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    mfa_tok2 = r_replay_pw.json()["mfa_token"]
    r5 = c.post("/auth/login/mfa", json={"code": drifted_code},
                headers={"Authorization": f"Bearer {mfa_tok2}"})
    assert r5.status_code == 401
