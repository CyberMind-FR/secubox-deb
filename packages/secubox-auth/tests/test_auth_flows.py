# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

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
    # Webui-toggleable runtime settings live here; isolate to tmp so a test
    # never reads/writes the real /etc/secubox/auth-runtime.json.
    monkeypatch.setenv("SECUBOX_AUTH_RUNTIME", str(tmp_path / "auth-runtime.json"))

    # Isolate config: the real /etc/secubox/secubox.conf may exist but be
    # unreadable to the test user (0640 secubox:secubox). Force the in-code
    # dev defaults so _load() never touches it.
    from secubox_core import config as sbx_config
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)

    # Point user_store at the temp file
    from secubox_core import user_store
    monkeypatch.setattr(user_store, "USERS_PATH", users_path)

    # Re-import the app for a clean state
    import importlib
    from api import main as auth_main
    importlib.reload(auth_main)

    return TestClient(auth_main.app), users_path, sessions_path


def test_admin_password_login_default_off_returns_session(client):
    """Default (require_admin_totp unset) → admin logs in with password only.

    The requirement now defaults OFF so a node stays reachable; it is opted
    back in from the webui, which writes /etc/secubox/auth-runtime.json.
    """
    c, users_path, _ = client
    r = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    assert r.status_code == 200
    body = r.json()
    assert body.get("access_token"), body
    assert not body.get("enrollment_required")


def test_admin_enrollment_forced_when_runtime_requires_totp(client):
    """require_admin_totp=true (webui toggle → runtime file) forces enrollment."""
    c, users_path, _ = client
    from api import main as auth_main
    auth_main._AUTH_RUNTIME_FILE.write_text(json.dumps({"require_admin_totp": True}))
    r = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    assert r.status_code == 200
    body = r.json()
    assert body.get("enrollment_required") is True
    assert "enrollment_token" in body


def test_admin_login_session_when_totp_not_required(client, monkeypatch):
    """require_admin_totp=false in [auth] config → admin logs in with password only."""
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


def test_admin_login_allowed_when_config_errors(client, monkeypatch):
    """Reachability-first: a get_config error must NOT lock admins out.

    With no runtime override present, a config read error falls through to the
    default-OFF value (fail-open), so the admin still gets a session.
    """
    c, _users_path, _ = client
    from api import main as auth_main

    def _boom(section=""):
        raise RuntimeError("config unreadable")

    monkeypatch.setattr(auth_main, "get_config", _boom)
    r = c.post("/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"})
    assert r.status_code == 200
    assert r.json().get("access_token")
    assert not r.json().get("enrollment_required")


def test_settings_endpoint_roundtrip(client):
    """GET reflects the toggle; an admin POST flips and persists it."""
    c, _users_path, _ = client
    tok = c.post(
        "/auth/login", json={"username": "admin", "password": "GoodPass!42xyz"}
    ).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}

    assert c.get("/settings", headers=h).json() == {"require_admin_totp": False}

    r_on = c.post("/settings", json={"require_admin_totp": True}, headers=h)
    assert r_on.status_code == 200
    assert r_on.json() == {"require_admin_totp": True}
    assert c.get("/settings", headers=h).json() == {"require_admin_totp": True}

    # An admin whose session predates the toggle can still turn it back off.
    r_off = c.post("/settings", json={"require_admin_totp": False}, headers=h)
    assert r_off.json() == {"require_admin_totp": False}


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
    # Enrollment only triggers when the admin-TOTP requirement is on.
    from api import main as auth_main
    auth_main._AUTH_RUNTIME_FILE.write_text(json.dumps({"require_admin_totp": True}))

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
    # Enrollment only triggers when the admin-TOTP requirement is on.
    from api import main as auth_main
    auth_main._AUTH_RUNTIME_FILE.write_text(json.dumps({"require_admin_totp": True}))

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
