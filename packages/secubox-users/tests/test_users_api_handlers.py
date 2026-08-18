# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-users API handlers — verify each mutation delegates to engine.*

Tests in this module use FastAPI TestClient with:
- USERS_FILE pointed at a tmp_path JSON file
- require_jwt bypassed (monkeypatched to a no-op)
- engine reloaded so _engine picks up the patched USERS_FILE env var
"""
import importlib
import json
import sys
from pathlib import Path

import pytest

# Ensure both secubox_core stub and api/ are importable (mirrors conftest.py)
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-users"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _noop_jwt():
    """Sync stub that satisfies Depends(require_jwt)."""
    return {"sub": "admin"}


def _make_client(tmp_path: Path, monkeypatch):
    """Build a TestClient pointing at a fresh users.json in tmp_path."""
    from fastapi.testclient import TestClient

    users_path = tmp_path / "users.json"
    users_path.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    monkeypatch.setenv("USERS_FILE", str(users_path))

    # Reload main so _engine re-reads USERS_FILE from the env
    import api.main as users_main
    importlib.reload(users_main)

    # Bypass JWT auth via FastAPI dependency_overrides (works regardless of
    # how require_jwt is referenced in the module — captures the actual callable
    # object used in Depends()).
    users_main.app.dependency_overrides[users_main.require_jwt] = _noop_jwt

    # Bypass RBAC: user_has_permission always returns True so require_permission
    # passes for "admin" (the sub returned by _noop_jwt) regardless of the
    # users.json content in tests focused on mutation behaviour, not access control.
    monkeypatch.setattr(users_main, "user_has_permission", lambda *_a, **_kw: True)

    return TestClient(users_main.app), users_path, users_main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ctx(tmp_path: Path, monkeypatch):
    """Return (client, users_path, main_module) with JWT bypassed."""
    return _make_client(tmp_path, monkeypatch)


@pytest.fixture
def ctx_with_alice(tmp_path: Path, monkeypatch):
    """ctx with alice pre-created via engine."""
    client, users_path, main_mod = _make_client(tmp_path, monkeypatch)
    from api import engine
    e = engine.Engine(users_path=users_path)
    e.create_user("alice", email="alice@example.com", role="viewer")
    return client, users_path, main_mod


# ---------------------------------------------------------------------------
# POST /user — create_user delegates to engine
# ---------------------------------------------------------------------------

def test_create_user_writes_via_engine(ctx):
    client, users_path, _ = ctx
    r = client.post("/user", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "ignored-for-internal-hash",
        "services": [],
    })
    assert r.status_code == 200
    doc = json.loads(users_path.read_text())
    names = [u["username"] for u in doc["users"]]
    assert "bob" in names


def test_create_duplicate_user_returns_400(ctx):
    client, users_path, _ = ctx
    payload = {"username": "bob", "email": "bob@example.com", "password": "x", "services": []}
    client.post("/user", json=payload)
    r = client.post("/user", json=payload)
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# POST /user/{username}/disable — delegates to engine.disable_user
# ---------------------------------------------------------------------------

def test_disable_endpoint_calls_engine(ctx_with_alice):
    client, users_path, _ = ctx_with_alice
    r = client.post("/user/alice/disable")
    assert r.status_code == 200
    assert r.json().get("ok") is True
    doc = json.loads(users_path.read_text())
    assert doc["users"][0]["enabled"] is False


def test_disable_unknown_user_returns_404(ctx):
    client, _, _ = ctx
    r = client.post("/user/nobody/disable")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# POST /user/{username}/enable — delegates to engine.enable_user
# ---------------------------------------------------------------------------

def test_enable_endpoint_calls_engine(ctx_with_alice):
    client, users_path, _ = ctx_with_alice
    # First disable
    client.post("/user/alice/disable")
    assert json.loads(users_path.read_text())["users"][0]["enabled"] is False
    # Then re-enable
    r = client.post("/user/alice/enable")
    assert r.status_code == 200
    assert r.json().get("ok") is True
    doc = json.loads(users_path.read_text())
    assert doc["users"][0]["enabled"] is True


# ---------------------------------------------------------------------------
# DELETE /user/{username} — delegates to engine.delete_user
# ---------------------------------------------------------------------------

def test_delete_endpoint_calls_engine(ctx_with_alice):
    client, users_path, _ = ctx_with_alice
    r = client.delete("/user/alice")
    assert r.status_code == 200
    doc = json.loads(users_path.read_text())
    assert doc["users"] == []


def test_delete_unknown_user_returns_404(ctx):
    client, _, _ = ctx
    r = client.delete("/user/nobody")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# POST /user/{username}/totp/disable — delegates to engine.disable_totp
# ---------------------------------------------------------------------------

def test_totp_disable_endpoint(ctx_with_alice):
    client, users_path, _ = ctx_with_alice
    # Enroll TOTP first
    from api import engine as _eng
    e = _eng.Engine(users_path=users_path)
    e.enroll_totp("alice", secret="JBSWY3DPEHPK3PXP")
    assert json.loads(users_path.read_text())["users"][0]["totp"] is not None

    r = client.post("/user/alice/totp/disable")
    assert r.status_code == 200
    assert r.json().get("ok") is True
    doc = json.loads(users_path.read_text())
    assert doc["users"][0]["totp"] is None


def test_totp_disable_unknown_user_returns_404(ctx):
    client, _, _ = ctx
    r = client.post("/user/nobody/totp/disable")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# POST /user/{username}/totp/backup-codes — delegates to engine.regenerate_backup_codes
# ---------------------------------------------------------------------------

def test_regen_backup_codes_endpoint(ctx_with_alice):
    client, users_path, _ = ctx_with_alice
    from api import engine as _eng
    e = _eng.Engine(users_path=users_path)
    e.enroll_totp("alice", secret="JBSWY3DPEHPK3PXP")

    r = client.post("/user/alice/totp/backup-codes")
    assert r.status_code == 200
    codes = r.json().get("backup_codes", [])
    assert len(codes) == 10
    assert all(isinstance(c, str) for c in codes)


def test_regen_backup_codes_without_totp_returns_400(ctx_with_alice):
    """Regeneration on a user without TOTP enrolled must return 400."""
    client, _, _ = ctx_with_alice
    r = client.post("/user/alice/totp/backup-codes")
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# GET /user/{username}/sessions — filters sessions by username
# ---------------------------------------------------------------------------

def test_list_user_sessions_filters_by_username(ctx_with_alice, tmp_path, monkeypatch):
    client, users_path, main_mod = ctx_with_alice
    sessions_path = tmp_path / "sessions.json"
    sessions_path.write_text(json.dumps([
        {"username": "alice", "id": "s1", "expires": 9_999_999_999},
        {"username": "bob",   "id": "s2", "expires": 9_999_999_999},
    ]))
    monkeypatch.setenv("SECUBOX_AUTH_SESSIONS", str(sessions_path))
    # Patch SESSIONS_FILE in the reloaded module
    monkeypatch.setattr(main_mod, "SESSIONS_FILE", str(sessions_path))

    r = client.get("/user/alice/sessions")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert all(s["username"] == "alice" for s in data)
    assert len(data) == 1


def test_list_user_sessions_missing_file(ctx_with_alice, monkeypatch):
    """Missing sessions file returns empty list, not an error."""
    client, _, main_mod = ctx_with_alice
    monkeypatch.setattr(main_mod, "SESSIONS_FILE", "/nonexistent/sessions.json")
    r = client.get("/user/alice/sessions")
    assert r.status_code == 200
    assert r.json() == []


# ---------------------------------------------------------------------------
# POST /user/{username}/sessions/revoke — delegates to engine.revoke_sessions
# ---------------------------------------------------------------------------

def test_revoke_user_sessions_endpoint(ctx_with_alice, monkeypatch):
    client, users_path, main_mod = ctx_with_alice
    # Wire a fake revoke callback into the engine instance
    revoked_for = []
    from api import engine as _eng
    # Reload engine instance to inject callback
    e = main_mod._engine
    e.set_revoke_callback(lambda name: revoked_for.append(name) or 3)

    r = client.post("/user/alice/sessions/revoke")
    assert r.status_code == 200
    assert r.json()["revoked"] == 3
    assert "alice" in revoked_for


# ---------------------------------------------------------------------------
# POST /user/{username}/password — hashes locally via engine
# ---------------------------------------------------------------------------

def test_password_endpoint_writes_hash_and_returns_propagation_results(
    tmp_path: Path, monkeypatch
):
    """POST /user/{u}/password hashes locally via engine AND attempts external
    service propagation. Verifies the local argon2id hash is written."""
    client, users_path, main_mod = _make_client(tmp_path, monkeypatch)

    # Pre-create the target user via engine
    from api import engine as _eng
    e = _eng.Engine(users_path=users_path)
    e.create_user("bob", email="b@b.c", role="viewer")

    # No mocking of subprocess — external services may legitimately fail when
    # not installed; we only assert on the local hash side-effect.
    r = client.post("/user/bob/password", json={"password": "GoodPass!42xyz"})
    assert r.status_code == 200

    # Local password_hash must be set in users.json
    doc = json.loads(users_path.read_text())
    u = next(x for x in doc["users"] if x["username"] == "bob")
    assert u["password_hash"] is not None
    assert u["password_hash"].startswith("$argon2id$")
    assert u["must_change_password"] is False
