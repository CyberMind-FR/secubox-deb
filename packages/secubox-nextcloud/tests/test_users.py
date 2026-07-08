# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import importlib
from fastapi.testclient import TestClient


def _load(monkeypatch, running=True):
    import api.main as m
    importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    monkeypatch.setattr(m, "lxc_running", lambda: running)
    return m


def test_users_list_detailed(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True,
        '[{"uid":"alice","displayname":"Alice","enabled":true,"quota":"5 GB"}]', ""))
    c = TestClient(m.app)
    r = c.get("/users")
    assert r.status_code == 200
    assert r.json()["users"][0]["uid"] == "alice"


def test_users_list_info_map(monkeypatch):
    # occ user:list --info shape: {uid: {display_name, enabled, quota, last_seen}}
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True,
        '{"admin":{"user_id":"admin","display_name":"Admin","enabled":true,'
        '"quota":"none","last_seen":"2026-06-01T04:48:17+00:00"},'
        '"bob":{"user_id":"bob","display_name":"Bob","enabled":false,"quota":"5 GB"}}', ""))
    c = TestClient(m.app)
    r = c.get("/users")
    assert r.status_code == 200
    users = {u["uid"]: u for u in r.json()["users"]}
    assert users["admin"]["displayname"] == "Admin"
    assert users["admin"]["enabled"] is True
    assert users["admin"]["quota"] == "none"
    assert users["bob"]["enabled"] is False


def test_users_list_bare_map_fallback(monkeypatch):
    # fallback occ user:list --output=json shape: {uid: displayname}
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True, '{"admin":"admin","gk2":"gk2"}', ""))
    c = TestClient(m.app)
    r = c.get("/users")
    assert r.status_code == 200
    users = {u["uid"]: u for u in r.json()["users"]}
    assert users["gk2"]["displayname"] == "gk2"
    assert users["gk2"]["enabled"] is True


def test_create_user_calls_ctl(monkeypatch):
    m = _load(monkeypatch)
    seen = {}
    monkeypatch.setattr(m, "ctl", lambda sub, **k: (seen.setdefault("sub", sub), (True, "created", ""))[1])
    c = TestClient(m.app)
    r = c.post("/user", json={"uid": "bob", "display_name": "Bob", "password": "s3cret!!"})
    assert r.status_code == 200 and r.json()["success"] is True
    assert seen["sub"][:2] == ["user", "add"]


def test_bad_uid_rejected_400(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True, "", ""))
    c = TestClient(m.app)
    for path in ["/user/a;rm/enable", "/user/a b/disable"]:
        assert c.post(path).status_code == 400


def test_user_ops_409_when_not_running(monkeypatch):
    m = _load(monkeypatch, running=False)
    c = TestClient(m.app)
    assert c.post("/user/alice/enable").status_code == 409
    assert c.post("/user", json={"uid": "x", "display_name": "X", "password": "yyyyyyyy"}).status_code == 409


def test_quota_validation(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True, "", ""))
    c = TestClient(m.app)
    assert c.post("/user/alice/quota", json={"quota": "5GB"}).status_code == 200
    assert c.post("/user/alice/quota", json={"quota": "$(x)"}).status_code == 400


def test_reset_password_uses_stdin_not_argv(monkeypatch):
    m = _load(monkeypatch)  # running=True
    seen = {}
    def fake_ctl(sub, timeout=60, stdin=None):
        seen["sub"] = sub; seen["stdin"] = stdin
        return True, "", ""
    monkeypatch.setattr(m, "ctl", fake_ctl)
    c = TestClient(m.app)
    r = c.post("/user/password", json={"uid": "alice", "password": "it's a s3cret"})
    assert r.status_code == 200
    assert seen["sub"][:2] == ["user", "setpass"]
    # the password must NOT appear anywhere in the argv subcmd
    assert not any("OC_PASS" in str(x) or "resetpassword" in str(x) or "s3cret" in str(x) for x in seen["sub"])
    assert seen["stdin"] is not None  # password went via stdin
    assert "s3cret" in seen["stdin"]


def test_reset_password_bad_uid_rejected_400(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True, "", ""))
    c = TestClient(m.app)
    r = c.post("/user/password", json={"uid": "a;rm -rf /", "password": "x"})
    assert r.status_code == 400


def test_reset_password_409_when_not_running(monkeypatch):
    m = _load(monkeypatch, running=False)
    c = TestClient(m.app)
    r = c.post("/user/password", json={"uid": "alice", "password": "x"})
    assert r.status_code == 409
