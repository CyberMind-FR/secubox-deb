# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import importlib
import socket

from fastapi.testclient import TestClient


def _load(monkeypatch):
    import api.main as m
    importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    return m


def test_ctl_routes_through_sudo_nextcloudctl(monkeypatch):
    m = _load(monkeypatch)
    seen = {}

    def fake_run(cmd, timeout=30):
        seen["cmd"] = cmd
        return True, "RUNNING", ""

    monkeypatch.setattr(m, "run_cmd", fake_run)
    ok, out, _ = m.ctl(["status", "--json"])
    assert seen["cmd"][:3] == ["sudo", "-n", "/usr/sbin/nextcloudctl"]
    assert seen["cmd"][3:] == ["status", "--json"]


def test_status_running_and_reachable(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True,
        '{"running":true,"installed":true,"version":"29.0.1","user_count":3}', ""))
    monkeypatch.setattr(m, "container_reachable", lambda: True)
    c = TestClient(m.app)
    r = c.get("/status")
    assert r.status_code == 200
    b = r.json()
    assert b["running"] is True and b["reachable"] is True
    assert b["version"] == "29.0.1" and b["user_count"] == 3
    # real URL, never localhost
    assert b["web_url"].startswith("https://") and "localhost" not in b["web_url"]


def test_status_is_cached_and_invalidated(monkeypatch):
    # /status is heavy (lxc/occ) and auto-polled; it must be cached so repeat
    # polls don't re-run the privileged helper (which would block the shared
    # aggregator loop's threadpool and storm the board). A lifecycle action
    # invalidates the cache so the next poll is fresh.
    m = _load(monkeypatch)
    calls = {"n": 0}

    def counting_ctl(sub, *a, **k):
        if list(sub[:1]) == ["status"]:
            calls["n"] += 1
        return (True, '{"running":true,"installed":true,"version":"1","user_count":1}', "")

    monkeypatch.setattr(m, "ctl", counting_ctl)
    monkeypatch.setattr(m, "container_reachable", lambda: True)
    monkeypatch.setattr(m, "lxc_installed", lambda: True)
    c = TestClient(m.app)
    c.get("/status")
    c.get("/status")
    assert calls["n"] == 1, "second poll must be served from cache"
    m._invalidate_stats()
    c.get("/status")
    assert calls["n"] == 2, "invalidation must force a fresh compute"


def test_connections_uses_real_vhost(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "public_url", lambda: "https://nc.gk2.secubox.in")
    c = TestClient(m.app)
    b = c.get("/connections").json()
    assert b["base_url"] == "https://nc.gk2.secubox.in"
    assert b["webdav"].startswith("https://nc.gk2.secubox.in/remote.php/dav/files/")
    assert "localhost" not in b["base_url"]


def test_reachable_probe_is_failsafe(monkeypatch):
    m = _load(monkeypatch)

    def boom(*a, **k):
        raise socket.timeout("nope")

    monkeypatch.setattr(socket, "create_connection", boom)
    assert m.container_reachable() is False  # never raises


def test_storage_reports_real_usage(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (True,
        '{"used":"12G","total":"100G","used_pct":12,"data":"11G"}', ""))
    c = TestClient(m.app)
    r = c.get("/storage")
    assert r.status_code == 200
    b = r.json()
    assert b["used_pct"] == 12
    assert b["used"] == "12G" and b["total"] == "100G" and b["data"] == "11G"


def test_storage_is_failsafe_on_ctl_error(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda *a, **k: (False, "", "boom"))
    c = TestClient(m.app)
    r = c.get("/storage")
    assert r.status_code == 200
    b = r.json()
    assert b["used_pct"] == 0
