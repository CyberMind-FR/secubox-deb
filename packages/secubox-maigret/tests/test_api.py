# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""API tests for secubox-maigret. The container/subprocess layer is monkeypatched
so no real LXC is needed. If secubox_core / fastapi aren't importable, or the
import-time data-dir mkdir isn't permitted in this environment, the tests skip
cleanly instead of failing collection."""
import importlib
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("secubox_core")
from fastapi.testclient import TestClient


def _load(monkeypatch, installed=True, running=True):
    try:
        import api.main as m
        importlib.reload(m)
    except OSError as e:  # import-time mkdir of /var/lib/secubox/maigret denied
        pytest.skip(f"data dir not writable in this env: {e}")
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    monkeypatch.setattr(m, "_ctl_status",
                        lambda: {"running": running, "installed": installed,
                                 "ip": "10.100.0.42", "tools": {"maigret": running}})
    return m


def test_status_shape_when_down(monkeypatch):
    m = _load(monkeypatch, installed=False, running=False)
    c = TestClient(m.app)
    r = c.get("/status")
    assert r.status_code == 200
    body = r.json()
    assert body["module"] == "maigret"
    assert body["installed"] is False and body["running"] is False
    assert body["ip"] == "10.100.0.42"
    assert "total_lookups" in body


def test_health_no_auth(monkeypatch):
    m = _load(monkeypatch)
    assert TestClient(m.app).get("/health").json() == {"status": "ok", "module": "maigret"}


def test_lookup_writes_pending_and_returns_id(monkeypatch):
    m = _load(monkeypatch)
    spawned = {}
    # Don't spawn a real detached worker; capture args and let the endpoint's own
    # write-pending logic run so we can read the record back.
    monkeypatch.setattr(m.subprocess, "Popen",
                        lambda *a, **k: spawned.setdefault("argv", a[0]))
    c = TestClient(m.app)
    r = c.post("/lookup", json={"username": "johndoe"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "started" and body["username"] == "johndoe"
    lid = body["lookup_id"]
    assert len(lid) == 8
    # spawned worker is the detached ctl call
    assert spawned["argv"][:4] == ["sudo", "-n", m.CTL, "lookup"]
    assert spawned["argv"][4] == "johndoe"
    # GET /lookup/{id} returns the pending record just written
    g = c.get("/lookup/" + lid)
    assert g.status_code == 200
    rec = g.json()
    assert rec["id"] == lid and rec["username"] == "johndoe" and rec["status"] == "pending"
    # cleanup
    assert c.delete("/lookup/" + lid).status_code == 200
    assert c.get("/lookup/" + lid).status_code == 404


def test_invalid_username_400(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: None)
    c = TestClient(m.app)
    for bad in ["-flag", "a b", "a;rm -rf /", "../x", ""]:
        assert c.post("/lookup", json={"username": bad}).status_code == 400


def test_lookup_when_not_installed_409(monkeypatch):
    m = _load(monkeypatch, installed=False, running=False)
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: None)
    c = TestClient(m.app)
    assert c.post("/lookup", json={"username": "johndoe"}).status_code == 409


def test_get_and_delete_id_validated(monkeypatch):
    m = _load(monkeypatch)
    c = TestClient(m.app)
    assert c.get("/lookup/NOTHEX99").status_code == 400
    assert c.delete("/lookup/../etc").status_code in (400, 404)
    assert c.get("/lookup/a1b2c3d4").status_code == 404   # valid hex, no record


def test_install_detached_when_absent(monkeypatch):
    m = _load(monkeypatch, installed=False, running=False)
    called = {}
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: called.setdefault("argv", a[0]))
    c = TestClient(m.app)
    r = c.post("/install")
    assert r.status_code == 200 and r.json()["status"] == "installing"
    assert called["argv"][:4] == ["sudo", "-n", m.CTL, "install"]


def test_install_refused_when_present(monkeypatch):
    m = _load(monkeypatch, installed=True)
    assert TestClient(m.app).post("/install").status_code == 400
