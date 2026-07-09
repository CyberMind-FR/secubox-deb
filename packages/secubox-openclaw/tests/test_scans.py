import importlib, json
from fastapi.testclient import TestClient
def _load(monkeypatch, installed=True):
    import api.main as m; importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    monkeypatch.setattr(m, "_ctl_status", lambda: {"running": True, "installed": installed, "ip": "10.100.0.41", "tools": {}})
    return m

def test_external_active_scan_refused_without_authorization(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "_spawn_worker", lambda *a, **k: None)
    c = TestClient(m.app)
    r = c.post("/scan/ip", json={"target": "scanme.nmap.org"})
    assert r.status_code == 409

def test_external_active_scan_allowed_when_authorized(monkeypatch):
    m = _load(monkeypatch); spawned = {}
    monkeypatch.setattr(m, "_spawn_worker", lambda t, tgt, i: spawned.update(type=t, target=tgt, id=i))
    c = TestClient(m.app)
    r = c.post("/scan/ip", json={"target": "scanme.nmap.org", "authorized": True})
    assert r.status_code == 200 and r.json()["status"] == "started"
    assert spawned["type"] == "ip"

def test_lan_active_scan_allowed_without_authorization(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "_spawn_worker", lambda *a, **k: None)
    c = TestClient(m.app)
    assert c.post("/scan/ip", json={"target": "192.168.1.5"}).status_code == 200

def test_passive_domain_scan_always_allowed(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "_spawn_worker", lambda *a, **k: None)
    c = TestClient(m.app)
    assert c.post("/scan/domain", json={"target": "scanme.nmap.org"}).status_code == 200

def test_bad_target_rejected_400(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "_spawn_worker", lambda *a, **k: None)
    c = TestClient(m.app)
    assert c.post("/scan/domain", json={"target": "a;rm -rf /"}).status_code == 400

def test_scan_get_and_delete_id_validated(monkeypatch):
    m = _load(monkeypatch)
    c = TestClient(m.app)
    assert c.get("/scan/NOTHEX99").status_code == 400
    assert c.delete("/scan/../etc").status_code in (400, 404)

def test_install_detached_when_absent(monkeypatch):
    m = _load(monkeypatch, installed=False)
    called = {}
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: called.setdefault("argv", a[0]))
    c = TestClient(m.app)
    r = c.post("/install")
    assert r.status_code == 200 and r.json()["status"] == "installing"
    assert called["argv"][:4] == ["sudo", "-n", m.CTL, "install"]

def test_install_refused_when_present(monkeypatch):
    m = _load(monkeypatch, installed=True)
    assert TestClient(m.app).post("/install").status_code == 400
