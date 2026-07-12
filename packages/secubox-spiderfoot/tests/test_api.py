# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""API tests for secubox-spiderfoot. The container/subprocess layer is
monkeypatched so no real LXC is needed. If secubox_core / fastapi aren't
importable, or the import-time data-dir mkdir isn't permitted in this
environment, the tests skip cleanly instead of failing collection."""
import importlib
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("secubox_core")
from fastapi.testclient import TestClient


def _load(monkeypatch, installed=True, running=True, ui_up=True):
    try:
        import api.main as m
        importlib.reload(m)
    except OSError as e:  # import-time mkdir of /var/lib/secubox/spiderfoot denied
        pytest.skip(f"data dir not writable in this env: {e}")
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    monkeypatch.setattr(m, "_ctl_status",
                        lambda: {"running": running, "installed": installed,
                                 "ip": "10.100.0.43", "port": 5001, "ui_up": ui_up})
    return m


def test_health_no_auth(monkeypatch):
    m = _load(monkeypatch)
    assert TestClient(m.app).get("/health").json() == {"status": "ok", "module": "spiderfoot"}


def test_status_shape_when_down(monkeypatch):
    m = _load(monkeypatch, installed=False, running=False, ui_up=False)
    c = TestClient(m.app)
    r = c.get("/status")
    assert r.status_code == 200
    body = r.json()
    assert body["module"] == "spiderfoot"
    assert body["installed"] is False and body["running"] is False
    assert body["ui_up"] is False
    assert body["ip"] == "10.100.0.43"
    assert body["port"] == 5001


def test_status_shape_when_up(monkeypatch):
    m = _load(monkeypatch, installed=True, running=True, ui_up=True)
    body = TestClient(m.app).get("/status").json()
    assert body["running"] is True and body["installed"] is True and body["ui_up"] is True


def test_install_detached_when_absent(monkeypatch):
    m = _load(monkeypatch, installed=False, running=False, ui_up=False)
    called = {}
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: called.setdefault("argv", a[0]))
    c = TestClient(m.app)
    r = c.post("/install")
    assert r.status_code == 200 and r.json()["status"] == "installing"
    assert called["argv"][:4] == ["sudo", "-n", m.CTL, "install"]


def test_install_refused_when_present(monkeypatch):
    m = _load(monkeypatch, installed=True)
    assert TestClient(m.app).post("/install").status_code == 400


def _record_ctl(calls):
    def _ctl(sub, timeout=60):
        calls["sub"] = sub
        return (True, "", "")
    return _ctl


def test_start_calls_ctl(monkeypatch):
    m = _load(monkeypatch)
    calls = {}
    monkeypatch.setattr(m, "ctl", _record_ctl(calls))
    r = TestClient(m.app).post("/start")
    assert r.status_code == 200 and r.json()["status"] == "started"
    assert calls["sub"] == ["start"]


def test_stop_calls_ctl(monkeypatch):
    m = _load(monkeypatch)
    calls = {}
    monkeypatch.setattr(m, "ctl", _record_ctl(calls))
    r = TestClient(m.app).post("/stop")
    assert r.status_code == 200 and r.json()["status"] == "stopped"
    assert calls["sub"] == ["stop"]


def test_restart_ui_calls_ctl(monkeypatch):
    m = _load(monkeypatch)
    calls = {}
    monkeypatch.setattr(m, "ctl", _record_ctl(calls))
    r = TestClient(m.app).post("/restart-ui")
    assert r.status_code == 200 and r.json()["status"] == "restarted"
    assert calls["sub"] == ["restart-ui"]


def test_start_ctl_failure_500(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "ctl", lambda sub, timeout=60: (False, "", "boom"))
    assert TestClient(m.app).post("/start").status_code == 500


def test_mutating_endpoints_require_jwt(monkeypatch):
    # Load WITHOUT the dependency override so require_jwt is enforced.
    try:
        import api.main as m
        importlib.reload(m)
    except OSError as e:
        pytest.skip(f"data dir not writable in this env: {e}")
    m.app.dependency_overrides.clear()
    monkeypatch.setattr(m, "_ctl_status",
                        lambda: {"running": False, "installed": False,
                                 "ip": "10.100.0.43", "port": 5001, "ui_up": False})
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: None)
    monkeypatch.setattr(m, "ctl", lambda sub, timeout=60: (True, "", ""))
    c = TestClient(m.app)
    for path in ["/install", "/start", "/stop", "/restart-ui"]:
        assert c.post(path).status_code in (401, 403), path
