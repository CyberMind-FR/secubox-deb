# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import importlib, inspect
from fastapi.testclient import TestClient

def _app(monkeypatch, frigate_stats=None, frigate_events=None, up=True):
    import api.main as m
    importlib.reload(m)
    # bypass JWT
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "test"}
    def fake_get(path):
        if not up:
            return None, False
        if path == "/api/stats":
            return frigate_stats or {"cameras": {"demo": {"camera_fps": 5, "detection_fps": 4.9, "process_fps": 5}},
                                     "detectors": {"ov": {"inference_speed": 12.3}},
                                     "service": {"version": "0.14.1", "uptime": 3600}}, True
        if path.startswith("/api/events"):
            return frigate_events or [{"id": "1", "label": "person", "camera": "demo", "start_time": 1, "zones": []}], True
        return {}, True
    monkeypatch.setattr(m, "_frigate_get", fake_get)
    return TestClient(m.app), m

def test_status_up(monkeypatch):
    c, _ = _app(monkeypatch)
    r = c.get("/api/v1/frigate/status")
    assert r.status_code == 200
    b = r.json()
    assert b["up"] is True and b["version"] == "0.14.1"

def test_status_down_is_failsafe(monkeypatch):
    c, _ = _app(monkeypatch, up=False)
    r = c.get("/api/v1/frigate/status")
    assert r.status_code == 200          # never 5xx
    assert r.json()["up"] is False

def test_cameras_shape(monkeypatch):
    c, _ = _app(monkeypatch)
    r = c.get("/api/v1/frigate/cameras")
    assert r.status_code == 200
    cams = r.json()["cameras"]
    assert cams[0]["name"] == "demo" and cams[0]["online"] is True

def test_events_bounded(monkeypatch):
    c, _ = _app(monkeypatch)
    r = c.get("/api/v1/frigate/events")
    assert r.status_code == 200
    assert r.json()["events"][0]["label"] == "person"

def test_all_handlers_plain_def(monkeypatch):
    _, m = _app(monkeypatch)
    for name in ("status", "cameras", "events", "storage", "stats"):
        fn = getattr(m, name)
        assert not inspect.iscoroutinefunction(fn), f"{name} must be plain def (aggregator SPOF rule)"
