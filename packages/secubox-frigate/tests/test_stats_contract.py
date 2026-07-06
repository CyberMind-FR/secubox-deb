# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import importlib
from fastapi.testclient import TestClient

def test_stats_top_level_keys(monkeypatch):
    import api.main as m
    importlib.reload(m)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "t"}
    monkeypatch.setattr(m, "_frigate_get", lambda p: (
        ({"cameras": {"demo": {"camera_fps": 5, "detection_fps": 4.5, "process_fps": 5}},
          "detectors": {"ov": {"inference_speed": 10.0}}, "service": {"version": "0.14.1"}}, True)
        if p == "/api/stats" else ([{"id": "1", "label": "car", "camera": "demo"}], True)))
    m._cache.clear()
    b = TestClient(m.app).get("/api/v1/frigate/stats").json()
    assert set(["cameras", "events", "fps"]).issubset(b), "sidebar reads top-level cameras/events/fps"
    assert b["cameras"] == 1 and b["events"] == 1 and b["fps"] == 10.0
