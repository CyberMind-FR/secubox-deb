from fastapi.testclient import TestClient
from secubox_toolbox.app import app
from secubox_toolbox import sentinel_link as sl

client = TestClient(app)


def test_stats_active_when_daemon_up(monkeypatch):
    monkeypatch.setattr(sl, "fetch_stats",
                        lambda: {"detections": 3, "blocked": 1, "spyware": 2})
    r = client.get("/admin/sentinel/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["detections"] == 3 and body["spyware"] == 2


def test_stats_inactive_when_daemon_down(monkeypatch):
    monkeypatch.setattr(sl, "fetch_stats", lambda: {})
    r = client.get("/admin/sentinel/stats")
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is False
    assert body["detections"] == 0 and body["blocked"] == 0 and body["spyware"] == 0


def test_verdicts_shape_and_failsafe(monkeypatch):
    monkeypatch.setattr(sl, "fetch_verdicts", lambda limit=50: [
        {"class": "spyware_pegasus", "severity": 95, "confidence": 95,
         "action": "report", "evidence": {}, "mac_hash": "aa", "ts": 1, "report": "R"},
    ])
    r = client.get("/admin/sentinel/verdicts")
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["assess"]["tier"] == "suspicious"
    assert len(body["detections"]) == 1

    monkeypatch.setattr(sl, "fetch_verdicts", lambda limit=50: [])
    r = client.get("/admin/sentinel/verdicts")
    assert r.status_code == 200
    assert r.json()["active"] is False
    assert r.json()["assess"]["tier"] == "clean"
