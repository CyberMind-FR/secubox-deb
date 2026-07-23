# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
from unittest.mock import patch
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

def test_status_reflects_ctl_output():
    """L'API ne devine rien : elle relaie le verdict du ctl."""
    payload = json.dumps({"installed": True, "running": False, "ip": "10.100.0.140",
                          "pinned_sha": "0123456789abcdef0123456789abcdef01234567",
                          "session_active": False})
    with patch("api.main._ctl", return_value=(0, payload)):
        r = client.get("/status")
    assert r.status_code == 200
    assert r.json()["installed"] is True and r.json()["running"] is False
    assert r.json()["ip"] == "10.100.0.140"

def test_status_degrades_cleanly_when_ctl_fails():
    """Un ctl indisponible ne doit pas 500 le panel : état inconnu, pas de crash."""
    with patch("api.main._ctl", return_value=(1, "")):
        r = client.get("/status")
    assert r.status_code == 200
    assert r.json()["installed"] is False
    assert r.json()["error"]

def test_start_delegates_to_ctl_and_never_runs_privileged_itself():
    with patch("api.main._ctl", return_value=(0, "")) as m:
        r = client.post("/start")
    assert r.status_code == 200
    assert m.call_args[0][0] == ["start"]
