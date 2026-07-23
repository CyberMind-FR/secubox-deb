# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import json
import subprocess
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from api.main import app, _ctl

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


# --- Couche _ctl → OS : ces tests patchent subprocess.run (pas _ctl) pour
# exercer le VRAI corps de _ctl. Voir revue de la tâche 2 : les 3 tests
# ci-dessus ne couvrent que routeur→_ctl ; ceux-ci couvrent _ctl→OS. ---

def test_ctl_invokes_exact_privileged_argv():
    """Règle centrale du module : une seule surface root, auditée.

    Doit échouer si quelqu'un retire "sudo"/"-n" ou change le chemin du ctl.
    """
    with patch("api.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n")
        _ctl(["start"])
    mock_run.assert_called_once()
    argv = mock_run.call_args[0][0]
    assert argv == ["sudo", "-n", "/usr/sbin/picobrewctl", "start"]


def test_ctl_survives_missing_binary():
    """picobrewctl absent (FileNotFoundError) : _ctl ne lève jamais."""
    with patch("api.main.subprocess.run", side_effect=FileNotFoundError):
        rc, out = _ctl(["status"])
    assert rc == 1
    assert out == ""


def test_ctl_survives_timeout():
    """ctl trop lent (TimeoutExpired) : _ctl ne lève jamais."""
    with patch("api.main.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="x", timeout=20)):
        rc, out = _ctl(["status"])
    assert rc == 1
    assert out == ""


def test_status_route_survives_empty_ctl_output():
    """rc=0 mais stdout vide : le panel reçoit un repli exploitable, pas un crash."""
    with patch("api.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        r = client.get("/status")
    assert r.status_code == 200
    body = r.json()
    assert body["installed"] is False
    assert body["running"] is False
    assert body["error"]


def test_status_route_survives_invalid_json():
    """rc=0, stdout non-JSON : la garde JSONDecodeError doit intercepter."""
    with patch("api.main.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0,
                                           stdout="ceci n'est pas du json")
        r = client.get("/status")
    assert r.status_code == 200
    body = r.json()
    assert body["installed"] is False
    assert body["error"]
