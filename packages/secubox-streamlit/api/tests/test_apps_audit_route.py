"""Tests for GET /apps/audit — the route consumed by the Mosaic tab (#956).

The endpoint is a thin, deliberately public (no JWT) passthrough to
`streamlitctl app audit`, run with a 60s timeout since the command takes
~11s on the board. These tests only lock down the wiring: that it shells
out to the right sub-command/timeout and returns the ctl's JSON verbatim,
without requiring authentication.
"""
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from api.main import app


def test_apps_audit_is_public_and_returns_ctl_payload():
    """No Authorization header required; JSON stdout from streamlitctl is
    returned as-is."""
    payload = (
        b'{"apps": [{"name": "fabricator", "shape": "dir", "entrypoint": "app.py", '
        b'"declared": true, "running": true, "port": 8520, "issues": ["stale-port"]}], '
        b'"summary": {"total": 66, "running": 15}}'
    )
    fake = MagicMock(returncode=0, stdout=payload.decode(), stderr="")
    with patch("api.main.subprocess.run", return_value=fake) as run_mock:
        client = TestClient(app)
        r = client.get("/apps/audit")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"] == {"total": 66, "running": 15}
    assert body["apps"][0]["name"] == "fabricator"

    args = run_mock.call_args.args[0]
    assert args[:2] == ["sudo", "-n"]
    assert "app" in args and "audit" in args
    assert run_mock.call_args.kwargs.get("timeout") == 60


def test_apps_audit_survives_ctl_timeout():
    """If streamlitctl hangs past 60s, the route reports the error instead
    of raising — same contract as the other _run_ctl-backed routes."""
    import subprocess

    with patch("api.main.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="streamlitctl", timeout=60)):
        client = TestClient(app)
        r = client.get("/apps/audit")

    assert r.status_code == 200, r.text
    assert r.json().get("error") == "timeout"
