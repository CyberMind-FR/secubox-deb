"""Tests for the idle-timeout wake endpoint (#331).

Covers POST /apps/{name}/wake — success path (already running), 404 path
(app missing on disk), and timeout path (streamlitctl returned non-zero).

JWT auth is bypassed via FastAPI's dependency_overrides — the canonical
pattern used elsewhere in this codebase (see secubox-haproxy/tests).
"""
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api import main as api_main
from api.main import app
from secubox_core.auth import require_jwt


@pytest.fixture
def client(tmp_path, monkeypatch):
    """TestClient with JWT bypassed and APPS_PATH/CTL pointing into tmp_path.

    A dummy CTL file is created so the route's Path(CTL).exists() check
    passes; subprocess.run is mocked separately in each test so the file
    is never actually invoked.
    """
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    fake_ctl = tmp_path / "streamlitctl"
    fake_ctl.write_text("#!/bin/sh\nexit 0\n")
    fake_ctl.chmod(0o755)

    monkeypatch.setattr(api_main, "APPS_PATH", str(apps_dir))
    monkeypatch.setattr(api_main, "CTL", str(fake_ctl))

    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    try:
        yield TestClient(app), apps_dir
    finally:
        app.dependency_overrides.clear()


def test_wake_missing_app_returns_404(client):
    """When streamlitctl reports the app as unknown (rc=2), return 404.

    Existence is delegated to streamlitctl (#959) — the route no longer
    re-checks APPS_PATH/{name} itself, so this exercises the rc=2 mapping
    instead of a pre-emptive directory check.
    """
    test_client, _apps_dir = client

    fake = MagicMock(returncode=2, stderr=b"ERROR: App not found: nope\n", stdout=b"")
    with patch("api.main.subprocess.run", return_value=fake):
        r = test_client.post("/apps/nope/wake")

    assert r.status_code == 404, r.text
    assert "not found" in r.json()["detail"].lower()


def test_wake_running_returns_200_running(client):
    """When streamlitctl reports the app was already running, return 200
    with status='running'."""
    test_client, apps_dir = client
    (apps_dir / "foo").mkdir()

    fake = MagicMock(returncode=0, stderr=b"wake: foo already running\n", stdout=b"")
    with patch("api.main.subprocess.run", return_value=fake):
        r = test_client.post("/apps/foo/wake")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "foo"
    assert body["status"] == "running"
    assert "duration_ms" in body


def test_wake_timeout_returns_504(client):
    """When streamlitctl exits non-zero (e.g. port never came up), return 504."""
    test_client, apps_dir = client
    (apps_dir / "foo").mkdir()

    fake = MagicMock(
        returncode=1,
        stderr=b"wake: foo did not come up within 30s\n",
        stdout=b"",
    )
    with patch("api.main.subprocess.run", return_value=fake):
        r = test_client.post("/apps/foo/wake")

    assert r.status_code == 504, r.text
    assert "wake failed" in r.json()["detail"]
