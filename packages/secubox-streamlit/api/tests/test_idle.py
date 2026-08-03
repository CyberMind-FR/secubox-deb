"""Tests for the idle-timeout wake endpoint (#331, budget/blocking fix #958).

Covers POST /apps/{name}/wake — success path (already running), 404 path
(app missing), and the "not running yet" path, which no longer blocks the
request on the actual wake (see api/tests/test_wake_background.py for the
background-task/non-blocking/lock coverage in depth).

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
    passes. `_get_apps` (the fast liveness check) and `_do_wake_in_background`
    (the actual, potentially-slow wake) are mocked separately in each test —
    never a single shared `subprocess.run` stub standing in for both, since
    that would no longer distinguish the two calls this route now makes.
    """
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    fake_ctl = tmp_path / "streamlitctl"
    fake_ctl.write_text("#!/bin/sh\nexit 0\n")
    fake_ctl.chmod(0o755)

    monkeypatch.setattr(api_main, "APPS_PATH", str(apps_dir))
    monkeypatch.setattr(api_main, "CTL", str(fake_ctl))
    # Never let a real background wake run in a test that doesn't care about
    # it — a stray real subprocess would hang on the fake sudo/ctl above.
    monkeypatch.setattr(api_main, "_do_wake_in_background", lambda name: None)
    # Wake claims are process-global state (ref #958's dedup lock) — a
    # leftover claim from one test must never leak into the next.
    api_main._WAKE_IN_PROGRESS.clear()

    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    try:
        yield TestClient(app), apps_dir
    finally:
        app.dependency_overrides.clear()
        api_main._WAKE_IN_PROGRESS.clear()


def test_wake_missing_app_returns_404(client):
    """An app absent from `app list`'s output is unknown to this route —
    `app list` and `app wake` share the same entrypoint/process resolution
    since #958 (_app_entrypoint/_scan_running_apps), so this can no longer
    diverge from streamlitctl's own notion of "exists" the way the
    pre-#959 directory-only check did."""
    test_client, _apps_dir = client

    with patch.object(api_main, "_get_apps", return_value=[]):
        r = test_client.post("/apps/nope/wake")

    assert r.status_code == 404, r.text
    assert "not found" in r.json()["detail"].lower()


def test_wake_running_returns_200_running(client):
    """An already-running app is reported instantly — no background task
    is needed (and none was even given a chance to fire, since
    `_do_wake_in_background` is stubbed above)."""
    test_client, _apps_dir = client

    with patch.object(api_main, "_get_apps", return_value=[{"name": "foo", "running": True}]):
        r = test_client.post("/apps/foo/wake")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "foo"
    assert body["status"] == "running"
    assert "duration_ms" in body


def test_wake_not_running_returns_waking_without_blocking(client):
    """A sleeping app never makes this request wait on the wake itself
    (up to 300s on a loaded board, ref #958) — it answers "waking" as soon
    as the background task is scheduled. `_do_wake_in_background` is
    stubbed to a no-op in the fixture, so a 200 here with rc bounded to
    the test's own timeout proves the route isn't awaiting it inline."""
    test_client, _apps_dir = client

    with patch.object(api_main, "_get_apps", return_value=[{"name": "foo", "running": False}]):
        r = test_client.post("/apps/foo/wake")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "foo"
    assert body["status"] == "waking"
    assert "duration_ms" in body
