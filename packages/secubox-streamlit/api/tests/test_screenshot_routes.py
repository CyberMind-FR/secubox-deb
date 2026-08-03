"""Tests for the screenshot/recapture routes and the wake->lazy-capture
hook (#958).

Covers:
  - GET  /apps/{name}/screenshot   — public read of the conserved PNG
  - POST /apps/{name}/recapture    — manual trigger, JWT-gated
  - POST /apps/{name}/wake         — now also fires a lazy capture on success

JWT auth is bypassed via FastAPI's dependency_overrides where needed
(canonical pattern used elsewhere in this codebase, see test_idle.py) —
except for the tests that specifically verify the auth gate itself, which
must run WITHOUT the override.
"""
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api import main as api_main
from api.main import app
from secubox_core import screenshots
from secubox_core.auth import require_jwt


@pytest.fixture
def client(tmp_path, monkeypatch):
    """TestClient with JWT bypassed and SHOTS_CACHE_DIR/CTL pointing into
    tmp_path. `_spawn_shotter` is monkeypatched to a spy by default so no
    test ever launches a real subprocess."""
    shots_dir = tmp_path / "shots"
    fake_ctl = tmp_path / "streamlitctl"
    fake_ctl.write_text("#!/bin/sh\nexit 0\n")
    fake_ctl.chmod(0o755)

    monkeypatch.setattr(api_main, "SHOTS_CACHE_DIR", shots_dir)
    monkeypatch.setattr(api_main, "CTL", str(fake_ctl))

    spawned = []
    monkeypatch.setattr(api_main, "_spawn_shotter",
                         lambda name, force: spawned.append((name, force)))

    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    try:
        yield TestClient(app), shots_dir, spawned
    finally:
        app.dependency_overrides.clear()


# ─────────────────────────────────────────────────────────────────────────
# GET /apps/{name}/screenshot — public, read-only
# ─────────────────────────────────────────────────────────────────────────

def test_screenshot_404_when_none_captured_yet(client):
    test_client, _shots_dir, _spawned = client
    r = test_client.get("/apps/never-captured/screenshot")
    assert r.status_code == 404


def test_screenshot_200_serves_png_with_headers(client):
    test_client, shots_dir, _spawned = client
    screenshots.record(shots_dir, "demo", b"\x89PNG" + b"0" * 60000, "fp-1", ok=True)

    r = test_client.get("/apps/demo/screenshot")

    assert r.status_code == 200
    assert r.headers["content-type"] == "image/png"
    assert r.headers["x-captured-at"]
    assert r.content.startswith(b"\x89PNG")


def test_screenshot_failed_capture_still_serves_previous_png(client):
    test_client, shots_dir, _spawned = client
    screenshots.record(shots_dir, "demo", b"\x89PNG" + b"0" * 60000, "fp-1", ok=True)
    screenshots.record(shots_dir, "demo", None, "fp-2", ok=False)

    r = test_client.get("/apps/demo/screenshot")

    assert r.status_code == 200
    assert r.content.startswith(b"\x89PNG")


def test_screenshot_rejects_path_traversal(client):
    test_client, _shots_dir, _spawned = client
    r = test_client.get("/apps/..%2f..%2fetc%2fpasswd/screenshot")
    assert r.status_code in (404, 400)


def test_screenshot_route_requires_no_auth_at_all(tmp_path, monkeypatch):
    """The wall loads this via a plain <img src>, which never carries an
    Authorization header — this route must be reachable with none. Unlike
    the `client` fixture above, this test does NOT override require_jwt,
    to prove the route genuinely has no JWT dependency (a stray
    Depends(require_jwt) added later would 401 here)."""
    shots_dir = tmp_path / "shots"
    monkeypatch.setattr(api_main, "SHOTS_CACHE_DIR", shots_dir)
    screenshots.record(shots_dir, "demo", b"\x89PNG" + b"0" * 60000, "fp-1", ok=True)

    raw_client = TestClient(app)
    r = raw_client.get("/apps/demo/screenshot")

    assert r.status_code == 200


# ─────────────────────────────────────────────────────────────────────────
# POST /apps/{name}/recapture — manual trigger, JWT-gated
# ─────────────────────────────────────────────────────────────────────────

def test_recapture_requires_jwt():
    """Unlike the screenshot GET, this one must be gated — verified WITHOUT
    the dependency_overrides bypass used by every other test in this file."""
    raw_client = TestClient(app)
    r = raw_client.post("/apps/demo/recapture")
    assert r.status_code == 401


def test_recapture_triggers_a_detached_capture_and_returns_immediately(client):
    test_client, _shots_dir, spawned = client
    with patch.object(api_main, "_run_ctl", return_value={"ok": True, "url": "http://1.2.3.4:8501/", "source": "/x"}):
        r = test_client.post("/apps/demo/recapture")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["triggered"] is True
    assert spawned == [("demo", True)], "recapture must always force, bypassing freshness"


def test_recapture_unknown_app_returns_404(client):
    test_client, _shots_dir, spawned = client
    with patch.object(api_main, "_run_ctl", return_value={"ok": False, "error": "app not found"}):
        r = test_client.post("/apps/ghost/recapture")

    assert r.status_code == 404
    assert spawned == [], "an unresolved app must never spawn a capture"


def test_recapture_sleeping_app_returns_409_and_never_spawns(client):
    """Mirrors the shot-target invariant at the route level: a sleeping
    app must be refused here too, never silently queued."""
    test_client, _shots_dir, spawned = client
    with patch.object(api_main, "_run_ctl", return_value={"ok": False, "error": "not running"}):
        r = test_client.post("/apps/sleepy/recapture")

    assert r.status_code == 409
    assert spawned == []


# ─────────────────────────────────────────────────────────────────────────
# POST /apps/{name}/wake — lazy capture hook
# ─────────────────────────────────────────────────────────────────────────

def test_wake_success_fires_a_lazy_non_forced_capture(client):
    test_client, _shots_dir, spawned = client
    fake = MagicMock(returncode=0, stderr=b"wake: foo started\n", stdout=b"")
    with patch("api.main.subprocess.run", return_value=fake):
        r = test_client.post("/apps/foo/wake")

    assert r.status_code == 200, r.text
    assert spawned == [("foo", False)], "wake must trigger a lazy (non-forced) capture attempt"


def test_wake_already_running_still_fires_lazy_capture(client):
    """An idempotent wake of an already-running app is still a legitimate
    moment to check staleness (spec §3.1's "update" trigger can only be
    caught this way if the app never actually went to sleep)."""
    test_client, _shots_dir, spawned = client
    fake = MagicMock(returncode=0, stderr=b"wake: foo already running\n", stdout=b"")
    with patch("api.main.subprocess.run", return_value=fake):
        r = test_client.post("/apps/foo/wake")

    assert r.status_code == 200, r.text
    assert spawned == [("foo", False)]


def test_wake_not_found_never_fires_a_capture(client):
    test_client, _shots_dir, spawned = client
    fake = MagicMock(returncode=2, stderr=b"ERROR: App not found: nope\n", stdout=b"")
    with patch("api.main.subprocess.run", return_value=fake):
        r = test_client.post("/apps/nope/wake")

    assert r.status_code == 404
    assert spawned == [], "a wake that fails to resolve the app must never trigger a capture"


def test_wake_timeout_never_fires_a_capture(client):
    test_client, _shots_dir, spawned = client
    fake = MagicMock(returncode=1, stderr=b"wake: foo did not come up within 30s\n", stdout=b"")
    with patch("api.main.subprocess.run", return_value=fake):
        r = test_client.post("/apps/foo/wake")

    assert r.status_code == 504
    assert spawned == [], "a failed wake must never trigger a capture"
