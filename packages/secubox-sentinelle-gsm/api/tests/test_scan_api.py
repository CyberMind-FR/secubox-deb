# packages/secubox-sentinelle-gsm/api/tests/test_scan_api.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>

"""API surface tests for v0.3 /scan/* + /observations endpoints.

Both LivemonRunner and GsmtapListener are mocked so the test doesn't
spawn `grgsm_livemon_headless` and doesn't bind a real UDP socket.
ObservationsDB uses a real on-disk SQLite under tmp_path so the
GET /observations route hits the real implementation end-to-end.

JWT is bypassed via FastAPI's dependency_overrides — the real JWT
layer lives at nginx + Authelia, not inside the app.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path):
    from api import main as api_main
    from sentinelle_gsm.observations import ObservationsDB

    # Real DB so GET /observations exercises the real query path.
    api_main._obs_db = ObservationsDB(tmp_path / "obs.db")

    # Mock the runner — it would otherwise try to spawn the gr-gsm
    # binary, which isn't installed in the test environment.
    api_main._livemon = MagicMock()
    api_main._livemon.start = AsyncMock(return_value=MagicMock(
        running=True, pid=42, freq="925.4M", started_at=1.0, stderr_tail=""))
    api_main._livemon.stop = AsyncMock(return_value=MagicMock(
        running=False, pid=None, freq=None, started_at=None, stderr_tail=""))
    api_main._livemon.status = MagicMock(return_value=MagicMock(
        running=False, pid=None, freq=None, started_at=None, stderr_tail=""))

    # Mock the listener — start() would otherwise create a real UDP
    # endpoint on 127.0.0.1:4729 which (a) needs the port free and
    # (b) is irrelevant to these API surface tests.
    api_main._listener = MagicMock()
    api_main._listener.start = AsyncMock(return_value=None)
    api_main._listener.stop = AsyncMock(return_value=None)

    # Reset consume-task slot so /scan/start doesn't 409 from a stale
    # task left over by a sibling test.
    api_main._consume_task = None

    api_main.app.dependency_overrides[api_main.require_jwt] = (
        lambda: {"sub": "tester"}
    )
    try:
        yield TestClient(api_main.app)
    finally:
        api_main.app.dependency_overrides.clear()
        # Cancel any consume task this test left dangling so it doesn't
        # leak into the next test's event loop.
        task = api_main._consume_task
        if task is not None and not task.done():
            task.cancel()
        api_main._consume_task = None
        api_main._livemon = None
        api_main._listener = None
        api_main._obs_db = None


def test_scan_start_calls_livemon(client):
    r = client.post("/scan/start", json={"freq": "925.4M"})
    assert r.status_code == 200
    assert r.json()["running"] is True


def test_scan_stop_calls_livemon(client):
    r = client.post("/scan/stop")
    assert r.status_code == 200
    assert r.json()["running"] is False


def test_observations_returns_empty_by_default(client):
    r = client.get("/observations")
    assert r.status_code == 200
    assert r.json()["sightings"] == []
