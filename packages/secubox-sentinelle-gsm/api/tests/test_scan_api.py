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

    # Reset consume-task + fleet slots so /scan/start and /scan/auto
    # don't 409 from state a sibling test left set.
    api_main._consume_task = None
    api_main._fleet = None

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
        api_main._fleet = None
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


# ── v0.3.5: /scan/auto endpoint ───────────────────────────────────────

def test_scan_auto_runs_scanner_starts_fleet(client, monkeypatch):
    """Happy path: scanner returns 3 cells, /scan/auto picks them and
    starts a 3-runner fleet. Each runner's payload echoes the cell."""
    from api import main as api_main
    from sentinelle_gsm.livemon_fleet import RunnerSummary
    from sentinelle_gsm.scanner import CellInfo

    cells = [
        CellInfo(arfcn=73, freq="939.6M", cid=100, lac=200, mcc=208, mnc=1, power=-50),
        CellInfo(arfcn=119, freq="947.4M", cid=12345, lac=234, mcc=208, mnc=10, power=-45),
        CellInfo(arfcn=1, freq="935.2M", cid=50, lac=100, mcc=208, mnc=20, power=-55),
    ]

    async def fake_scan_band(**_):
        return cells

    monkeypatch.setattr(api_main, "scan_band", fake_scan_band)

    fake_fleet = MagicMock()
    fake_fleet.start = AsyncMock(return_value=[
        RunnerSummary(cell=c, serverport=4730 + i, status=MagicMock(
            running=True, pid=1000 + i, freq=c.freq, started_at=1.0, stderr_tail=""))
        for i, c in enumerate(cells)
    ])
    fake_fleet.is_running = MagicMock(return_value=True)
    monkeypatch.setattr(api_main, "LivemonFleet", lambda **_: fake_fleet)

    r = client.post("/scan/auto", json={"band": "GSM900", "max_cells": 3})
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "fleet"
    assert body["cells_found"] == 3
    assert len(body["runners"]) == 3
    serverports = [run["serverport"] for run in body["runners"]]
    assert serverports == [4730, 4731, 4732]


def test_scan_auto_409s_when_single_scan_active(client):
    """Can't start a fleet while /scan/start's single runner is mid-flight."""
    from api import main as api_main
    api_main._consume_task = MagicMock(done=MagicMock(return_value=False))
    try:
        r = client.post("/scan/auto", json={"max_cells": 1})
        assert r.status_code == 409
    finally:
        api_main._consume_task = None


def test_scan_auto_400_on_zero_max_cells(client):
    r = client.post("/scan/auto", json={"max_cells": 0})
    assert r.status_code == 400


def test_scan_auto_returns_empty_when_no_cells_found(client, monkeypatch):
    """A blank scan must not 500 — it's a legitimate "no GSM here" state."""
    from api import main as api_main

    async def empty_scan(**_):
        return []

    monkeypatch.setattr(api_main, "scan_band", empty_scan)
    r = client.post("/scan/auto", json={"band": "GSM900", "max_cells": 3})
    assert r.status_code == 200
    body = r.json()
    assert body["cells_found"] == 0
    assert body["runners"] == []


def test_scan_auto_504_on_scanner_timeout(client, monkeypatch):
    """grgsm_scanner that doesn't finish in scan_timeout → 504, not 500."""
    from api import main as api_main
    import asyncio as _aio

    async def timing_out(**_):
        raise _aio.TimeoutError

    monkeypatch.setattr(api_main, "scan_band", timing_out)
    r = client.post("/scan/auto", json={"band": "GSM900", "max_cells": 3})
    assert r.status_code == 504


def test_scan_auto_status_no_fleet(client):
    r = client.get("/scan/auto/status")
    assert r.status_code == 200
    body = r.json()
    assert body["running"] is False
    assert body["runners"] == []
