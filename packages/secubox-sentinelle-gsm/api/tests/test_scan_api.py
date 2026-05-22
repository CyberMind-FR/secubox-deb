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

    # Reset consume-task + fleet + job registry so /scan/start and
    # /scan/auto don't 409 from state a sibling test left set.
    api_main._consume_task = None
    api_main._fleet = None
    # Fresh JobRegistry per test — terminal-state jobs from siblings
    # would otherwise show up in /scan/auto/jobs listings.
    from sentinelle_gsm.scan_auto_job import JobRegistry as _JobRegistry
    api_main._job_registry = _JobRegistry(max_history=10)

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
        # Cancel any in-flight job task so it doesn't leak into the
        # next test's event loop (e.g. stalling scans waiting on
        # pending_evt that's about to go out of scope).
        active = api_main._job_registry.active()
        if active is not None and active.task is not None and not active.task.done():
            active.task.cancel()
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


# ── v0.3.6: /scan/auto async-job endpoint ─────────────────────────────

import asyncio as _aio
import time as _time


def _wait_for_job_state(client, job_id, target_states, timeout=2.0, poll=0.02):
    """Poll GET /scan/auto/jobs/{id} until state ∈ target_states.

    Necessary because POST /scan/auto returns immediately while the
    driver coroutine runs in the background. Returns the final job
    payload; raises AssertionError on timeout."""
    if isinstance(target_states, str):
        target_states = {target_states}
    deadline = _time.time() + timeout
    while _time.time() < deadline:
        r = client.get(f"/scan/auto/jobs/{job_id}")
        assert r.status_code == 200, r.text
        body = r.json()
        if body["state"] in target_states:
            return body
        _time.sleep(poll)
    raise AssertionError(
        f"job {job_id} did not reach {target_states} within {timeout}s "
        f"(last state: {body['state']})"
    )


def _make_slow_scan(seconds: float = 5.0):
    """Return an async scan_band stand-in that just sleeps. Avoids the
    cross-event-loop pitfall of asyncio.Event() (a fresh loop per
    TestClient request would break .set() across the boundary)."""
    async def slow_scan(**_):
        await _aio.sleep(seconds)
        return []
    return slow_scan


def test_scan_auto_returns_job_id_immediately(client, monkeypatch):
    """v0.3.6: POST returns synchronously with {id, state=pending}.
    The background task does the actual work."""
    from api import main as api_main

    monkeypatch.setattr(api_main, "scan_band", _make_slow_scan(5.0))

    r = client.post("/scan/auto", json={"band": "GSM900", "max_cells": 3})
    assert r.status_code == 200
    body = r.json()
    assert "id" in body
    assert body["state"] in ("pending", "scanning")

    # Job appears in GET by id.
    r2 = client.get(f"/scan/auto/jobs/{body['id']}")
    assert r2.status_code == 200
    assert r2.json()["id"] == body["id"]
    # Cancel rather than wait the full sleep — fixture teardown
    # cancels any lingering task anyway, but explicit is cleaner.
    client.post(f"/scan/auto/jobs/{body['id']}/cancel")


def test_scan_auto_happy_path_reaches_running(client, monkeypatch):
    """Three cells found, fleet started — job should land in `running`
    with cells_selected and runners populated."""
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
    fake_fleet.stop_all = AsyncMock(return_value=[])
    monkeypatch.setattr(api_main, "LivemonFleet", lambda **_: fake_fleet)

    r = client.post("/scan/auto", json={"band": "GSM900", "max_cells": 3})
    job_id = r.json()["id"]
    body = _wait_for_job_state(client, job_id, "running")

    assert body["cells_found"] == 3
    assert len(body["runners"]) == 3
    serverports = [run["serverport"] for run in body["runners"]]
    assert serverports == [4730, 4731, 4732]


def test_scan_auto_409s_when_single_scan_active(client):
    """Can't start a job while /scan/start's single runner is mid-flight."""
    from api import main as api_main
    api_main._consume_task = MagicMock(done=MagicMock(return_value=False))
    try:
        r = client.post("/scan/auto", json={"max_cells": 1})
        assert r.status_code == 409
    finally:
        api_main._consume_task = None


def test_scan_auto_409s_when_another_job_active(client):
    """v0.3.6: second POST while a job is in flight → 409.

    TestClient cancels tasks at request-scope exit, so we can't rely
    on the spawned driver to stay alive across requests in tests.
    Instead, seed the registry with a job in `scanning` state directly
    — same effect on the endpoint's active() check, no race.
    """
    from api import main as api_main
    job = api_main._job_registry.submit({"band": "GSM900", "max_cells": 1})
    job.set_state("scanning")
    try:
        r = client.post("/scan/auto", json={"band": "GSM900", "max_cells": 3})
        assert r.status_code == 409
    finally:
        job.set_state("cancelled")  # release the active() slot


def test_scan_auto_400_on_zero_max_cells(client):
    r = client.post("/scan/auto", json={"max_cells": 0})
    assert r.status_code == 400


def test_scan_auto_empty_scan_lands_in_stopped(client, monkeypatch):
    """Blank scan = no cells found = job state `stopped` (not failed —
    "no GSM around here" is legitimate)."""
    from api import main as api_main

    async def empty_scan(**_):
        return []

    monkeypatch.setattr(api_main, "scan_band", empty_scan)
    r = client.post("/scan/auto", json={"band": "GSM900", "max_cells": 3})
    assert r.status_code == 200
    job_id = r.json()["id"]
    body = _wait_for_job_state(client, job_id, "stopped")
    assert body["cells_found"] == 0
    assert body["runners"] == []


def test_scan_auto_scanner_timeout_lands_in_failed(client, monkeypatch):
    """grgsm_scanner that times out → job state `failed` with error.
    HTTP no longer returns 504 — the POST returns 200 quickly, the
    failure surfaces in subsequent GETs."""
    from api import main as api_main

    async def timing_out(**_):
        raise _aio.TimeoutError

    monkeypatch.setattr(api_main, "scan_band", timing_out)
    r = client.post("/scan/auto", json={"band": "GSM900", "max_cells": 3})
    assert r.status_code == 200
    job_id = r.json()["id"]
    body = _wait_for_job_state(client, job_id, "failed")
    # asyncio.TimeoutError carries no message in Python 3.10+; we just
    # need a non-None error field (whatever the str() gave us).
    assert body["error"] is not None


def test_scan_auto_jobs_list(client, monkeypatch):
    """GET /scan/auto/jobs lists newest-first up to limit."""
    from api import main as api_main

    async def empty_scan(**_):
        return []

    monkeypatch.setattr(api_main, "scan_band", empty_scan)

    ids = []
    for _ in range(3):
        r = client.post("/scan/auto", json={"band": "GSM900", "max_cells": 1})
        ids.append(r.json()["id"])
        _wait_for_job_state(client, ids[-1], "stopped")

    r = client.get("/scan/auto/jobs")
    assert r.status_code == 200
    jobs = r.json()["jobs"]
    # Newest first.
    assert [j["id"] for j in jobs[:3]] == list(reversed(ids))


def test_scan_auto_cancel_in_flight(client):
    """POST /scan/auto/jobs/{id}/cancel → calls task.cancel() and
    returns the updated payload. Cross-request task lifecycle is
    tested in test_scan_auto_job.py against the driver directly;
    here we just verify the endpoint plumbing (task.cancel + 200)."""
    from api import main as api_main
    job = api_main._job_registry.submit({"band": "GSM900", "max_cells": 1})
    job.set_state("scanning")

    cancelled = False

    class _FakeTask:
        def done(self):
            return False

        def cancel(self):
            nonlocal cancelled
            cancelled = True
            job.set_state("cancelled")

        def __await__(self):
            # async behaviour: yield nothing, complete immediately.
            if False:
                yield
            return None

    job.task = _FakeTask()
    r = client.post(f"/scan/auto/jobs/{job.id}/cancel")
    assert r.status_code == 200
    assert r.json()["state"] == "cancelled"
    assert cancelled is True


def test_scan_auto_cancel_unknown_job_404(client):
    r = client.post("/scan/auto/jobs/nope/cancel")
    assert r.status_code == 404


def test_scan_auto_get_unknown_job_404(client):
    r = client.get("/scan/auto/jobs/nope")
    assert r.status_code == 404


def test_scan_auto_status_no_fleet(client):
    r = client.get("/scan/auto/status")
    assert r.status_code == 200
    body = r.json()
    assert body["running"] is False
    assert body["runners"] == []
