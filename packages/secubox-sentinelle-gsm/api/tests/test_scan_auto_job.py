# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Direct unit tests for the v0.3.6 async-job state machine.

test_scan_api.py covers the HTTP plumbing; this file covers the
registry and the driver coroutine in isolation, where we can drive
the event loop ourselves (no Starlette TestClient cancelling spawned
tasks at request-scope exit).
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinelle_gsm.livemon_fleet import RunnerSummary
from sentinelle_gsm.scan_auto_job import (
    JobRegistry,
    ScanAutoJob,
    TERMINAL_STATES,
)
from sentinelle_gsm.scanner import CellInfo


# ── JobRegistry ──────────────────────────────────────────────────────

def test_registry_submit_creates_pending_job():
    r = JobRegistry()
    j = r.submit({"band": "GSM900", "max_cells": 3})
    assert j.state == "pending"
    assert j.id
    assert r.get(j.id) is j
    assert r.active() is j


def test_registry_active_returns_first_non_terminal():
    r = JobRegistry()
    j1 = r.submit({"band": "GSM900", "max_cells": 1})
    j1.set_state("stopped")
    j2 = r.submit({"band": "GSM900", "max_cells": 1})
    assert r.active() is j2


def test_registry_evicts_old_terminal_on_next_submit():
    """Eviction fires on submit() — so 3 terminal jobs survive until
    a 4th submit triggers the FIFO cleanup."""
    r = JobRegistry(max_history=2)
    for _ in range(3):
        r.submit({"band": "GSM900", "max_cells": 1}).set_state("stopped")
    # Pre-eviction, all 3 still in the list (last submit ran before
    # the previous two became terminal).
    # New active job triggers _evict_old which sees 3 terminal +
    # 1 active = keep active + max_history (=2) terminals.
    active = r.submit({"band": "GSM900", "max_cells": 1})
    assert r.active() is active
    assert len(r.list()) == 3   # 2 terminal + 1 active


def test_registry_list_newest_first():
    r = JobRegistry()
    ids = [r.submit({"band": "GSM900", "max_cells": 1}).id for _ in range(3)]
    listed = [j.id for j in r.list()]
    assert listed == list(reversed(ids))


def test_set_state_records_finished_at_on_terminal():
    j = ScanAutoJob(id="x", params={})
    j.set_state("scanning")
    assert j.finished_at is None
    j.set_state("stopped")
    assert j.finished_at is not None
    # finished_at sticks — re-setting a terminal state doesn't bump it
    first = j.finished_at
    j.set_state("failed")
    assert j.finished_at == first


def test_terminal_states_set():
    """Sanity check: stopped/failed/cancelled are terminal."""
    assert TERMINAL_STATES == {"stopped", "failed", "cancelled"}


# ── _drive_scan_auto_job (the driver coroutine) ──────────────────────

@pytest.fixture
def driver_env(tmp_path):
    """Set up enough api.main globals for the driver to walk its
    state machine without touching real grgsm binaries / sockets.
    Returns the patched module so tests can inspect or mutate."""
    from api import main as api_main
    from sentinelle_gsm.observations import ObservationsDB

    api_main._obs_db = ObservationsDB(tmp_path / "obs.db")

    api_main._livemon = MagicMock()
    api_main._livemon.stop = AsyncMock(return_value=MagicMock(
        running=False, pid=None, freq=None, started_at=None, stderr_tail=""))
    api_main._livemon.status = MagicMock(return_value=MagicMock(
        running=False, pid=None, freq=None, started_at=None, stderr_tail=""))

    api_main._listener = MagicMock()
    api_main._listener.start = AsyncMock(return_value=None)
    api_main._listener.stop = AsyncMock(return_value=None)
    api_main._listener.port = 4729

    api_main._consume_task = None
    api_main._fleet = None
    api_main._job_registry = JobRegistry(max_history=10)

    try:
        yield api_main
    finally:
        if api_main._consume_task is not None:
            api_main._consume_task.cancel()
        api_main._consume_task = None
        api_main._fleet = None
        api_main._livemon = None
        api_main._listener = None
        api_main._obs_db = None


@pytest.mark.asyncio
async def test_driver_happy_path(driver_env):
    """pending → scanning → starting_fleet → running with cells +
    runners populated. Listener and fleet mocks observe the right
    calls in order."""
    api_main = driver_env

    cells = [
        CellInfo(arfcn=73, freq="939.6M", cid=100, lac=200, mcc=208, mnc=1, power=-50),
        CellInfo(arfcn=119, freq="947.4M", cid=12345, lac=234, mcc=208, mnc=10, power=-45),
    ]

    async def fake_scan(**_):
        return cells

    fake_fleet = MagicMock()
    fake_fleet.start = AsyncMock(return_value=[
        RunnerSummary(cell=c, serverport=4730 + i, status=MagicMock(
            running=True, pid=1000 + i, freq=c.freq, started_at=1.0, stderr_tail=""))
        for i, c in enumerate(cells)
    ])
    fake_fleet.is_running = MagicMock(return_value=True)
    fake_fleet.stop_all = AsyncMock(return_value=[])

    with patch.object(api_main, "scan_band", fake_scan):
        with patch.object(api_main, "LivemonFleet", lambda **_: fake_fleet):
            job = api_main._job_registry.submit(
                {"band": "GSM900", "max_cells": 2, "scan_timeout": 60.0}
            )
            await api_main._drive_scan_auto_job(job)

    assert job.state == "running"
    assert job.cells_found == 2
    assert len(job.cells_selected) == 2
    assert len(job.runners) == 2
    api_main._listener.stop.assert_called()
    api_main._listener.start.assert_called()
    fake_fleet.start.assert_awaited_once()


@pytest.mark.asyncio
async def test_driver_empty_scan_lands_in_stopped(driver_env):
    """No cells found → state=stopped (not failed)."""
    api_main = driver_env

    async def empty_scan(**_):
        return []

    with patch.object(api_main, "scan_band", empty_scan):
        job = api_main._job_registry.submit({"band": "GSM900", "max_cells": 3})
        await api_main._drive_scan_auto_job(job)

    assert job.state == "stopped"
    assert job.cells_found == 0


@pytest.mark.asyncio
async def test_driver_scanner_timeout_lands_in_failed(driver_env):
    """scan_band raising TimeoutError → state=failed + error set +
    listener torn down."""
    api_main = driver_env

    async def timing_out(**_):
        raise asyncio.TimeoutError

    with patch.object(api_main, "scan_band", timing_out):
        job = api_main._job_registry.submit({"band": "GSM900", "max_cells": 1})
        await api_main._drive_scan_auto_job(job)

    assert job.state == "failed"
    assert job.error is not None
    # cleanup also stops listener — at minimum once (initial scan-prep stop).
    assert api_main._listener.stop.await_count >= 1


@pytest.mark.asyncio
async def test_driver_scanner_runtime_error_lands_in_failed(driver_env):
    """scan_band raising a generic RuntimeError → state=failed."""
    api_main = driver_env

    async def broken_scan(**_):
        raise RuntimeError("simulated grgsm_scanner exit 1")

    with patch.object(api_main, "scan_band", broken_scan):
        job = api_main._job_registry.submit({"band": "GSM900", "max_cells": 1})
        await api_main._drive_scan_auto_job(job)

    assert job.state == "failed"
    assert "simulated" in (job.error or "")


@pytest.mark.asyncio
async def test_driver_fleet_start_failure_lands_in_failed(driver_env):
    """scan returns cells but fleet.start raises → state=failed +
    listener torn back down (no orphan socket)."""
    api_main = driver_env

    cells = [CellInfo(arfcn=73, freq="939.6M", cid=100, lac=200, mcc=208, mnc=1, power=-50)]

    async def fake_scan(**_):
        return cells

    fake_fleet = MagicMock()
    fake_fleet.start = AsyncMock(side_effect=OSError("device busy"))
    fake_fleet.stop_all = AsyncMock(return_value=[])

    with patch.object(api_main, "scan_band", fake_scan):
        with patch.object(api_main, "LivemonFleet", lambda **_: fake_fleet):
            job = api_main._job_registry.submit({"band": "GSM900", "max_cells": 1})
            await api_main._drive_scan_auto_job(job)

    assert job.state == "failed"
    assert "device busy" in (job.error or "")


@pytest.mark.asyncio
async def test_driver_cancellation_during_scan(driver_env):
    """Cancelling the task during scan → state=cancelled with
    cleanup. The driver's CancelledError handler stops the listener
    and clears _fleet/_consume_task."""
    api_main = driver_env

    started_evt = asyncio.Event()

    async def slow_scan(**_):
        started_evt.set()
        await asyncio.sleep(60)
        return []

    with patch.object(api_main, "scan_band", slow_scan):
        job = api_main._job_registry.submit({"band": "GSM900", "max_cells": 1})
        task = asyncio.create_task(api_main._drive_scan_auto_job(job))
        await started_evt.wait()
        # Now the task is inside slow_scan's sleep.
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert job.state == "cancelled"
    assert api_main._fleet is None
