# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""LivemonFleet — N parallel runners, each on its own --serverport."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinelle_gsm.livemon_fleet import LivemonFleet
from sentinelle_gsm.scanner import CellInfo


def _cell(arfcn: int, freq: str, mnc: int) -> CellInfo:
    return CellInfo(arfcn=arfcn, freq=freq, cid=arfcn, lac=1,
                    mcc=208, mnc=mnc, power=-50)


def _make_fake_proc(wait_returns=None):
    """Same helper pattern as test_livemon_runner."""
    fake = MagicMock(spec=asyncio.subprocess.Process)
    fake.pid = 90000
    fake.returncode = None
    fake.stderr = AsyncMock()
    fake.stderr.read = AsyncMock(return_value=b"")
    fake.terminate = MagicMock()
    if wait_returns is None:
        fake.wait = AsyncMock(side_effect=lambda: asyncio.Future())
    else:
        async def _wait():
            return wait_returns
        fake.wait = AsyncMock(side_effect=_wait)
    return fake


@pytest.mark.asyncio
async def test_fleet_starts_one_runner_per_cell():
    """The IMSI-catcher pattern: N livemons, each on serverport=base+i,
    each watching a different cell's freq."""
    cells = [
        _cell(73, "939.6M", 1),
        _cell(119, "947.4M", 10),
        _cell(1, "935.2M", 20),
    ]
    fleet = LivemonFleet()
    procs = [_make_fake_proc() for _ in cells]
    with patch("asyncio.create_subprocess_exec", AsyncMock(side_effect=procs)) as mck:
        summaries = await fleet.start(cells)

    assert len(summaries) == 3
    assert mck.call_count == 3

    # Each call's argv has the right freq and a unique --serverport
    seen_serverports = []
    seen_freqs = []
    for call in mck.call_args_list:
        argv = call[0]
        seen_freqs.append(argv[argv.index("-f") + 1])
        for a in argv:
            if a.startswith("--serverport="):
                seen_serverports.append(int(a.split("=")[1]))

    assert seen_freqs == ["939.6M", "947.4M", "935.2M"]
    assert seen_serverports == [4730, 4731, 4732]


@pytest.mark.asyncio
async def test_fleet_refuses_double_start():
    cells = [_cell(73, "939.6M", 1)]
    fleet = LivemonFleet()
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=_make_fake_proc())):
        await fleet.start(cells)
        with pytest.raises(RuntimeError, match="already running"):
            await fleet.start(cells)


@pytest.mark.asyncio
async def test_fleet_rejects_empty_cells():
    """An empty fleet is meaningless — fail fast so the API endpoint
    returns 400 rather than spawning nothing and pretending success."""
    fleet = LivemonFleet()
    with pytest.raises(ValueError, match="no cells"):
        await fleet.start([])


@pytest.mark.asyncio
async def test_fleet_rolls_back_on_partial_failure():
    """If the second runner fails to start, the first must be stopped
    before the exception propagates. Otherwise we leak grgsm children."""
    cells = [_cell(73, "939.6M", 1), _cell(119, "947.4M", 10)]
    fleet = LivemonFleet()

    good = _make_fake_proc()
    # Configure good.wait so stop() can resolve.
    resolve = asyncio.Event()

    async def waiting():
        await resolve.wait()
        return 0

    good.wait = AsyncMock(side_effect=waiting)

    def on_term():
        resolve.set()

    good.terminate.side_effect = on_term

    side_effect = [good, OSError("simulated osmosdr failure")]
    with patch("asyncio.create_subprocess_exec", AsyncMock(side_effect=side_effect)):
        with pytest.raises(OSError, match="simulated"):
            await fleet.start(cells)

    # The first runner's terminate must have been called during rollback.
    good.terminate.assert_called_once()
    # Fleet should be back to empty so the next start() works.
    assert fleet.is_running() is False
    assert fleet.summaries() == []


@pytest.mark.asyncio
async def test_fleet_stop_all_drains_children_and_clears_state():
    cells = [_cell(73, "939.6M", 1), _cell(119, "947.4M", 10)]
    fleet = LivemonFleet()

    procs = []
    for _ in cells:
        p = _make_fake_proc()
        ev = asyncio.Event()

        async def waiting(ev=ev):
            await ev.wait()
            return 0

        p.wait = AsyncMock(side_effect=waiting)

        def on_term(ev=ev):
            ev.set()

        p.terminate.side_effect = on_term
        procs.append(p)

    with patch("asyncio.create_subprocess_exec", AsyncMock(side_effect=procs)):
        await fleet.start(cells)
    finals = await fleet.stop_all()
    assert len(finals) == 2
    for p in procs:
        p.terminate.assert_called_once()
    assert fleet.is_running() is False
    assert fleet.summaries() == []


@pytest.mark.asyncio
async def test_fleet_custom_base_serverport():
    """Operator override — useful if 4730+ collides with something."""
    cells = [_cell(73, "939.6M", 1)]
    fleet = LivemonFleet(base_serverport=5000)
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=_make_fake_proc())) as mck:
        await fleet.start(cells)
    argv = mck.call_args[0]
    assert "--serverport=5000" in argv
