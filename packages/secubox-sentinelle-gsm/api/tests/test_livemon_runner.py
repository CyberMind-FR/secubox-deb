# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from sentinelle_gsm.livemon_runner import LivemonRunner, ScanStatus


def _make_fake_proc(wait_returns: int | None = None):
    """Build a MagicMock asyncio Process. If `wait_returns` is None, wait()
    blocks forever (simulates a still-running child). Otherwise it
    resolves with the given returncode (simulates natural exit)."""
    fake = MagicMock(spec=asyncio.subprocess.Process)
    fake.pid = 12345
    fake.returncode = None
    fake.stderr = AsyncMock()
    fake.stderr.read = AsyncMock(return_value=b"")
    fake.terminate = MagicMock()
    if wait_returns is None:
        # Never resolves while the test holds it.
        fake.wait = AsyncMock(side_effect=lambda: asyncio.Future())
    else:
        async def _wait():
            return wait_returns
        fake.wait = AsyncMock(side_effect=_wait)
    return fake


@pytest.mark.asyncio
async def test_initial_status_not_running():
    r = LivemonRunner()
    s = r.status()
    assert s.running is False
    assert s.pid is None


@pytest.mark.asyncio
async def test_start_spawns_with_rtl_args():
    r = LivemonRunner()
    fake = _make_fake_proc()      # never exits
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake)) as mck:
        s = await r.start("925.4M")
    args = mck.call_args[0]
    assert "--args=rtl=0" in args
    assert "-f" in args and "925.4M" in args
    assert s.running is True
    assert s.pid == 12345


@pytest.mark.asyncio
async def test_start_refuses_double_start():
    r = LivemonRunner()
    fake = _make_fake_proc()      # never exits → "still running"
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake)):
        await r.start("925.4M")
        with pytest.raises(RuntimeError, match="already running"):
            await r.start("947.4M")


@pytest.mark.asyncio
async def test_stop_sends_sigterm_then_clears_state():
    r = LivemonRunner()
    fake = _make_fake_proc()      # never exits naturally → terminate path
    # When stop() calls terminate, proc.wait() must then resolve so the
    # caller doesn't block forever. Switch wait() to a resolving variant
    # after terminate is called.
    resolve_event = asyncio.Event()

    async def waiting():
        await resolve_event.wait()
        return 0

    fake.wait = AsyncMock(side_effect=waiting)

    def on_terminate():
        resolve_event.set()
    fake.terminate.side_effect = on_terminate

    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake)):
        await r.start("925.4M")
        s = await r.stop()
    fake.terminate.assert_called_once()
    assert s.running is False


@pytest.mark.asyncio
async def test_stop_when_not_running_is_noop():
    r = LivemonRunner()
    s = await r.stop()
    assert s.running is False


# ── v0.3.2 NEW TESTS ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_watcher_marks_done_on_natural_exit():
    """Bug v0.3.1 → v0.3.2 fix: a grgsm crash must flip status.running
    to False without anyone calling stop(). The watcher task awaits
    proc.wait() and sets _done."""
    r = LivemonRunner()
    fake = _make_fake_proc(wait_returns=42)    # natural exit code=42
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake)):
        s = await r.start("925.4M")
        # Right after start, the watcher hasn't run yet
        assert s.running is True
        # Yield to the event loop so the watcher's wait() resolves
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        # status() must now report running=False (watcher set _done)
        s2 = r.status()
    assert s2.running is False


@pytest.mark.asyncio
async def test_start_passes_gain_samp_rate_ppm():
    """v0.3.2: optional tuning params appear in the argv."""
    r = LivemonRunner()
    fake = _make_fake_proc()
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake)) as mck:
        await r.start("925.4M", gain=45, samp_rate="2.4M", ppm=10)
    args = mck.call_args[0]
    assert "-g" in args and "45" in args
    assert "-s" in args and "2.4M" in args
    assert "-p" in args and "10" in args


@pytest.mark.asyncio
async def test_start_custom_args_override():
    """v0.3.2: gr-osmosdr args can be overridden from the caller."""
    r = LivemonRunner()
    fake = _make_fake_proc()
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake)) as mck:
        await r.start("925.4M", args="numchan=1,rtl=0")
    args = mck.call_args[0]
    assert "--args=numchan=1,rtl=0" in args
    # Default rtl=0 should NOT be in argv when overridden
    assert "--args=rtl=0" not in args


@pytest.mark.asyncio
async def test_double_start_after_natural_exit_is_allowed():
    """v0.3.2 fix: once the child exits naturally, start() must accept
    a new scan without an explicit stop() first."""
    r = LivemonRunner()
    fake1 = _make_fake_proc(wait_returns=1)   # crashes immediately
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake1)):
        await r.start("925.4M")
        await asyncio.sleep(0)
        await asyncio.sleep(0)
    # First child exited via watcher. status() should report not running.
    assert r.status().running is False
    # Second start with a fresh proc — should succeed, NOT raise.
    fake2 = _make_fake_proc()
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake2)):
        s = await r.start("947.4M")
    assert s.running is True
