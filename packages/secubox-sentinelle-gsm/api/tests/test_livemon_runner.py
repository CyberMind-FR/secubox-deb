# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from sentinelle_gsm.livemon_runner import LivemonRunner, ScanStatus


@pytest.mark.asyncio
async def test_initial_status_not_running():
    r = LivemonRunner()
    s = r.status()
    assert s.running is False
    assert s.pid is None


@pytest.mark.asyncio
async def test_start_spawns_with_rtl_args():
    r = LivemonRunner()
    fake_proc = MagicMock(spec=asyncio.subprocess.Process)
    fake_proc.pid = 12345
    fake_proc.returncode = None
    fake_proc.stderr = AsyncMock()
    fake_proc.stderr.read = AsyncMock(return_value=b"")
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake_proc)) as mck:
        s = await r.start("925.4M")
    args = mck.call_args[0]
    assert "--args=rtl=0" in args
    assert "-f" in args and "925.4M" in args
    assert s.running is True
    assert s.pid == 12345


@pytest.mark.asyncio
async def test_start_refuses_double_start():
    r = LivemonRunner()
    fake_proc = MagicMock(); fake_proc.pid = 12345; fake_proc.returncode = None
    fake_proc.stderr = AsyncMock(); fake_proc.stderr.read = AsyncMock(return_value=b"")
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake_proc)):
        await r.start("925.4M")
        with pytest.raises(RuntimeError, match="already running"):
            await r.start("947.4M")


@pytest.mark.asyncio
async def test_stop_sends_sigterm_then_clears_state():
    r = LivemonRunner()
    fake_proc = MagicMock(); fake_proc.pid = 12345; fake_proc.returncode = None
    fake_proc.stderr = AsyncMock(); fake_proc.stderr.read = AsyncMock(return_value=b"")
    fake_proc.terminate = MagicMock()
    fake_proc.wait = AsyncMock(return_value=0)
    with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=fake_proc)):
        await r.start("925.4M")
        s = await r.stop()
    fake_proc.terminate.assert_called_once()
    assert s.running is False


@pytest.mark.asyncio
async def test_stop_when_not_running_is_noop():
    r = LivemonRunner()
    s = await r.stop()
    assert s.running is False
