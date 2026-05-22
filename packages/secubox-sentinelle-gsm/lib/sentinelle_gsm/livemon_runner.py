# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Manages the lifecycle of a single grgsm_livemon_headless subprocess.

Key design point (closes #344): the parent service NEVER opens the
RTL-SDR directly. Only the child grgsm_livemon_headless process claims
the device; when stopped, it releases. This lets ad-hoc tools
(rtl_test, rtl_adsb, kalibrate) coexist with the service when no scan
is active.
"""

from __future__ import annotations

import asyncio
import dataclasses
import shutil
import time
from typing import Optional


@dataclasses.dataclass
class ScanStatus:
    running: bool = False
    pid: Optional[int] = None
    freq: Optional[str] = None
    started_at: Optional[float] = None
    stderr_tail: str = ""


class LivemonRunner:
    def __init__(self, gsmtap_port: int = 4729):
        self.gsmtap_port = gsmtap_port
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._freq: Optional[str] = None
        self._started_at: Optional[float] = None
        self._stderr_buf = bytearray()
        self._stderr_task: Optional[asyncio.Task] = None
        self._bin = shutil.which("grgsm_livemon_headless") or "/usr/bin/grgsm_livemon_headless"

    def status(self) -> ScanStatus:
        running = self._proc is not None and self._proc.returncode is None
        return ScanStatus(
            running=running,
            pid=self._proc.pid if running else None,
            freq=self._freq if running else None,
            started_at=self._started_at if running else None,
            stderr_tail=self._stderr_buf.decode(errors="replace")[-2000:],
        )

    async def start(self, freq: str) -> ScanStatus:
        """Spawn grgsm_livemon_headless on the given frequency.

        freq: anything grgsm_livemon_headless accepts, e.g. '925.4M', '947.4e6'.
        """
        if self._proc is not None and self._proc.returncode is None:
            raise RuntimeError("scan already running — stop first")

        # gr-osmosdr default device is UHD; force RTL-SDR via --args=rtl=0
        self._proc = await asyncio.create_subprocess_exec(
            self._bin,
            "--args=rtl=0",
            "-f", freq,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        self._freq = freq
        self._started_at = time.time()
        self._stderr_buf = bytearray()
        self._stderr_task = asyncio.create_task(self._drain_stderr())
        return self.status()

    async def stop(self, timeout: float = 5.0) -> ScanStatus:
        """SIGTERM the child; SIGKILL if it doesn't exit within timeout."""
        if self._proc is None or self._proc.returncode is not None:
            return self.status()
        self._proc.terminate()
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            self._proc.kill()
            await self._proc.wait()
        if self._stderr_task:
            self._stderr_task.cancel()
        self._proc = None
        self._freq = None
        self._started_at = None
        return self.status()

    async def _drain_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        try:
            while True:
                chunk = await self._proc.stderr.read(4096)
                if not chunk:
                    break
                self._stderr_buf.extend(chunk)
                # Cap to last 16 KiB to bound memory.
                if len(self._stderr_buf) > 16384:
                    del self._stderr_buf[:-16384]
        except asyncio.CancelledError:
            pass
