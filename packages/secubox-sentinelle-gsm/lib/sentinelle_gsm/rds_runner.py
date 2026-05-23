# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Manages the lifecycle of an rtl_fm | redsea pipeline for FM RDS decoding.

Mirror of LivemonRunner (lib/sentinelle_gsm/livemon_runner.py) but for
the FM band (87.5-108 MHz) instead of GSM900. Both runners claim the
same RTL-SDR — the api/main.py device-claim layer refuses concurrent
starts.

Pipeline:
    rtl_fm -f <freq> -M fm -l 0 -A std -p <ppm> -s 171k -g <gain> -F 9 -E deemp -
        | redsea -e -r 171000

redsea emits one JSON line per decoded RDS frame. Fields we care about:
    pi    — 4-hex Program Identification code (station unique id in country)
    ps    — 8-char Program Service (station name as displayed on radios)
    rt    — RadioText (up to 64 chars, song title/news/etc.)
    tp    — Traffic Program flag
    ta    — Traffic Announcement flag
    pty   — Program Type code (0-31, e.g. 10=Pop Music)
    af    — Alternative Frequencies list (in kHz)

171 kHz sample rate (not 250 or 240) because the RDS subcarrier is at
57 kHz; rtl_fm + redsea at this rate gives clean SDR-to-decoded-bits.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import time
from typing import Optional


REDSEA_BIN = os.environ.get(
    "SECUBOX_REDSEA_BIN",
    "/usr/libexec/secubox/secubox-redsea",
)
RTL_FM_BIN = os.environ.get("SECUBOX_RTL_FM_BIN", "/usr/bin/rtl_fm")


@dataclasses.dataclass
class RdsStatus:
    running: bool = False
    pid: Optional[int] = None
    freq: Optional[str] = None
    started_at: Optional[float] = None
    last_pi: Optional[str] = None
    last_ps: Optional[str] = None
    frames: int = 0
    stderr_tail: str = ""


@dataclasses.dataclass
class RdsFrame:
    """One redsea JSON line, normalised."""
    pi: Optional[str] = None
    ps: Optional[str] = None
    rt: Optional[str] = None
    tp: Optional[bool] = None
    ta: Optional[bool] = None
    pty: Optional[int] = None
    af: list[int] = dataclasses.field(default_factory=list)


class RdsRunner:
    """Spawns rtl_fm | redsea and consumes redsea's JSON stdout.

    Same lifecycle pattern as LivemonRunner: start() spawns + returns
    immediately, status() polls, stop() SIGTERMs both procs. A watcher
    task awaits the redsea process and flips _done — without it,
    callers polling status() get stale `running=True` if redsea
    silently exited (no signal coverage, rtl_fm crash, …).

    Frame consumption: callers can either subscribe via the on_frame
    callback (called from the asyncio loop) or just poll the latest_*
    fields. The runner doesn't persist anything itself — the api layer
    writes to observations.db on every frame.
    """

    def __init__(
        self,
        on_frame=None,   # Optional[Callable[[RdsFrame, str_freq], Awaitable]]
    ):
        self._rtl_proc: Optional[asyncio.subprocess.Process] = None
        self._redsea_proc: Optional[asyncio.subprocess.Process] = None
        self._freq: Optional[str] = None
        self._started_at: Optional[float] = None
        self._stderr_buf = bytearray()
        self._reader_task: Optional[asyncio.Task] = None
        self._watcher_task: Optional[asyncio.Task] = None
        self._stderr_task: Optional[asyncio.Task] = None
        self._done: bool = False
        # Latest observed values + counters — surfaced via status().
        self._last_pi: Optional[str] = None
        self._last_ps: Optional[str] = None
        self._frame_count: int = 0
        self._on_frame = on_frame

    def status(self) -> RdsStatus:
        # Mirrors LivemonRunner.status(): `running` only stays True
        # until the watcher observes a natural exit. Without this,
        # a redsea crash would leave returncode=None forever.
        running = (
            self._rtl_proc is not None
            and self._redsea_proc is not None
            and not self._done
        )
        return RdsStatus(
            running=running,
            pid=self._redsea_proc.pid if (running and self._redsea_proc) else None,
            freq=self._freq if running else None,
            started_at=self._started_at if running else None,
            last_pi=self._last_pi,
            last_ps=self._last_ps,
            frames=self._frame_count,
            stderr_tail=self._stderr_buf.decode(errors="replace")[-2000:],
        )

    async def start(
        self,
        freq: str,
        gain: Optional[float] = None,
        ppm: Optional[float] = None,
    ) -> RdsStatus:
        """Spawn rtl_fm and redsea, plumbed by pipe.

        freq: FM frequency, anything rtl_fm accepts (e.g. "100.6M",
            "100600000"). Caller validates the 87.5-108 MHz range.
        gain: RTL-SDR tuner gain in dB. None = rtl_fm default (49 max).
        ppm: clock correction. None = 0.
        """
        if self._rtl_proc is not None and not self._done:
            raise RuntimeError("RDS scan already running — stop first")

        # rtl_fm narrowband-FM at 171 kHz sample rate, deemphasis on,
        # automatic gain mode. The `-F 9` selects the best FIR filter
        # quality at this sample rate (recommended by redsea docs).
        rtl_argv = [
            RTL_FM_BIN,
            "-f", freq,
            "-M", "fm",
            "-l", "0",
            "-A", "std",
            "-s", "171k",
            "-F", "9",
            "-E", "deemp",
        ]
        if gain is not None:
            rtl_argv += ["-g", str(gain)]
        if ppm is not None:
            rtl_argv += ["-p", str(int(ppm))]
        rtl_argv += ["-"]   # stdout = pipe

        # redsea: -r N input sample rate (must match rtl_fm `-s`). With
        # no -o flag, output defaults to one JSON object per RDS frame
        # on stdout. DO NOT pass -e — that's --feed-through, which
        # echoes the raw PCM input to stdout and pushes the decoded
        # groups to stderr instead. We were silently parsing PCM bytes
        # as JSON for a while and getting 0 frames forever.
        redsea_argv = [
            REDSEA_BIN,
            "-r", "171000",
        ]

        # Spawn rtl_fm → pipe stdout to redsea's stdin. Both procs'
        # stderr feeds the same buffer (truncated to 16 KiB) so the
        # operator sees the actual failure mode without spelunking.
        #
        # asyncio.subprocess.PIPE on stdout gives back a StreamReader,
        # which uvloop can't reuse as stdin for the next exec (it tries
        # `.fileno()` on it and fails). The canonical pattern is a raw
        # os.pipe() handed to BOTH children — kernel does the rest, the
        # parent never reads or writes through it.
        rtl_read, rtl_write = os.pipe()
        try:
            self._rtl_proc = await asyncio.create_subprocess_exec(
                *rtl_argv,
                stdout=rtl_write,
                stderr=asyncio.subprocess.PIPE,
            )
        finally:
            os.close(rtl_write)
        try:
            self._redsea_proc = await asyncio.create_subprocess_exec(
                *redsea_argv,
                stdin=rtl_read,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except BaseException:
            # rtl_fm already spawned and claimed the RTL-SDR. If redsea
            # fails to launch (binary missing, OOM, …), SIGTERM rtl_fm
            # before re-raising so we don't leak the USB device until
            # systemd hits its stop-timeout (gk2 saw 91s once, journal
            # 2026-05-23 17:06–17:08).
            try:
                self._rtl_proc.terminate()
                await asyncio.wait_for(self._rtl_proc.wait(), timeout=2.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                try: self._rtl_proc.kill()
                except ProcessLookupError: pass
            self._rtl_proc = None
            raise
        finally:
            os.close(rtl_read)

        self._freq = freq
        self._started_at = time.time()
        self._stderr_buf = bytearray()
        self._frame_count = 0
        self._last_pi = None
        self._last_ps = None
        self._done = False

        self._reader_task  = asyncio.create_task(self._read_frames())
        self._stderr_task  = asyncio.create_task(self._drain_stderr())
        self._watcher_task = asyncio.create_task(self._watch_exit())
        return self.status()

    async def _read_frames(self) -> None:
        """Pull JSON lines from redsea stdout, surface to caller."""
        assert self._redsea_proc is not None and self._redsea_proc.stdout is not None
        try:
            while True:
                line = await self._redsea_proc.stdout.readline()
                if not line:
                    break
                try:
                    obj = json.loads(line.decode(errors="replace"))
                except (ValueError, UnicodeDecodeError):
                    continue
                frame = RdsFrame(
                    pi=obj.get("pi"),
                    ps=obj.get("ps"),
                    rt=obj.get("rt"),
                    tp=obj.get("tp"),
                    ta=obj.get("ta"),
                    pty=obj.get("pty"),
                    af=list(obj.get("af", [])),
                )
                self._frame_count += 1
                if frame.pi: self._last_pi = frame.pi
                if frame.ps: self._last_ps = frame.ps
                if self._on_frame is not None:
                    try:
                        await self._on_frame(frame, self._freq or "")
                    except Exception:                       # noqa: BLE001
                        # The runner mustn't die because the consumer
                        # raised. Caller is responsible for surfacing
                        # its own errors via logging.
                        pass
        except asyncio.CancelledError:
            pass

    async def _drain_stderr(self) -> None:
        """Concatenate rtl_fm + redsea stderr into a single 16 KiB
        ring buffer for status()."""
        async def pump(reader):
            try:
                while True:
                    chunk = await reader.read(4096)
                    if not chunk:
                        break
                    self._stderr_buf.extend(chunk)
                    if len(self._stderr_buf) > 16384:
                        del self._stderr_buf[:-16384]
            except asyncio.CancelledError:
                pass
        tasks = []
        if self._rtl_proc and self._rtl_proc.stderr:
            tasks.append(asyncio.create_task(pump(self._rtl_proc.stderr)))
        if self._redsea_proc and self._redsea_proc.stderr:
            tasks.append(asyncio.create_task(pump(self._redsea_proc.stderr)))
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for t in tasks: t.cancel()
            raise

    async def _watch_exit(self) -> None:
        """Set self._done when EITHER child exits naturally. Mirrors
        LivemonRunner._watch_exit but watches both."""
        if self._rtl_proc is None or self._redsea_proc is None:
            return
        try:
            _, pending = await asyncio.wait(
                [
                    asyncio.create_task(self._rtl_proc.wait()),
                    asyncio.create_task(self._redsea_proc.wait()),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for p in pending: p.cancel()
        except asyncio.CancelledError:
            pass
        finally:
            self._done = True

    async def stop(self, timeout: float = 5.0) -> RdsStatus:
        """SIGTERM both children; SIGKILL after `timeout`. Same
        idempotency as LivemonRunner.stop()."""
        # Capture final stats BEFORE clearing state.
        final = RdsStatus(
            running=False, pid=None, freq=None, started_at=None,
            last_pi=self._last_pi, last_ps=self._last_ps,
            frames=self._frame_count,
            stderr_tail=self._stderr_buf.decode(errors="replace")[-2000:],
        )
        for proc in (self._redsea_proc, self._rtl_proc):
            if proc is None: continue
            if proc.returncode is None:
                try:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=timeout)
                    except asyncio.TimeoutError:
                        proc.kill()
                        await proc.wait()
                except ProcessLookupError:
                    pass
        for task in (self._reader_task, self._stderr_task, self._watcher_task):
            if task and not task.done(): task.cancel()
        self._rtl_proc = None
        self._redsea_proc = None
        self._freq = None
        self._started_at = None
        self._done = False
        return final
