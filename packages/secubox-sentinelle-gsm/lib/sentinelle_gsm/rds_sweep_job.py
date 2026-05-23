# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Async-job for sweeping the FM broadcast band and cataloguing every
RDS-emitting station. Same fire-and-poll pattern as scan_auto_job.py
(v0.3.6) — the operator POSTs /rds/sweep and polls for progress.

Walk freqs from `start_mhz` to `end_mhz` in `step_khz` increments,
dwell `dwell_sec` seconds on each, capture any PI/PS heard, persist
to the rds_stations table. Per-step lifecycle is RdsRunner.start +
sleep + RdsRunner.stop, so the redsea pipeline gets fresh state at
each freq (no DSP carry-over).

Default sweep: 87.5 → 108.0 MHz in 200 kHz steps × 10s dwell. That's
103 steps × ~10s = ~17 min, similar order of magnitude to grgsm_scanner
GSM900. Operator can shorten by widening the step or trimming the
range.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
import uuid
from typing import Optional


TERMINAL_STATES = {"stopped", "failed", "cancelled"}


@dataclasses.dataclass
class FreqProbe:
    """One step's outcome — what we heard at this freq."""
    freq_mhz: float
    pi: Optional[str] = None
    ps: Optional[str] = None
    frames: int = 0


@dataclasses.dataclass
class RdsSweepJob:
    """Lifecycle of one /rds/sweep request. State machine identical
    in spirit to ScanAutoJob: pending → tuning → ... → stopped /
    failed / cancelled. The driver writes incremental progress so
    a GET /rds/sweep/jobs/{id} returns fresh data without blocking."""

    id: str
    params: dict                 # echoes the POST body
    state: str = "pending"
    started_at: float = 0.0
    finished_at: Optional[float] = None
    # Progress: step_index/step_total + freqs probed list.
    step_index: int = 0
    step_total: int = 0
    current_freq_mhz: Optional[float] = None
    probes: list[FreqProbe] = dataclasses.field(default_factory=list)
    stations_found: int = 0
    error: Optional[str] = None
    task: Optional[asyncio.Task] = None

    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def is_active(self) -> bool:
        return not self.is_terminal()

    def set_state(self, new: str) -> None:
        self.state = new
        if new in TERMINAL_STATES and self.finished_at is None:
            self.finished_at = time.time()


class RdsSweepRegistry:
    """Process-local store of sweep jobs. Same FIFO semantics as
    JobRegistry in scan_auto_job — at most one active job, last N
    terminal kept."""

    def __init__(self, max_history: int = 10):
        self._jobs: dict[str, RdsSweepJob] = {}
        self._order: list[str] = []
        self.max_history = max_history

    def active(self) -> Optional[RdsSweepJob]:
        for jid in self._order:
            j = self._jobs.get(jid)
            if j and j.is_active():
                return j
        return None

    def get(self, job_id: str) -> Optional[RdsSweepJob]:
        return self._jobs.get(job_id)

    def list(self, limit: int = 10) -> list[RdsSweepJob]:
        out = []
        for jid in self._order:
            j = self._jobs.get(jid)
            if j:
                out.append(j)
            if len(out) >= limit:
                break
        return out

    def submit(self, params: dict) -> RdsSweepJob:
        job = RdsSweepJob(
            id=str(uuid.uuid4()),
            params=params,
            started_at=time.time(),
        )
        self._jobs[job.id] = job
        self._order.insert(0, job.id)
        self._evict_old()
        return job

    def _evict_old(self) -> None:
        kept_terminal = 0
        keep: list[str] = []
        for jid in self._order:
            j = self._jobs.get(jid)
            if j is None: continue
            if j.is_active():
                keep.append(jid); continue
            if kept_terminal < self.max_history:
                keep.append(jid); kept_terminal += 1
        for jid in list(self._jobs):
            if jid not in keep:
                del self._jobs[jid]
        self._order = keep


def freq_range(start_mhz: float, end_mhz: float, step_khz: float) -> list[float]:
    """Inclusive list of freqs (in MHz) to probe.

    Plain arithmetic accumulation rather than range(int(...)) to avoid
    accumulated float drift at 50/200 kHz steps."""
    out: list[float] = []
    step_mhz = step_khz / 1000.0
    f = start_mhz
    # Tolerate rounding (1e-6 = 1 Hz)
    while f <= end_mhz + 1e-6:
        out.append(round(f, 4))
        f += step_mhz
    return out
