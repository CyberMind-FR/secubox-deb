# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Async-job state for /scan/auto. v0.3.5 ran the scanner synchronously in
the HTTP handler — fine for unit tests, brutal on real RF where a
GSM900 sweep takes 8-15 minutes on the MOCHAbin's Cortex-A72 and
blocks the request thread (and any TestClient assertions) the whole
time.

This module owns:
  - ScanAutoJob: per-request state (params, lifecycle timestamps,
    discovered cells, fleet summaries, error message)
  - JobRegistry: process-local store of jobs with a fixed-size FIFO
    retention policy. NOT durable across service restarts — the
    operational "what's happening right now" view, not history.
    Sightings persist in observations.db as before.

The actual coroutine that drives a job lives in api/main.py (it needs
the listener/runner/fleet globals); this module just holds state.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
import uuid
from typing import Optional

from .livemon_fleet import LivemonFleet, RunnerSummary
from .scanner import CellInfo


# State machine:
#
#   pending → scanning → starting_fleet → running → stopped
#                                     ↘ failed
#                          ↘ failed
#                          ↘ cancelled
#
# Terminal states (job is done, no further transitions): stopped,
# failed, cancelled. The registry uses this to decide what to keep in
# the FIFO and whether a new POST /scan/auto can run.
TERMINAL_STATES = {"stopped", "failed", "cancelled"}


@dataclasses.dataclass
class ScanAutoJob:
    """One end-to-end /scan/auto request.

    `state` is the source of truth for "what is happening now"; the
    other fields fill in as the job progresses. Callers should NOT
    mutate ScanAutoJob from outside its driving coroutine — except
    `cancel()`, which is safe to call from any task.
    """

    id: str
    params: dict
    state: str = "pending"
    started_at: float = 0.0
    finished_at: Optional[float] = None
    cells_found: int = 0
    cells_selected: list[CellInfo] = dataclasses.field(default_factory=list)
    runners: list[RunnerSummary] = dataclasses.field(default_factory=list)
    error: Optional[str] = None
    # Set when the job enters `starting_fleet` and survives until the
    # fleet stops. None during scanning and after terminal cleanup.
    fleet: Optional[LivemonFleet] = None
    # Set when the job's driver coroutine starts; None for jobs in
    # terminal state. We hold a reference so /scan/stop and cancel()
    # can target the task.
    task: Optional[asyncio.Task] = None

    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def is_active(self) -> bool:
        """True if any /scan/auto path is in flight for this job —
        i.e. NOT in a terminal state."""
        return not self.is_terminal()

    def set_state(self, new: str) -> None:
        """Centralised state writer that records finished_at on
        transitions into terminal states."""
        self.state = new
        if new in TERMINAL_STATES and self.finished_at is None:
            self.finished_at = time.time()


class JobRegistry:
    """Process-local store of /scan/auto jobs.

    - At most one ACTIVE job (non-terminal). Enforced by
      submit_or_reject() — callers must check the result.
    - History capped at `max_history` terminal jobs (FIFO eviction).
    - Newest-first ordering for the /scan/auto/jobs listing.
    """

    def __init__(self, max_history: int = 10):
        self._jobs: dict[str, ScanAutoJob] = {}
        self._order: list[str] = []  # newest-first
        self.max_history = max_history

    def active(self) -> Optional[ScanAutoJob]:
        """The single in-flight job, or None if nothing's running."""
        for jid in self._order:
            j = self._jobs.get(jid)
            if j and j.is_active():
                return j
        return None

    def get(self, job_id: str) -> Optional[ScanAutoJob]:
        return self._jobs.get(job_id)

    def list(self, limit: int = 10) -> list[ScanAutoJob]:
        out: list[ScanAutoJob] = []
        for jid in self._order:
            j = self._jobs.get(jid)
            if j:
                out.append(j)
            if len(out) >= limit:
                break
        return out

    def submit(self, params: dict) -> ScanAutoJob:
        """Create a new job in `pending` state and insert it at the
        head of the list. The caller is responsible for refusing to
        submit when another job is active — this method does NOT
        check, so unit tests can construct multi-job scenarios.
        """
        job = ScanAutoJob(
            id=str(uuid.uuid4()),
            params=params,
            started_at=time.time(),
        )
        self._jobs[job.id] = job
        self._order.insert(0, job.id)
        self._evict_old()
        return job

    def _evict_old(self) -> None:
        """Keep only the most recent active job + max_history
        terminal jobs. Anything older is dropped."""
        kept_terminal = 0
        keep: list[str] = []
        for jid in self._order:
            j = self._jobs.get(jid)
            if j is None:
                continue
            if j.is_active():
                keep.append(jid)
                continue
            if kept_terminal < self.max_history:
                keep.append(jid)
                kept_terminal += 1
        # Drop everything not in `keep`.
        for jid in list(self._jobs):
            if jid not in keep:
                del self._jobs[jid]
        self._order = keep
