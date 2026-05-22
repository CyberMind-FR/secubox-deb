# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Multi-cell capture: N LivemonRunners, each watching a different ARFCN,
all emitting GSMTAP to the same listener on port 4729 (default).

The gkerma/IMSI-catcher project's scan-and-livemon script demonstrates
this pattern. grgsm_livemon_headless's --serverport BINDs a control
port (not the GSMTAP destination, which is hardcoded to 4729), so each
runner needs a UNIQUE --serverport — we use base=4730, base+1=4731, …
LivemonRunner v0.3.4 already supports a serverport kwarg and defaults
it to gsmtap_port+1, so the fleet just bumps it per runner.

The L3 scoring engine (lib/sentinelle_gsm/scoring_engine.py) was always
designed to operate on multi-cell data — ghost_bts and
anomalous_neighbours heuristics return false negatives when only one
cell is in view.
"""

from __future__ import annotations

import asyncio
import dataclasses
from typing import Optional

from .livemon_runner import LivemonRunner, ScanStatus
from .scanner import CellInfo


@dataclasses.dataclass
class RunnerSummary:
    """Per-runner status enriched with the cell context that started it.

    Distinct from ScanStatus (which knows nothing about MCC/MNC/CID)
    because the API endpoint wants to echo enough to identify which
    operator/cell each runner is watching.
    """

    cell: CellInfo
    serverport: int
    status: ScanStatus


class LivemonFleet:
    def __init__(self, gsmtap_port: int = 4729, base_serverport: int = 4730):
        self.gsmtap_port = gsmtap_port
        self.base_serverport = base_serverport
        # Parallel arrays — index i ties together the runner, its
        # serverport, and the cell it was started for.
        self._runners: list[LivemonRunner] = []
        self._cells: list[CellInfo] = []
        self._serverports: list[int] = []

    def is_running(self) -> bool:
        """True if any runner is still alive. Mirrors LivemonRunner's
        `not _done` semantics — a fleet with all children dead is not
        running, even if cleanup hasn't been called."""
        return any(r.status().running for r in self._runners)

    def summaries(self) -> list[RunnerSummary]:
        return [
            RunnerSummary(cell=c, serverport=p, status=r.status())
            for r, c, p in zip(self._runners, self._cells, self._serverports)
        ]

    async def start(
        self,
        cells: list[CellInfo],
        gain: Optional[float] = None,
        ppm: Optional[float] = None,
        samp_rate: Optional[str] = None,
    ) -> list[RunnerSummary]:
        """Spawn one LivemonRunner per cell.

        Fails fast on the first runner that doesn't come up — stops
        whatever started successfully before raising, so the fleet
        never lingers in a partially-started state.
        """
        if self._runners:
            raise RuntimeError("fleet already running — stop first")
        if not cells:
            raise ValueError("no cells to watch")

        for i, cell in enumerate(cells):
            runner = LivemonRunner(gsmtap_port=self.gsmtap_port)
            serverport = self.base_serverport + i
            try:
                await runner.start(
                    cell.freq,
                    gain=gain,
                    ppm=ppm,
                    samp_rate=samp_rate,
                    serverport=serverport,
                )
            except Exception:
                # Roll back anything we did start before re-raising.
                await self._stop_all_quiet()
                raise
            self._runners.append(runner)
            self._cells.append(cell)
            self._serverports.append(serverport)
        return self.summaries()

    async def _stop_all_quiet(self) -> None:
        """Best-effort stop of every runner so an aborted start() can
        unwind cleanly. Errors swallowed — we're already on the failure
        path."""
        for r in self._runners:
            try:
                await r.stop()
            except Exception:
                pass
        self._runners.clear()
        self._cells.clear()
        self._serverports.clear()

    async def stop_all(self) -> list[RunnerSummary]:
        """Send SIGTERM to every runner, await exit, capture final
        status. Returns the pre-clear summaries so callers can show
        each runner's stderr_tail one last time."""
        # Capture the per-runner final status (with cell + serverport
        # context) BEFORE we clear the lists.
        final: list[RunnerSummary] = []
        for runner, cell, sp in zip(self._runners, self._cells, self._serverports):
            try:
                st = await runner.stop()
            except Exception as e:
                st = ScanStatus(stderr_tail=f"stop() raised: {e}")
            final.append(RunnerSummary(cell=cell, serverport=sp, status=st))
        self._runners.clear()
        self._cells.clear()
        self._serverports.clear()
        return final
