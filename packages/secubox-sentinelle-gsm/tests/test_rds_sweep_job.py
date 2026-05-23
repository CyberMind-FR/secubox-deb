# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Tests for the RDS sweep job model:
  - freq_range() arithmetic accumulates without drift at 200 kHz / 50 kHz
  - RdsSweepJob terminal-state semantics
  - RdsSweepRegistry FIFO + history eviction
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from sentinelle_gsm.rds_sweep_job import (
    RdsSweepJob,
    RdsSweepRegistry,
    TERMINAL_STATES,
    freq_range,
)


def test_freq_range_default_fm_band():
    f = freq_range(87.5, 108.0, 200)
    # 87.5 → 108.0 in 0.2 MHz steps. (108.0 - 87.5) / 0.2 = 102.5 — the
    # nominal grid never lands on 108.0 exactly. Last channel is at
    # 87.5 + 102 * 0.2 = 107.9 MHz, then the next iteration would go to
    # 108.1 and exit the while loop. So 103 entries, end at 107.9.
    assert f[0] == 87.5
    assert f[-1] == 107.9
    assert len(f) == 103


def test_freq_range_50khz_step_no_drift():
    """Float accumulation must not turn 100.000 into 100.0000001 — the
    rds_runner passes the value straight to rtl_fm which tolerates a few
    Hz of drift but anything bigger picks the wrong channel."""
    f = freq_range(100.0, 100.5, 50)
    # 100.0 / 100.05 / 100.10 / ... / 100.50 = 11 entries
    assert len(f) == 11
    assert f[0] == 100.0
    assert f[-1] == 100.5
    # round() to 4 decimal places means no value can be > 0.0001 off the
    # nominal grid.
    for i, v in enumerate(f):
        nominal = round(100.0 + i * 0.05, 4)
        assert abs(v - nominal) < 1e-9


def test_sweep_job_is_active_initially():
    j = RdsSweepJob(id="x", params={})
    assert not j.is_terminal()
    assert j.is_active()


def test_sweep_job_set_state_records_finished_at():
    j = RdsSweepJob(id="x", params={})
    j.set_state("stopped")
    assert j.is_terminal()
    assert j.finished_at is not None
    assert "stopped" in TERMINAL_STATES


def test_registry_active_returns_only_active():
    reg = RdsSweepRegistry(max_history=10)
    j1 = reg.submit({"a": 1})
    assert reg.active() is j1
    j1.set_state("stopped")
    assert reg.active() is None


def test_registry_evicts_old_terminals():
    """_evict_old() keeps the N newest terminal jobs AT THE MOMENT IT
    RUNS — and it only runs at submit(). So after 4 submit+stop pairs
    with max_history=2, the LAST set_state happened after the last
    eviction, leaving 3 terminals in store (the 2 capped during the
    last submit, plus the one that just terminated). Triggering one
    more submit forces re-eviction down to the cap."""
    reg = RdsSweepRegistry(max_history=2)
    jobs = []
    for i in range(4):
        j = reg.submit({"i": i})
        j.set_state("stopped")
        jobs.append(j)
    # No re-eviction has run since the last set_state, so j3 + the 2
    # capped survivors from that submit (j2, j1) all live.
    surviving = reg.list(limit=10)
    assert {j.id for j in surviving} == {jobs[3].id, jobs[2].id, jobs[1].id}
    # A fresh submit forces _evict_old to keep only the 2 newest
    # terminals — j1 (oldest terminal at that point) is dropped.
    pivot = reg.submit({"i": "pivot"})  # still active, never stopped
    ids_after = {j.id for j in reg.list(limit=10)}
    assert pivot.id in ids_after
    assert jobs[3].id in ids_after and jobs[2].id in ids_after
    assert jobs[1].id not in ids_after
    assert jobs[0].id not in ids_after


def test_registry_keeps_active_even_under_pressure():
    """Active jobs MUST never be evicted, no matter how small max_history."""
    reg = RdsSweepRegistry(max_history=1)
    # Three terminals then one active.
    for _ in range(3):
        j = reg.submit({})
        j.set_state("stopped")
    active = reg.submit({})
    # Don't terminate.
    surviving_ids = {j.id for j in reg.list(limit=10)}
    assert active.id in surviving_ids
    assert reg.active() is active
