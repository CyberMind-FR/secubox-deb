# packages/secubox-sentinelle-gsm/api/tests/test_baseline.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>

"""
Tests for CellBaseline (operator-baseline learning).

Schema setup mirrors production: ObservationsDB creates the cell_baseline
table (idempotent CREATE IF NOT EXISTS) when it opens the file, then we
hand the underlying sqlite3.Connection to CellBaseline. This exercises
the colocation invariant (one observations.db, multiple wrappers).
"""

import sqlite3
import time

import pytest

from sentinelle_gsm.baseline import BaselineCell, CellBaseline
from sentinelle_gsm.observations import ObservationsDB


@pytest.fixture
def conn(tmp_path):
    # ObservationsDB.__init__ creates the cell_baseline table.
    db = ObservationsDB(tmp_path / "obs.db")
    yield db._db


@pytest.fixture
def baseline(conn):
    return CellBaseline(conn)


def test_first_consider_starts_at_1_not_baseline_yet(baseline):
    baseline.consider("208-01-200-12345", mcc=208, mnc=1, lac=200, arfcn=124)
    cell = baseline.get("208-01-200-12345")
    assert cell is not None
    assert cell.learn_count == 1
    assert baseline.is_baseline("208-01-200-12345") is False


def test_three_considers_graduate_to_baseline(baseline):
    cid = "208-01-200-12345"
    for _ in range(3):
        baseline.consider(cid, mcc=208, mnc=1, lac=200, arfcn=124)
    cell = baseline.get(cid)
    assert cell is not None
    assert cell.learn_count == 3
    assert baseline.is_baseline(cid) is True


def test_learn_mode_graduates_first_consider(baseline):
    baseline.set_learn_mode(60)
    assert baseline.in_learn_mode() is True
    baseline.consider("208-01-300-99999", mcc=208, mnc=1, lac=300, arfcn=64)
    cell = baseline.get("208-01-300-99999")
    assert cell is not None
    assert cell.learn_count == CellBaseline.LEARN_THRESHOLD
    assert baseline.is_baseline("208-01-300-99999") is True


def test_consider_updates_metadata_via_coalesce(baseline):
    cid = "208-01-400-55555"
    # First sighting carries mcc=208.
    baseline.consider(cid, mcc=208, mnc=1, lac=400, arfcn=42)
    # Second sighting carries mcc=None — must NOT clobber the prior 208.
    baseline.consider(cid, mcc=None, mnc=None, lac=None, arfcn=42)
    cell = baseline.get(cid)
    assert cell is not None
    assert cell.mcc == 208
    assert cell.mnc == 1
    assert cell.lac == 400
    assert cell.learn_count == 2


def test_list_orders_by_last_learned_desc(baseline):
    baseline.consider("cell-A", arfcn=10)
    time.sleep(0.01)
    baseline.consider("cell-B", arfcn=20)
    time.sleep(0.01)
    baseline.consider("cell-C", arfcn=30)
    cells = baseline.list()
    assert len(cells) == 3
    assert cells[0].cell_id == "cell-C"
    assert cells[1].cell_id == "cell-B"
    assert cells[2].cell_id == "cell-A"
    # Confirm dataclass type (defensive — catches accidental tuple return).
    assert isinstance(cells[0], BaselineCell)
