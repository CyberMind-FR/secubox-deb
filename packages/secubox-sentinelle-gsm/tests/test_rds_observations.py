# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
Tests for RdsStationRegistry — the UPSERT-by-PI registry that backs the
/rds/stations endpoint.

Covers:
  - schema bootstrap on a fresh sqlite file
  - first INSERT writes pi + first_seen + last_seen + count=1
  - subsequent UPSERT bumps count, refreshes last_seen, preserves
    first_seen
  - COALESCE behaviour: a bare-PI frame after a full frame does NOT
    null out PS/RT/PTY/TP/TA/freq
  - list_stations() returns newest-first by last_seen
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from sentinelle_gsm.rds_observations import RdsStationRegistry


def _open(tmp_path) -> RdsStationRegistry:
    return RdsStationRegistry(tmp_path / "obs.db")


def test_schema_bootstraps(tmp_path):
    reg = _open(tmp_path)
    # An empty registry returns count 0 + empty list.
    assert reg.count() == 0
    assert reg.list_stations() == []


def test_first_insert_sets_seen_and_count(tmp_path):
    reg = _open(tmp_path)
    reg.record(pi="F201", ps="FRANCE I", freq="100.6M")
    rows = reg.list_stations()
    assert len(rows) == 1
    row = rows[0]
    assert row["pi"] == "F201"
    assert row["ps"] == "FRANCE I"
    assert row["count"] == 1
    assert row["first_seen"] > 0
    assert row["last_seen"] >= row["first_seen"]


def test_second_record_bumps_count_and_refreshes_last_seen(tmp_path):
    reg = _open(tmp_path)
    reg.record(pi="F201", ps="FRANCE I")
    first_last_seen = reg.list_stations()[0]["last_seen"]
    # Force a measurable gap so last_seen advances.
    time.sleep(0.02)
    reg.record(pi="F201")
    row = reg.list_stations()[0]
    assert row["count"] == 2
    assert row["last_seen"] > first_last_seen


def test_coalesce_preserves_existing_fields(tmp_path):
    reg = _open(tmp_path)
    # First frame brings the full payload.
    reg.record(
        pi="F202", ps="EUROPE 1", rt="Le monde bouge", pty=10,
        tp=True, ta=False, freq="104.7M",
    )
    # Second frame is a bare PI ping (very common in early RDS sync).
    reg.record(pi="F202")
    row = reg.list_stations()[0]
    assert row["ps"] == "EUROPE 1"
    assert row["rt"] == "Le monde bouge"
    assert row["pty"] == 10
    assert row["tp"] == 1
    assert row["ta"] == 0
    assert row["freq"] == "104.7M"
    assert row["count"] == 2


def test_newest_first_ordering(tmp_path):
    reg = _open(tmp_path)
    reg.record(pi="AAAA")
    time.sleep(0.02)
    reg.record(pi="BBBB")
    time.sleep(0.02)
    reg.record(pi="CCCC")
    pis = [r["pi"] for r in reg.list_stations()]
    assert pis == ["CCCC", "BBBB", "AAAA"]


def test_count_increment_does_not_double_first_seen(tmp_path):
    reg = _open(tmp_path)
    reg.record(pi="F203")
    fs = reg.list_stations()[0]["first_seen"]
    time.sleep(0.02)
    reg.record(pi="F203")
    row = reg.list_stations()[0]
    # first_seen MUST stay frozen on UPSERT — only last_seen + count move.
    assert row["first_seen"] == fs
