# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_metrics_collect.py
Local snapshot collection for fleet metrics (T3) — injected-reader unit tests.
"""
import json
import re

import pytest

from annuaire import metrics_collect
from annuaire.model import MetricSnapshot

NODE_DID = "did:plc:" + "b" * 32


def _fake_cache(**overrides):
    base = {"cpu_pct": 10.0, "mem_pct": 20.0, "disk_pct": 30.0, "load1": 0.5, "uptime_s": 1000}
    base.update(overrides)
    return lambda: base


def _fake_units(up=3, down=None):
    return lambda: (up, list(down or []))


def _fake_counters(**overrides):
    base = {"bans": 1, "assist_sessions": 2, "soc_alerts": 0}
    base.update(overrides)
    return lambda: base


def _raiser():
    raise RuntimeError("boom")


# ---------------------------------------------------------------------------
# Fixed shape / validation
# ---------------------------------------------------------------------------

def test_collect_snapshot_basic_shape_validates():
    rec = metrics_collect.collect_snapshot(
        NODE_DID, "gk2",
        cache_reader=_fake_cache(),
        unit_lister=_fake_units(up=5, down=["secubox-x"]),
        counter_reader=_fake_counters(),
    )
    # No sig/signer fields — those come from fleet.sign_snapshot
    assert "sig" not in rec and "signer_did" not in rec and "signer_pub" not in rec
    m = MetricSnapshot(**rec)
    assert m.node_did == NODE_DID
    assert m.issued_by == NODE_DID
    assert m.hostname == "gk2"
    assert m.modules_up == 5
    assert m.modules_down == ["secubox-x"]
    assert m.counters == {"bans": 1, "assist_sessions": 2, "soc_alerts": 0}


def test_ts_is_rfc3339_z():
    rec = metrics_collect.collect_snapshot(
        NODE_DID, "gk2",
        cache_reader=_fake_cache(), unit_lister=_fake_units(), counter_reader=_fake_counters(),
    )
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", rec["ts"])


def test_issued_by_equals_node_did():
    rec = metrics_collect.collect_snapshot(
        NODE_DID, "gk2",
        cache_reader=_fake_cache(), unit_lister=_fake_units(), counter_reader=_fake_counters(),
    )
    assert rec["issued_by"] == rec["node_did"] == NODE_DID


# ---------------------------------------------------------------------------
# Clamp regression (T1 review fix): cpu/mem/disk clamped to [0, 100]; load1 NOT clamped
# ---------------------------------------------------------------------------

def test_clamp_cpu_pct_over_100():
    rec = metrics_collect.collect_snapshot(
        NODE_DID, "gk2",
        cache_reader=_fake_cache(cpu_pct=150.0), unit_lister=_fake_units(), counter_reader=_fake_counters(),
    )
    assert rec["cpu_pct"] == 100.0
    MetricSnapshot(**rec)  # must validate


def test_clamp_mem_pct_negative():
    rec = metrics_collect.collect_snapshot(
        NODE_DID, "gk2",
        cache_reader=_fake_cache(mem_pct=-5.0), unit_lister=_fake_units(), counter_reader=_fake_counters(),
    )
    assert rec["mem_pct"] == 0.0
    MetricSnapshot(**rec)


def test_clamp_disk_pct_over_100():
    rec = metrics_collect.collect_snapshot(
        NODE_DID, "gk2",
        cache_reader=_fake_cache(disk_pct=250.0), unit_lister=_fake_units(), counter_reader=_fake_counters(),
    )
    assert rec["disk_pct"] == 100.0


def test_load1_not_clamped():
    rec = metrics_collect.collect_snapshot(
        NODE_DID, "gk2",
        cache_reader=_fake_cache(load1=12.5), unit_lister=_fake_units(), counter_reader=_fake_counters(),
    )
    assert rec["load1"] == 12.5
    MetricSnapshot(**rec)


# ---------------------------------------------------------------------------
# Graceful degradation — collect_snapshot NEVER raises
# ---------------------------------------------------------------------------

def test_cache_reader_raises_degrades_to_zeros():
    rec = metrics_collect.collect_snapshot(
        NODE_DID, "gk2",
        cache_reader=_raiser, unit_lister=_fake_units(), counter_reader=_fake_counters(),
    )
    assert rec["cpu_pct"] == 0.0
    assert rec["mem_pct"] == 0.0
    assert rec["disk_pct"] == 0.0
    assert rec["load1"] == 0.0
    assert rec["uptime_s"] == 0
    MetricSnapshot(**rec)


def test_unit_lister_raises_degrades():
    rec = metrics_collect.collect_snapshot(
        NODE_DID, "gk2",
        cache_reader=_fake_cache(), unit_lister=_raiser, counter_reader=_fake_counters(),
    )
    assert rec["modules_up"] == 0
    assert rec["modules_down"] == []
    MetricSnapshot(**rec)


def test_counter_reader_raises_degrades():
    rec = metrics_collect.collect_snapshot(
        NODE_DID, "gk2",
        cache_reader=_fake_cache(), unit_lister=_fake_units(), counter_reader=_raiser,
    )
    assert rec["counters"] == {"bans": 0, "assist_sessions": 0, "soc_alerts": 0}
    MetricSnapshot(**rec)


def test_all_readers_raise_never_raises():
    rec = metrics_collect.collect_snapshot(
        NODE_DID, "gk2", cache_reader=_raiser, unit_lister=_raiser, counter_reader=_raiser,
    )
    MetricSnapshot(**rec)


# ---------------------------------------------------------------------------
# modules_down capping
# ---------------------------------------------------------------------------

def test_modules_down_capped_at_20():
    down = [f"secubox-x{i}.service" for i in range(30)]
    rec = metrics_collect.collect_snapshot(
        NODE_DID, "gk2",
        cache_reader=_fake_cache(), unit_lister=_fake_units(up=1, down=down), counter_reader=_fake_counters(),
    )
    assert len(rec["modules_down"]) == 20
    MetricSnapshot(**rec)


# ---------------------------------------------------------------------------
# Default readers — prod path
# ---------------------------------------------------------------------------

def test_default_cache_reader_maps_overview_shape(tmp_path, monkeypatch):
    cache_path = tmp_path / "metrics-cache.json"
    cache_path.write_text(json.dumps({
        "overview": {
            "uptime": 12345,
            "load": "0.42 0.30 0.10",
            "cpu_pct": 33.3,
            "mem_pct": 44.4,
        },
        "waf": {},
        "connections": {},
    }))
    monkeypatch.setenv("METRICS_CACHE_PATH", str(cache_path))
    out = metrics_collect._default_cache_reader()
    assert out["cpu_pct"] == 33.3
    assert out["mem_pct"] == 44.4
    assert out["uptime_s"] == 12345
    assert out["load1"] == 0.42
    assert out["disk_pct"] == 0.0  # not present in metrics-cache.json today


def test_default_cache_reader_missing_file_returns_zeros(tmp_path, monkeypatch):
    monkeypatch.setenv("METRICS_CACHE_PATH", str(tmp_path / "nope.json"))
    out = metrics_collect._default_cache_reader()
    assert out == {"cpu_pct": 0.0, "mem_pct": 0.0, "disk_pct": 0.0, "load1": 0.0, "uptime_s": 0}


def test_default_unit_lister_counts_active_and_down(monkeypatch):
    fake_stdout = (
        "secubox-hub.service loaded active running SecuBox Hub\n"
        "secubox-dpi.service loaded failed failed SecuBox DPI\n"
        "secubox-qos.service loaded active running SecuBox QoS\n"
    )

    class _FakeProc:
        stdout = fake_stdout
        returncode = 0

    def _fake_run(*args, **kwargs):
        assert kwargs.get("shell", False) is False
        return _FakeProc()

    monkeypatch.setattr(metrics_collect.subprocess, "run", _fake_run)
    up, down = metrics_collect._default_unit_lister()
    assert up == 2
    assert down == ["secubox-dpi.service"]


def test_default_unit_lister_caps_down_at_20(monkeypatch):
    lines = "\n".join(
        f"secubox-x{i}.service loaded failed failed X{i}" for i in range(30)
    )

    class _FakeProc:
        stdout = lines
        returncode = 0

    monkeypatch.setattr(metrics_collect.subprocess, "run", lambda *a, **k: _FakeProc())
    up, down = metrics_collect._default_unit_lister()
    assert up == 0
    assert len(down) == 20


def test_default_unit_lister_subprocess_raises_degrades(monkeypatch):
    def _boom(*a, **k):
        raise OSError("systemctl missing")

    monkeypatch.setattr(metrics_collect.subprocess, "run", _boom)
    up, down = metrics_collect._default_unit_lister()
    assert up == 0
    assert down == []


def test_default_counter_reader_missing_db_returns_zeros(tmp_path, monkeypatch):
    monkeypatch.setenv("ANNUAIRE_DB_PATH", str(tmp_path / "does-not-exist" / "journal.db"))
    out = metrics_collect._default_counter_reader()
    assert out == {"bans": 0, "assist_sessions": 0, "soc_alerts": 0}


# ---------------------------------------------------------------------------
# T4 contract fix: hostname optional, defaults to socket.gethostname()
# ---------------------------------------------------------------------------

def test_collect_snapshot_hostname_defaults_to_gethostname(monkeypatch):
    """Single-arg call (no hostname) sources hostname from socket.gethostname()."""
    monkeypatch.setattr("socket.gethostname", lambda: "test-box")
    rec = metrics_collect.collect_snapshot(
        NODE_DID,
        cache_reader=_fake_cache(),
        unit_lister=_fake_units(),
        counter_reader=_fake_counters(),
    )
    assert rec["hostname"] == "test-box"
    MetricSnapshot(**rec)


def test_collect_snapshot_hostname_explicit_overrides_gethostname(monkeypatch):
    """Explicit hostname arg takes precedence over socket.gethostname()."""
    monkeypatch.setattr("socket.gethostname", lambda: "auto-box")
    rec = metrics_collect.collect_snapshot(
        NODE_DID,
        "explicit-box",
        cache_reader=_fake_cache(),
        unit_lister=_fake_units(),
        counter_reader=_fake_counters(),
    )
    assert rec["hostname"] == "explicit-box"


def test_collect_snapshot_hostname_gethostname_fails_degrades(monkeypatch):
    """If socket.gethostname() raises, hostname defaults to 'unknown'."""
    def _boom():
        raise OSError("gethostname failed")

    monkeypatch.setattr("socket.gethostname", _boom)
    rec = metrics_collect.collect_snapshot(
        NODE_DID,
        cache_reader=_fake_cache(),
        unit_lister=_fake_units(),
        counter_reader=_fake_counters(),
    )
    assert rec["hostname"] == "unknown"
    MetricSnapshot(**rec)
