# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SQLite store + reset-aware series for network-stats (ref #758)."""
import importlib
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
netstats = importlib.import_module("netstats")


def _conn():
    c = sqlite3.connect(":memory:")
    netstats.init_db(c)
    return c


def test_insert_and_query_drops_delta():
    c = _conn()
    # t=0 blacklist=100 ; t=30 blacklist=160 → delta 60 in the bucket at t=30
    netstats.insert_sample(c, 0, {"sbx_drop_blacklist_v4": {"packets": 100, "bytes": 0}}, {})
    netstats.insert_sample(c, 30, {"sbx_drop_blacklist_v4": {"packets": 160, "bytes": 0}}, {})
    out = netstats.query_series(c, window_s=3600, step_s=30)
    pts = out["drops"]["blacklist"]
    assert pts[-1][1] == 60


def test_query_drops_reset_aware():
    c = _conn()
    netstats.insert_sample(c, 0, {"sbx_drop_blacklist_v4": {"packets": 100, "bytes": 0}}, {})
    netstats.insert_sample(c, 30, {"sbx_drop_blacklist_v4": {"packets": 5, "bytes": 0}}, {})  # reload
    out = netstats.query_series(c, window_s=3600, step_s=30)
    assert out["drops"]["blacklist"][-1][1] == 5  # not negative


def test_query_throughput_bps():
    c = _conn()
    # 30s apart, +30000 rx bytes → 30000*8/30 = 8000 bps
    netstats.insert_sample(c, 0, {}, {"eth0": {"rx_bytes": 0, "rx_packets": 0, "tx_bytes": 0, "tx_packets": 0}})
    netstats.insert_sample(c, 30, {}, {"eth0": {"rx_bytes": 30000, "rx_packets": 0, "tx_bytes": 0, "tx_packets": 0}})
    out = netstats.query_series(c, window_s=3600, step_s=30)
    assert out["in_bps"]["eth0"][-1][1] == 8000


def test_prune_drops_old_rows():
    c = _conn()
    netstats.insert_sample(c, 0, {"sbx_drop_wafrl": {"packets": 1, "bytes": 0}}, {})
    netstats.insert_sample(c, 1_000_000, {"sbx_drop_wafrl": {"packets": 2, "bytes": 0}}, {})
    netstats.prune(c, keep_s=10)  # relative to max ts
    rows = c.execute("SELECT COUNT(*) FROM counter_samples").fetchone()[0]
    assert rows == 1
