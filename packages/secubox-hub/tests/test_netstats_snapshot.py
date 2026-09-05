# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Snapshot builder + collect_once with monkeypatched privileged sources (#758)."""
import importlib
import json
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
netstats = importlib.import_module("netstats")


def test_build_snapshot_network_drops_excludes_doh():
    c = sqlite3.connect(":memory:")
    netstats.init_db(c)
    counters = {
        "sbx_drop_blacklist_v4": {"packets": 4, "bytes": 0},
        "sbx_drop_wafrl": {"packets": 6, "bytes": 0},
        "sbx_doh_detect_v4": {"packets": 99, "bytes": 0},
    }
    netstats.insert_sample(c, 1000, counters, {})
    snap = netstats.build_snapshot(c, now=1000)
    assert snap["network_drops"] == 10           # 4 + 6, doh excluded
    assert snap["categories"]["doh"]["packets"] == 99
    assert snap["updated"] == 1000


def test_collect_once_writes_row_and_snapshot(tmp_path, monkeypatch):
    db = tmp_path / "netstats.db"
    snap = tmp_path / "netstats.json"
    monkeypatch.setattr(netstats, "DB_PATH", db)
    monkeypatch.setattr(netstats, "SNAP_PATH", snap)
    monkeypatch.setattr(netstats, "DATA_DIR", tmp_path)
    monkeypatch.setattr(netstats, "_read_nft_counters",
                        lambda: {"sbx_drop_wafrl": {"packets": 3, "bytes": 30}})
    monkeypatch.setattr(netstats, "_read_ifaces",
                        lambda: {"eth0": {"rx_bytes": 1, "rx_packets": 1, "tx_bytes": 1, "tx_packets": 1}})
    out = netstats.collect_once(now=1234)
    assert out["network_drops"] == 3
    assert snap.exists()
    written = json.loads(snap.read_text())
    assert written["updated"] == 1234
    # a second tick must not raise (DB reused)
    netstats.collect_once(now=1264)


def test_read_snapshot_marks_stale(tmp_path, monkeypatch):
    snap = tmp_path / "netstats.json"
    snap.write_text(json.dumps({"updated": 0, "categories": {}, "interfaces": {}, "network_drops": 0}))
    monkeypatch.setattr(netstats, "SNAP_PATH", snap)
    out = netstats.read_snapshot()
    assert out["stale"] is True
