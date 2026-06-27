# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Hub netstats endpoints (ref #758)."""
import asyncio
import importlib
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
main = importlib.import_module("main")
netstats = importlib.import_module("netstats")


def test_summary_reads_snapshot(tmp_path, monkeypatch):
    snap = tmp_path / "netstats.json"
    snap.write_text(json.dumps({
        "updated": 0, "categories": {"blacklist": {"packets": 4}},
        "interfaces": {}, "network_drops": 4,
    }))
    monkeypatch.setattr(netstats, "SNAP_PATH", snap)
    out = asyncio.run(main.netstats_summary())
    assert out["network_drops"] == 4
    assert out["stale"] is True


def test_series_queries_db(tmp_path, monkeypatch):
    db = tmp_path / "netstats.db"
    monkeypatch.setattr(netstats, "DB_PATH", db)
    c = sqlite3.connect(str(db))
    netstats.init_db(c)
    netstats.insert_sample(c, 0, {"sbx_drop_wafrl": {"packets": 0, "bytes": 0}}, {})
    netstats.insert_sample(c, 30, {"sbx_drop_wafrl": {"packets": 12, "bytes": 0}}, {})
    c.close()
    out = asyncio.run(main.netstats_series(window=3600, step=30))
    assert out["drops"]["waf_ratelimit"][-1][1] == 12
