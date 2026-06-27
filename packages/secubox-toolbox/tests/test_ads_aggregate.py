# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for the #ads aggregate breakdown (ref #755)."""
import sqlite3
import time
from secubox_toolbox import store


def _seed_db(tmp_path, monkeypatch):
    db = tmp_path / "toolbox.db"
    c = sqlite3.connect(str(db))
    c.executescript(
        "CREATE TABLE ad_block_stats(ad_host TEXT, site TEXT, action TEXT, hits INTEGER, bytes INTEGER, last_seen REAL, PRIMARY KEY(ad_host,site,action));"
        "CREATE TABLE ad_block_client_host(mac_hash TEXT, ad_host TEXT, hits INTEGER, last_seen REAL, PRIMARY KEY(mac_hash,ad_host));"
        "CREATE TABLE social_edges(ts INTEGER, client_mac_hash TEXT, src_site TEXT, tracker_domain TEXT, cookie_id_hash TEXT, ja4_hash TEXT, consent_state TEXT);"
    )
    now = int(time.time())
    # two distinct cookie-trackers in window, one duplicate, one stale (>24h)
    for cid, ts in [("A", now-60), ("A", now-30), ("B", now-60), ("C", now-90000), ("", now-10)]:
        c.execute("INSERT INTO social_edges(ts,client_mac_hash,src_site,tracker_domain,cookie_id_hash,ja4_hash,consent_state) VALUES(?,?,?,?,?,?,?)",
                  (ts, "m", "s", "t", cid, "j", "none_seen"))
    c.commit(); c.close()
    monkeypatch.setattr(store, "DB_PATH", db)
    return db


def test_ad_stats_trackers_seen_distinct_in_window(tmp_path, monkeypatch):
    _seed_db(tmp_path, monkeypatch)
    out = store.ad_stats(hours=24)
    # distinct non-empty cookie ids in the last 24h = {A, B}; C is stale, "" excluded
    assert out["trackers_seen"] == 2
    assert out["pages_cleaned"] == 0  # no cosmetic_events table yet → 0 (Task 2 fills it)
