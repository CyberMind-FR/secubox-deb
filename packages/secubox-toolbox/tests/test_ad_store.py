# SPDX-License-Identifier: LicenseRef-CMSD-1.0
from pathlib import Path
from secubox_toolbox import store


def _fresh(tmp_path, mp): mp.setattr(store, "DB_PATH", Path(tmp_path) / "t.db")


def test_record_and_aggregate(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    store.record_ad_blocks([
        ("ads.example.com", "cnn.com", "block", 5, 5 * 1500),
        ("ads.example.com", "bbc.com", "block", 3, 3 * 1500),
        ("px.tracker.io", "cnn.com", "block", 2, 2 * 1500),
        ("cnn.com", "cnn.com", "silent", 4, 0),
    ])
    s = store.ad_stats(hours=24)
    assert s["total_blocked"] == 10            # block hits only
    assert s["by_action"]["block"] == 10 and s["by_action"]["silent"] == 4
    assert s["top_hosts"][0]["host"] == "ads.example.com" and s["top_hosts"][0]["hits"] == 8
    sites = {r["site"]: r["hits"] for r in s["top_sites"]}
    assert sites["cnn.com"] == 7               # block hits per site (5+2)


def test_record_upsert_accumulates(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    store.record_ad_blocks([("a.com", "x.com", "block", 1, 1500)])
    store.record_ad_blocks([("a.com", "x.com", "block", 2, 3000)])
    s = store.ad_stats(hours=24)
    assert s["by_action"]["block"] == 3 and s["total_bytes"] == 4500


def test_candidates_capture_and_sites(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    store.record_ad_candidates([("ad.x.io", "cnn.com", 1), ("ad.x.io", "bbc.com", 1),
                                ("ad.x.io", "cnn.com", 1)])
    rows = store.ad_candidate_sites(min_sites=2)
    assert "ad.x.io" in rows                    # seen on 2 distinct sites
    assert store.ad_candidate_sites(min_sites=3) == []
