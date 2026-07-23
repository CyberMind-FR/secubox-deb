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


def test_candidates_fall_back_to_cumulative_when_window_empty(tmp_path, monkeypatch):
    """A stalled learning feed must stay VISIBLE, not look like 'nothing detected'.

    ad_candidates is a backlog awaiting promotion, not a time series: when the
    window holds nothing, ad_stats falls back to the cumulative backlog and flags
    it so the panel can label it instead of implying recent detection.
    """
    _fresh(tmp_path, monkeypatch)
    store.record_ad_candidates([("stale.tracker.io", "cnn.com", 4)])
    # Age the row well past the window (10 days), leaving the backlog non-empty.
    import sqlite3
    with sqlite3.connect(store.DB_PATH) as c:
        c.execute("UPDATE ad_candidates SET last_seen = last_seen - ?", (10 * 86400,))

    s = store.ad_stats(hours=24)
    assert s["candidates_cumulative"] is True
    assert s["total_candidates"] == 1
    assert s["top_candidates"][0]["host"] == "stale.tracker.io"


def test_candidates_in_window_are_not_flagged_cumulative(tmp_path, monkeypatch):
    """Fresh detections keep the windowed semantics (no cumulative label)."""
    _fresh(tmp_path, monkeypatch)
    store.record_ad_candidates([("fresh.tracker.io", "cnn.com", 2)])
    s = store.ad_stats(hours=24)
    assert not s.get("candidates_cumulative")
    assert s["top_candidates"][0]["host"] == "fresh.tracker.io"
