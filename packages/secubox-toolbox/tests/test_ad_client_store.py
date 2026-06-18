# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for per-visitor ad-block breakdown store (#659)."""
from pathlib import Path

from secubox_toolbox import store


def _fresh(tmp_path, mp):
    mp.setattr(store, "DB_PATH", Path(tmp_path) / "t.db")


def test_record_ad_client_blocks_accumulates(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    store.record_ad_client_blocks([
        ("mh_a", "ads.example.com", 3, 3 * 45000),
        ("mh_a", "px.tracker.io", 1, 45000),
    ])
    store.record_ad_client_blocks([("mh_a", "ads.example.com", 2, 2 * 45000)])
    c = store.ad_client_stats("mh_a", hours=24)
    assert c["mac_hash"] == "mh_a"
    assert c["total"] == 6
    hosts = {r["host"]: r for r in c["top_hosts"]}
    assert hosts["ads.example.com"]["hits"] == 5
    assert hosts["ads.example.com"]["bytes"] == 5 * 45000
    assert hosts["px.tracker.io"]["hits"] == 1


def test_record_ad_client_blocks_skips_empty_mac(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    store.record_ad_client_blocks([
        ("", "ads.example.com", 5, 5 * 45000),
        ("mh_b", "ads.example.com", 2, 2 * 45000),
    ])
    s = store.ad_stats(hours=24)
    macs = {r["mac_hash"] for r in s["top_visitors"]}
    assert "" not in macs
    assert macs == {"mh_b"}


def test_ad_stats_top_visitors_ranked(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    store.record_ad_client_blocks([
        ("mh_busy", "ads.example.com", 10, 0),
        ("mh_busy", "px.tracker.io", 5, 0),
        ("mh_quiet", "ads.example.com", 2, 0),
    ])
    s = store.ad_stats(hours=24)
    tv = s["top_visitors"]
    assert tv[0]["mac_hash"] == "mh_busy" and tv[0]["hits"] == 15
    assert tv[1]["mac_hash"] == "mh_quiet" and tv[1]["hits"] == 2


def test_ad_client_stats_window(tmp_path, monkeypatch):
    _fresh(tmp_path, monkeypatch)
    store.record_ad_client_blocks([("mh_c", "ads.example.com", 4, 0)])
    # within window
    assert store.ad_client_stats("mh_c", hours=24)["total"] == 4
    # zero-hour window (cutoff in the future) → nothing
    out = store.ad_client_stats("mh_c", hours=0)
    assert out["mac_hash"] == "mh_c"
    assert out["total"] == 0
    assert out["top_hosts"] == []
