# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for GET /admin/ad-stats/client/{mac_hash} (#659)."""
import asyncio

from secubox_toolbox import api, store

_CANNED = {
    "mac_hash": "MH_FIXED",
    "total": 7,
    "top_hosts": [{"host": "ads.example.com", "hits": 5, "bytes": 225000},
                  {"host": "px.tracker.io", "hits": 2, "bytes": 90000}],
}


def test_ad_stats_client_returns_store_data(monkeypatch):
    monkeypatch.setattr(store, "ad_client_stats",
                        lambda mac_hash, hours=24, **kw: dict(_CANNED))
    result = asyncio.run(api.admin_ad_stats_client("MH_FIXED", hours=24))
    assert result["mac_hash"] == "MH_FIXED"
    assert result["total"] == 7
    assert result["top_hosts"][0]["host"] == "ads.example.com"


def test_ad_stats_client_clamps_hours(monkeypatch):
    captured = {}

    def fake(mac_hash, hours=24, **kw):
        captured["hours"] = hours
        captured["mac_hash"] = mac_hash
        return dict(_CANNED)

    monkeypatch.setattr(store, "ad_client_stats", fake)
    asyncio.run(api.admin_ad_stats_client("MH", hours=0))
    assert captured["hours"] == 1
    assert captured["mac_hash"] == "MH"

    asyncio.run(api.admin_ad_stats_client("MH", hours=9999))
    assert captured["hours"] == 168
