# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for GET /admin/ad-stats (Task 4 ref #656)."""
import asyncio
from secubox_toolbox import api, store

_CANNED = {
    "window_hours": 24,
    "total_blocked": 42,
    "total_bytes": 63000,
    "by_action": {"block": 42, "silent": 5},
    "top_hosts": [{"host": "ads.example.com", "hits": 42, "bytes": 63000}],
    "top_sites": [{"site": "cnn.com", "hits": 42}],
}


def test_ad_stats_returns_store_data(monkeypatch):
    monkeypatch.setattr(store, "ad_stats", lambda hours=24, **kw: dict(_CANNED))
    result = asyncio.run(api.admin_ad_stats(hours=24))
    assert result["total_blocked"] == 42
    assert result["by_action"]["block"] == 42
    assert result["top_hosts"][0]["host"] == "ads.example.com"


def test_ad_stats_clamps_hours(monkeypatch):
    captured = {}

    def fake_stats(hours=24, **kw):
        captured["hours"] = hours
        return dict(_CANNED)

    monkeypatch.setattr(store, "ad_stats", fake_stats)
    asyncio.run(api.admin_ad_stats(hours=0))
    assert captured["hours"] == 1   # clamped to min=1

    asyncio.run(api.admin_ad_stats(hours=9999))
    assert captured["hours"] == 168  # clamped to max=168
