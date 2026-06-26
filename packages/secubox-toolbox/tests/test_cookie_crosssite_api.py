# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for GET /admin/cookie-crosssite (ref #749)."""
import asyncio
from secubox_toolbox import api, social

_CANNED = {
    "window_hours": 24,
    "generated_at": 1782000000,
    "trackers": [{
        "tracker_domain": "criteo.com", "sites": ["a.example", "b.example2"],
        "site_count": 2, "client_count": 3, "cookie_count": 1,
        "pre_consent_hits": 2, "last_seen": 1782000000,
    }],
}


def test_cookie_crosssite_returns_detail(monkeypatch):
    monkeypatch.setattr(social, "cookie_xsite_detail",
                        lambda hours=24, top_n=50, **kw: dict(_CANNED))
    result = asyncio.run(api.admin_cookie_crosssite(hours=24, top=50))
    assert result["trackers"][0]["tracker_domain"] == "criteo.com"
    assert result["trackers"][0]["site_count"] == 2
    assert result["window_hours"] == 24


def test_cookie_crosssite_forwards_params(monkeypatch):
    captured = {}

    def fake(hours=24, top_n=50, **kw):
        captured["hours"] = hours
        captured["top_n"] = top_n
        return dict(_CANNED)

    monkeypatch.setattr(social, "cookie_xsite_detail", fake)
    asyncio.run(api.admin_cookie_crosssite(hours=12, top=10))
    assert captured == {"hours": 12, "top_n": 10}
