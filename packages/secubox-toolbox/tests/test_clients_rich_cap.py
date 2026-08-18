# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import asyncio

from secubox_toolbox import api


def test_clients_rich_caps_enrichment(monkeypatch):
    rows = [
        {"mac_hash": f"m{i}", "ip": f"10.0.0.{i}", "state": "active",
         "level": "r1", "score": 0, "last_seen": float(i), "first_seen": 0.0}
        for i in range(20)
    ]
    monkeypatch.setattr(api.store, "list_clients", lambda: rows)
    monkeypatch.setattr(api.store, "latest_user_agent", lambda mh: "Mozilla/5.0")

    geo_calls = {"n": 0}

    def fake_lookup(ip):
        geo_calls["n"] += 1
        return {"flag": "🇫🇷", "country_iso": "FR", "asn_org": "X"}

    monkeypatch.setattr(api.geo, "lookup", fake_lookup)

    out = asyncio.run(api.admin_clients_rich())
    assert out["count"] == 20
    # Geo enrichment bounded to ENRICH_LIMIT, not all 20 clients.
    assert geo_calls["n"] == api.ENRICH_LIMIT
    # Most-recent client (last_seen highest) is enriched.
    assert out["clients"][0]["flag"] == "🇫🇷"
    # A client beyond the cap has bare geo fields.
    assert out["clients"][-1]["flag"] == ""
