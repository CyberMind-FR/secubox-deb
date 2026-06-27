# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""network_drops comes from the hub netstats snapshot (ref #758)."""
import asyncio
import json
from secubox_toolbox import api


def test_network_drops_from_snapshot(tmp_path, monkeypatch):
    snap = tmp_path / "netstats.json"
    snap.write_text(json.dumps({"network_drops": 42, "updated": 9_999_999_999}))
    monkeypatch.setattr(api, "NETSTATS_SNAPSHOT", snap)
    monkeypatch.setattr(api.store, "ad_stats", lambda hours: {"total_blocked": 0})

    async def _boom():
        raise AssertionError("must not fall back to nft when snapshot present")
    monkeypatch.setattr(api, "admin_blacklist", _boom)

    out = asyncio.run(api.admin_ad_stats(hours=24))
    assert out["network_drops"] == 42


def test_network_drops_fallback_to_blacklist(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "NETSTATS_SNAPSHOT", tmp_path / "missing.json")
    monkeypatch.setattr(api.store, "ad_stats", lambda hours: {"total_blocked": 0})

    async def _bl():
        return {"drops": 7}
    monkeypatch.setattr(api, "admin_blacklist", _bl)

    out = asyncio.run(api.admin_ad_stats(hours=24))
    assert out["network_drops"] == 7
