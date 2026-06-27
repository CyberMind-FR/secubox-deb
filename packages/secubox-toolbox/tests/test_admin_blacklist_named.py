# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""admin_blacklist must sum named counter OBJECTS (ref #758)."""
import asyncio
import json
import types
from secubox_toolbox import api


def _fake_nft_json():
    return json.dumps({"nftables": [
        {"set": {"name": "blacklist_v4", "elem": ["1.2.3.4"]}},
        {"counter": {"name": "sbx_drop_blacklist_v4", "packets": 7, "bytes": 700}},
        {"counter": {"name": "sbx_drop_quarantine_v4", "packets": 3, "bytes": 300}},
        {"counter": {"name": "sbx_doh_detect_v4", "packets": 5, "bytes": 500}},
    ]})


def test_admin_blacklist_sums_named_counters(monkeypatch):
    def fake_run(cmd, **kw):
        return types.SimpleNamespace(returncode=0, stdout=_fake_nft_json(), stderr="")
    monkeypatch.setattr("subprocess.run", fake_run)
    out = asyncio.run(api.admin_blacklist())
    assert out["drops"] == 10        # blacklist 7 + quarantine 3 (NOT doh)
    assert out["doh_hits"] == 5
    assert out["v4_count"] == 1
