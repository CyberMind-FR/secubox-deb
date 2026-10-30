# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 (relecture de sécurité de L5, R-L5-14) : `sync_zones` réapplique les zones NAC — une action, donc POST.

En GET, un lien suivi, ou une portée de pilotage `lecture` (GET/HEAD seulement), la déclenchait."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]


def test_sync_zones_est_un_post():
    source = (PKG / "api" / "main.py").read_text(encoding="utf-8")
    assert re.findall(r'@router\.(get|post)\("/sync_zones"\)', source) == ["post"]


def test_les_pages_appellent_sync_zones_en_post():
    for f in ("client-guardian/api.js", "view/client-guardian/zones.js"):
        page = (PKG / "www" / "luci-static" / "resources" / f).read_text(encoding="utf-8")
        assert re.findall(r"sbxFetch\('/api/v1/nac/sync_zones',\s*[^,]+,\s*'([A-Z]+)'\)", page) == ["POST"], f
