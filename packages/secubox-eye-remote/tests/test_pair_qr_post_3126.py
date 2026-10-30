# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3126 (relecture de sécurité de L5, R-L5-14) : `/pair/qr` CRÉE une session d'appairage — une action, donc POST.

En GET, un lien suivi, ou une portée de pilotage `lecture` (GET/HEAD seulement), ouvrait une session d'appairage."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]


def test_qr_est_un_post():
    source = (PKG / "api" / "routers" / "pairing.py").read_text(encoding="utf-8")
    assert re.findall(r'@router\.(get|post)\(\s*"/qr"', source) == ["post"]


def test_la_page_demande_le_qr_en_post():
    page = (PKG / "www" / "eye-remote" / "js" / "eye-remote.js").read_text(encoding="utf-8")
    assert re.search(r"apiRequest\('/pair/qr',\s*\{\s*method:\s*'POST'\s*\}\)", page)
