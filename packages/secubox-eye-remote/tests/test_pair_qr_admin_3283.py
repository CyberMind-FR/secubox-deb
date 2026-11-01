# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3283 : `/pair/qr` crée une session d'appairage. En mode tableau de bord, `require_lecture` laissait un
lecteur anonyme du LAN l'ouvrir : la route exige un administrateur réel (`require_jwt`)."""
import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
SOURCE = (PKG / "api" / "routers" / "pairing.py").read_text(encoding="utf-8")


def test_qr_exige_un_administrateur():
    m = re.search(r'@router\.post\(\s*"/qr"[^)]*dependencies=\[Depends\((\w+)\)\]', SOURCE)
    assert m and m.group(1) == "require_jwt"


def test_decouverte_reste_en_lecture():
    """/discover ne crée rien : la lecture suffit (inchangé)."""
    m = re.search(r'@router\.get\(\s*"/discover"[^)]*dependencies=\[Depends\((\w+)\)\]', SOURCE)
    assert m and m.group(1) == "require_lecture"
