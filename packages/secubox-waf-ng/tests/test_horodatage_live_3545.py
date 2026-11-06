# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""La ligne d'alerte en direct porte une heure façon console (#3545)."""
from pathlib import Path

PAGE = Path(__file__).parents[1] / "composants/waf/www/waf/index.html"


def test_la_ligne_live_affiche_l_heure():
    src = PAGE.read_text(encoding="utf-8")
    assert "function horodatage(ts)" in src
    assert "horodatage(e.ts)" in src
