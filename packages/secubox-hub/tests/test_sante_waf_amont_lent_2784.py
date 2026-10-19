# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2784 — la page Santé dit « amont lent » quand le témoin du WAF expire alors que les canaris sont bloqués (et non « défaillant »)."""
from pathlib import Path

PAGE = (Path(__file__).resolve().parents[1] / "www" / "health" / "index.html").read_text(encoding="utf-8")


def test_la_page_distingue_un_amont_lent_d_un_waf_defaillant():
    assert "d.avertissement" in PAGE and "amont lent" in PAGE
    assert "t.indetermine" in PAGE and "délai dépassé (amont lent)" in PAGE


def test_le_message_defaillant_reste_pour_un_vrai_echec():
    assert "défaillant — voir le détail" in PAGE and "entree && entree.ok ?" in PAGE
