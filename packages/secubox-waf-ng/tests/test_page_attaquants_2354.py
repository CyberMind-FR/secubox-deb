# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2354 — l'onglet « Attaquants suivis » du WAF est une vraie page autonome (sans navigateur)."""
import pathlib
import re

PAGE = pathlib.Path(__file__).resolve().parents[1] / "composants/waf/www/waf/attaquants.html"
S = PAGE.read_text(encoding="utf-8")


def test_en_tete_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in S[:400]


def test_hauteur_auto_et_pas_de_min_height_viewport():
    assert "sbxWafVue" in S and "onglet:'attaquants'" in S
    assert "ResizeObserver" in S
    assert not re.search(r"min-height\s*:\s*100vh", S)


def test_demo_embed_et_route_reelle():
    assert "'demo'" in S and "'embed'" in S
    assert "/api/v1/waf/bans/history" in S


def test_aucune_ressource_externe():
    assert not re.search(r"<script[^>]+src=", S, re.I)
    assert not re.search(r"<link[^>]+href=\s*[\"']https?:", S, re.I)


def test_ni_lorem_ni_secret():
    bas = S.lower()
    assert "lorem" not in bas
    assert not re.search(r"(password|passwd|secret|api[_-]?key)\s*[:=]\s*[\"'][^\"']+", bas)
    assert not re.search(r"eyJ[A-Za-z0-9_-]{20,}", S)
