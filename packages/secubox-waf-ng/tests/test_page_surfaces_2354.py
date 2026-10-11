# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2354 : l'onglet Surfaces du WAF est une page autonome, sans ressource externe, qui annonce sa démo et sa hauteur."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "composants" / "waf" / "www" / "waf" / "surfaces.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC[:400]


def test_hauteur_et_demo():
    assert "sbxWafVue" in SRC and "onglet:'surfaces'" in SRC
    assert "'demo'" in SRC and "DONNÉES DE DÉMONSTRATION" in SRC
    assert "min-height:100vh" not in SRC


def test_api_stats_seulement():
    assert "/api/v1/waf/stats" in SRC
    for cle in ("comptes_vises", "leurres_touches", "noms_non_routes", "par_type"):
        assert cle in SRC


def test_aucune_ressource_externe():
    assert not re.search(r"<script[^>]+src=", SRC, re.I)
    assert not re.search(r"(?:src|href)=[\"']https?://", SRC, re.I)


def test_ni_lorem_ni_secret():
    assert "lorem" not in SRC.lower()
    assert not re.search(r"(password|passwd|secret|token)\s*[:=]\s*[\"'][^\"']{6,}", SRC, re.I)
