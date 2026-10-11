# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2354 : la page Campagnes du WAF est autonome, en lecture seule, sans ressource externe ni secret."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "composants" / "waf" / "www" / "waf" / "campagnes.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC


def test_hauteur_auto_et_demo():
    assert "sbxWafVue" in SRC and "onglet:'campagnes'" in SRC
    assert "'demo'" in SRC and "DONNÉES DE DÉMONSTRATION" in SRC
    assert "min-height:100vh" not in SRC


def test_aucun_script_externe():
    assert not re.search(r"<script[^>]+src=", SRC, re.I)
    assert not re.search(r"<link[^>]+href=\"https?:", SRC, re.I)


def test_lecture_seule_et_routes():
    assert "method:'POST'" not in SRC and "'POST'" not in SRC
    for r in ("campaigns", "alerts", "bans"):
        assert "b+'" + r in SRC


def test_ni_lorem_ni_secret():
    assert "lorem" not in SRC.lower()
    assert not re.search(r"(password|passwd|secret|api[_-]?key)\s*[:=]", SRC, re.I)
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", SRC)
