# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Page autonome de l'onglet Menaces du WAF (#2354) : contrôles statiques, sans navigateur."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent / "composants" / "waf" / "www" / "waf" / "menaces.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_entete_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC[:600]


def test_hauteur_auto_vers_le_parent():
    assert "sbxWafVue" in SRC
    assert "onglet:'menaces'" in SRC
    assert "ResizeObserver" in SRC
    assert "min-height:100vh" not in SRC


def test_mode_demo_annonce():
    assert "demo" in SRC and "q.get('demo')" in SRC
    assert "DONNÉES DE DÉMONSTRATION" in SRC


def test_aucun_script_externe():
    assert not re.search(r"<script[^>]+src\s*=", SRC, re.I)
    assert not re.search(r"https?://", re.sub(r"<!--.*?-->", "", SRC, flags=re.S))


def test_lecture_seule_aucune_action():
    assert "method:'POST'" not in SRC and 'method: "POST"' not in SRC
    assert "banIp" not in SRC and "unbanIp" not in SRC


def test_routes_waf_lues():
    for r in ("stats", "status", "alerts?limit=20&aggregate=true", "bans", "categories", "detections"):
        assert "b+'" + r + "'" in SRC


def test_pas_de_lorem_ni_secret():
    bas = SRC.lower()
    assert "lorem" not in bas
    for mot in ("password", "passwd", "secret", "api_key", "apikey", "private key", "bearer eyj"):
        assert mot not in bas
