# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2354 — l'onglet Historique du WAF est une page autonome du niveau de vue.html (sans navigateur)."""
import pathlib
import re

PAGE = pathlib.Path(__file__).resolve().parents[1] / "composants/waf/www/waf/historique.html"
S = PAGE.read_text(encoding="utf-8")


def test_en_tete_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in S[:400]


def test_hauteur_auto_vers_le_parent():
    assert "sbxWafVue" in S and "onglet:'historique'" in S
    assert "ResizeObserver" in S
    assert "min-height:100vh" not in S


def test_mode_demo_annonce_et_embed():
    assert "'demo'" in S and "DONNÉES DE DÉMONSTRATION" in S
    assert "'embed'" in S


def test_route_api_lue():
    assert "/api/v1/waf/history" in S


def test_aucun_script_externe():
    assert not re.search(r"<script[^>]+src=", S, re.I)
    assert not re.search(r"https?://(?!www\.w3\.org)", S.replace("https://cybermind.fr", ""))


def test_ni_lorem_ni_secret():
    bas = S.lower()
    assert "lorem" not in bas
    for motif in ("password", "passwd", "api_key", "secret", "bearer sk-"):
        assert motif not in bas
