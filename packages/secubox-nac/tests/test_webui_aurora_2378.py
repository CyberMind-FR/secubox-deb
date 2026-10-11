# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Webui NAC au profil Aurora (#2378) : contrôles statiques, sans navigateur."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "www" / "nac" / "index.html"
HTML = PAGE.read_text(encoding="utf-8")


def test_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in HTML[:600]


def test_hauteur_et_demo():
    assert "sbxVue" in HTML and "onglet:'nac'" in HTML
    assert "demo" in HTML and "embed" in HTML
    assert "min-height:100vh" not in HTML and "scrollHeight" not in HTML


def test_aucun_script_externe():
    # seul le menu latéral commun est injecté par le script (hors embed et démo)
    assert not re.search(r"<script[^>]+src=", HTML)
    assert "http://" not in HTML and "https://" not in HTML.replace("https://secubox.in", "")


def test_pas_de_lorem_ni_secret():
    low = HTML.lower()
    assert "lorem" not in low
    for mot in ("password", "passwd", "secret", "private key"):
        assert mot not in low


def test_pas_de_dialogue_navigateur():
    assert not re.search(r"(?<![\w.])(confirm|alert|prompt)\(", HTML)


def test_routes_lecture():
    for r in ("/api/v1/nac", "/status", "/clients", "/quarantine", "/policy", "/history"):
        assert r in HTML


def test_routes_ecriture_identiques_a_l_ancienne_page():
    # ancienne page : POST /quarantine et /unquarantine, corps JSON {mac}, jeton sbx_token, credentials include
    assert "api('/quarantine',{method:'POST'" in HTML
    assert "api('/unquarantine',{method:'POST'" in HTML
    assert "JSON.stringify({mac:r.mac})" in HTML
    assert "'Content-Type':'application/json'" in HTML
    assert "sbx_token" in HTML and "credentials:'include'" in HTML


def test_mesure_absente_en_tiret():
    assert "'—'" in HTML


def test_menu_lateral_hors_embed():
    assert "/shared/sidebar.js" in HTML and "EMB" in HTML
