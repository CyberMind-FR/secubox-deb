# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Onglet « Empreintes » du webui nDPId au profil Aurora : page autonome, sans librairie externe, démo annoncée."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "composants" / "ndpid" / "www" / "ndpid" / "empreintes.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC


def test_poste_la_hauteur_au_parent():
    assert "sbxNdpidVue" in SRC and "onglet:'empreintes'" in SRC
    assert "min-height:100vh" not in SRC


def test_mode_demo_annonce():
    assert "demo" in SRC and "DONNÉES DE DÉMONSTRATION" in SRC


def test_aucune_ressource_externe():
    assert not re.search(r"<script[^>]+src=", SRC, re.I)
    assert not re.search(r"""(href|src)=["']https?://""", SRC, re.I)


def test_routes_lues():
    assert "/api/v1/ndpid/" in SRC
    for r in ("status", "fingerprints", "flows"):
        assert r in SRC


def test_ni_lorem_ni_secret():
    bas = SRC.lower()
    assert "lorem" not in bas
    for mot in ("password", "passwd", "api_key", "secret=", "bearer eyj"):
        assert mot not in bas


def test_actualisation_et_lecture_seule():
    assert "30000" in SRC and "visibilityState" in SRC
    assert "method:'POST'" not in SRC and 'method:"POST"' not in SRC


def test_l_etat_vide_distingue_moteur_actif_et_moteur_arrete():
    """Un moteur ACTIF qui ne relève aucune empreinte n'est pas « à activer » : le message dit la vraie cause (#2363)."""
    src = (W / "empreintes.html").read_text(encoding="utf-8") if "W" in globals() else None
    if src is None:
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1] / "composants/ndpid/www/ndpid/empreintes.html").read_text(encoding="utf-8")
    assert "D.run===true" in src and "sbxdpi calcule JA3 et JA4" in src   # #2405 : sbxdpi lit le ClientHello lui-même
    assert "doit être actif pour relever" not in src


def test_la_page_se_charge_sans_erreur_javascript_2418():
    """#2418 : une erreur de syntaxe (parenthèse en trop, #2405) vidait toute la page sans qu'aucun test ne le voie : on la charge dans un vrai navigateur."""
    import pathlib
    import pytest
    sync_api = pytest.importorskip("playwright.sync_api")
    page_html = pathlib.Path(__file__).resolve().parents[1] / "composants/ndpid/www/ndpid/empreintes.html"
    erreurs = []
    with sync_api.sync_playwright() as p:
        try:
            nav = p.chromium.launch()
        except Exception as e:   # navigateur absent de la machine de test
            pytest.skip(f"chromium indisponible : {e}")
        for q in ("?demo=1", ""):
            pg = nav.new_page()
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.goto("file://" + str(page_html) + q)
            pg.wait_for_timeout(500)
            if q:
                assert pg.evaluate("document.querySelectorAll('#rang .fp').length") > 0   # la démonstration affiche des empreintes
        nav.close()
    assert erreurs == [], erreurs
