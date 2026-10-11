# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2323 : le contenu de la page SOC ne passe pas sous la barre de navigation fixe de 220 px (vrai navigateur, barre simulée)."""
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "soc" / "index.html"
BARRE = ".sidebar{position:fixed;top:0;left:0;width:220px;height:100vh;background:#123}"


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def gauche_du_contenu(nav, largeur):
    p = nav.new_page(viewport={"width": largeur, "height": 800})
    p.route("http://s.test/api/**", lambda r: r.fulfill(status=401, content_type="application/json", body="{}"))
    p.route("http://s.test/shared/sidebar.js", lambda r: r.fulfill(status=200, content_type="application/javascript", body=f"document.head.insertAdjacentHTML('beforeend','<style>{BARRE}</style>');"))
    p.route("http://s.test/shared/**", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
    p.route("http://s.test/soc/", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.goto("http://s.test/soc/")
    p.wait_for_selector(".page")
    x = p.evaluate("document.querySelector('.page').getBoundingClientRect().left")
    p.close()
    return x


@pytest.mark.parametrize("largeur", [1000, 1280, 1500])
def test_le_contenu_commence_apres_la_barre_sur_une_fenetre_moyenne(nav, largeur):
    assert gauche_du_contenu(nav, largeur) >= 220


def test_sous_768_px_la_barre_est_masquee_et_le_contenu_prend_toute_la_largeur(nav):
    assert gauche_du_contenu(nav, 600) < 220
