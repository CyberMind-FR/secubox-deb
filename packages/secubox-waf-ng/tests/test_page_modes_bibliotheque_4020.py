# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#4020 — onglet Bibliothèque de /waf/modes.html : familles, identifier seulement / bannir, écriture par
/categories/modes ; vrai navigateur."""
import json
import os
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "composants" / "waf" / "www" / "waf"
PAGE = (WWW / "modes.html").read_text(encoding="utf-8")
XSS = "<img src=x onerror=window.xss=1>"

CATS = {"source": "box", "categories": {
    "sqli": {"name": "SQL Injection", "mode": "block", "motifs": 7, "structurels": 0, "enabled": True, "verrouille": False},
    "bib_fichiers_exposes": {"name": "Bibliothèque — Fichiers exposés", "mode": "detect", "motifs": 698, "structurels": 0,
                             "enabled": True, "verrouille": False},
    "bib_php": {"name": "Bibliothèque — PHP", "mode": "block", "motifs": 8, "structurels": 0, "enabled": True,
                "verrouille": False}}}
BIB = {"sources": {"owasp-crs": "v4.31.0", "nuclei-templates": "v10.5.3"}, "rejeu": {"requetes": 229996},
       "total_regles": 706, "familles": {
           "fichiers_exposes": {"categorie": "bib_fichiers_exposes", "presente": True, "mode": "detect",
                                "identifier_seulement": True, "regles": 698, "regex": 0, "chemins_exacts": 698,
                                "importees": 716, "rejetees_rejeu": 2, "touches_rejouees": 27,
                                "touches_7j": {"touches": 41, "par_jour": [3, 5, 8, 6, 7, 4, 8], "technos": {XSS: 3}}},
           "php": {"categorie": "bib_php", "presente": True, "mode": "block", "identifier_seulement": False,
                   "regles": 8, "regex": 8, "chemins_exacts": 0, "importees": 21, "rejetees_rejeu": 0,
                   "touches_rejouees": 26, "touches_7j": None},
           "sondes_techno": {"categorie": "bib_sondes_techno", "presente": False, "mode": None,
                             "identifier_seulement": True, "regles": 276, "regex": 0, "chemins_exacts": 276,
                             "importees": 1177, "rejetees_rejeu": 0, "touches_rejouees": 2, "touches_7j": None}}}

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvrir(nav, largeur):
    p = nav.new_page(viewport={"width": largeur, "height": 900})
    p.postes = []

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1]
        if u.startswith("/waf/modes.html"):
            return r.fulfill(status=200, content_type="text/html", body=PAGE)
        if r.request.method == "POST":
            p.postes.append((u, json.loads(r.request.post_data or "{}")))
            return r.fulfill(status=200, content_type="application/json", body="{}")
        corps = {"/api/v1/waf/categories": CATS, "/api/v1/waf/bibliotheque": BIB}.get(u.split("?")[0], {})
        return r.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/**", sert)
    p.goto("http://sbx.test/waf/modes.html?vue=bibliotheque")
    p.wait_for_selector("#bib .carte", state="attached")
    return p


def test_familles_et_categories_separees(nav):
    p = ouvrir(nav, 1280)
    assert p.is_visible("#panBib") and p.inner_text("#nBib") == "3"
    assert p.inner_text("#nCats") == "1"                                  # bib_* hors de l'onglet Catégories
    assert p.eval_on_selector_all("#cats .cat", "l => l.map(e => e.dataset.cat)") in ([], ["sqli"])
    cartes = p.eval_on_selector_all("#bib .carte", "l => l.map(e => e.dataset.cat)")
    assert cartes[0] == "bib_fichiers_exposes"                            # tri par touches 7 j
    assert "Identifier seulement" in p.inner_text('.carte[data-cat="bib_fichiers_exposes"]')
    assert "Bannir" in p.inner_text('.carte[data-cat="bib_php"]')
    assert "Pas encore dans les règles" in p.inner_text('.carte[data-cat="bib_sondes_techno"]')
    assert p.locator('.carte[data-cat="bib_fichiers_exposes"] .serie i').count() == 7
    assert p.evaluate("window.xss") is None                               # texte, jamais HTML
    if os.environ.get("SBX_CAPTURE"):
        p.screenshot(path=os.environ["SBX_CAPTURE"], full_page=True)
    p.close()


def test_bannir_une_famille_passe_par_categories_modes(nav):
    p = ouvrir(nav, 390)
    carte = p.locator('.carte[data-cat="bib_fichiers_exposes"]')
    carte.get_by_role("button", name="Après N").click()
    assert p.is_visible("#attente")
    p.click("#appliquer")
    p.wait_for_function("document.getElementById('succes').hidden === false")
    assert p.postes[0] == ("/api/v1/waf/categories/modes", {"changements": [
        {"categorie": "bib_fichiers_exposes", "mode": "escalate", "ban_seuil": 3, "ban_duree": "24h"}]})
    largeur = p.evaluate("document.documentElement.scrollWidth")
    assert largeur <= 390                                                  # aucun défilement horizontal
    p.close()
