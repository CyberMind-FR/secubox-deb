# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3980 — /waf/modes.html refaite : trois onglets pleine largeur, catégories par famille, barre d'attente ; vrai navigateur."""
import json
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "composants" / "waf" / "www" / "waf"
PAGE = (WWW / "modes.html").read_text(encoding="utf-8")
INDEX = (WWW / "index.html").read_text(encoding="utf-8")
XSS = "<img src=x onerror=window.xss=1>"

CATS = {"source": "box", "categories": {
    "sqli": {"name": "SQL Injection", "mode": "block", "motifs": 7, "structurels": 0, "enabled": True, "verrouille": False},
    "scanners": {"name": "Vulnerability Scanners", "mode": "escalate", "ban_seuil": 3, "ban_duree": "24h", "motifs": 11,
                 "structurels": 0, "enabled": True, "verrouille": False},
    "xss": {"name": XSS, "mode": "block", "motifs": 9, "structurels": 0, "enabled": True, "verrouille": False},
    "nextcloud": {"name": "Nextcloud", "mode": "detect", "motifs": 0, "structurels": 5, "enabled": True, "verrouille": False},
    "voip": {"name": "VoIP/SIP Security", "mode": "detect", "motifs": 6, "structurels": 0, "enabled": True, "verrouille": False},
    "product_absent_probes": {"name": "Product-absent probes", "mode": "escalate", "motifs": 4, "structurels": 0,
                              "enabled": True, "verrouille": True}}}
STATS = {"categories": {
    "scanners": {"touches": 1867, "faux_positifs_estimes": 0, "par_jour": [240, 310, 198, 280, 301, 260, 278]},
    "sqli": {"touches": 57, "faux_positifs_estimes": 3, "par_jour": [6, 9, 4, 12, 8, 10, 8]},
    "nextcloud": {"touches": 14, "faux_positifs_estimes": 0}}}
LEURRES = {"leurres": [{"service": "rdp", "port": 3389, "mode": "bannir"}, {"service": XSS, "port": 1, "mode": "observer"},
                       {"service": "imap", "port": 143, "mode": "observer"},
                       {"service": "smtp", "port": 25, "mode": "observer", "fixe": True}]}
SITES = {"detectes": [], "forcer": [], "exclure": [], "autres": 3, "servis": [], "routes_lisibles": True,
         "derniere_detection": None, "motifs_livres": []}

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvrir(nav, largeur, suffixe=""):
    p = nav.new_page(viewport={"width": largeur, "height": 900})
    p.postes = []

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1]
        if u.startswith("/waf/modes.html"):
            return r.fulfill(status=200, content_type="text/html", body=PAGE)
        if r.request.method == "POST":
            p.postes.append((u, json.loads(r.request.post_data or "{}")))
            return r.fulfill(status=200, content_type="application/json", body="{}")
        corps = {"/api/v1/waf/categories": CATS, "/api/v1/waf/categories/stats7j": STATS,
                 "/api/v1/waf/leurres-service/modes": LEURRES, "/api/v1/waf/php-sites": SITES}.get(u.split("?")[0], {})
        return r.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/**", sert)
    p.goto("http://sbx.test/waf/modes.html" + suffixe)
    p.wait_for_selector("#cats .cat", state="attached")
    return p


def test_onglets_et_compteurs(nav):
    p = ouvrir(nav, 1280)
    assert p.is_visible("#panCats") and not p.is_visible("#panLeurres") and not p.is_visible("#panSites")
    assert p.inner_text("#nCats") == "6" and p.inner_text("#nLeurres") == "4" and p.inner_text("#nSites") == "0"
    p.click("#o-leurres")
    assert p.is_visible("#panLeurres") and not p.is_visible("#panCats")
    assert p.get_attribute("#o-leurres", "aria-selected") == "true"
    assert p.evaluate("location.hash") == "#leurres"           # hors cadre : le fragment suit l'onglet
    p.click("#o-php")
    assert p.is_visible("#panSites")
    p.close()
    p = ouvrir(nav, 1280, "?vue=leurres")
    assert p.is_visible("#panLeurres")
    p.close()


def test_filtre_regroupement_et_tri(nav):
    p = ouvrir(nav, 1280)
    lignes = p.eval_on_selector_all("#cats .cat", "l => l.map(e => e.dataset.cat)")
    assert lignes == ["scanners", "sqli", "nextcloud"]          # avec touches seulement, par défaut ; tri par touches
    familles = p.eval_on_selector_all("#cats .famille", "l => l.map(e => e.dataset.famille)")
    assert familles == ["robots", "web", "php"]
    assert "2 catégories sans touche" in p.inner_text("#masquees")
    assert p.locator('.cat[data-cat="scanners"] .serie i').count() == 7
    assert p.locator('.cat[data-cat="nextcloud"] .serie').count() == 0    # pas de série : le nombre seul
    assert "3 local" in p.inner_text('.cat[data-cat="sqli"]')
    # les catégories fixées sont repliées à part
    assert not p.locator("#fixees").evaluate("d => d.open") and p.locator('#catsFixees .cat[data-cat="product_absent_probes"]').count() == 1
    p.uncheck("#avecTouches")
    lignes = p.eval_on_selector_all("#cats .cat", "l => l.map(e => e.dataset.cat)")
    assert set(lignes) == {"scanners", "sqli", "nextcloud", "xss", "voip"} and p.is_hidden("#masquees")
    p.fill("#cherche", "voip")
    assert p.eval_on_selector_all("#cats .cat", "l => l.map(e => e.dataset.cat)") == ["voip"]
    p.close()


def test_barre_d_attente(nav):
    p = ouvrir(nav, 1280)
    assert p.is_hidden("#attente")
    p.locator('.cat[data-cat="sqli"] .pas button', has_text="Après N").click()
    assert p.is_visible("#attente") and "1 changement en attente" in p.inner_text("#attente")
    assert p.evaluate("getComputedStyle(document.getElementById('attente')).position") == "sticky"
    p.locator('.cat[data-cat="sqli"] select').nth(0).select_option("5")
    p.click("#appliquer")
    p.wait_for_timeout(200)
    assert p.postes[0] == ("/api/v1/waf/categories/modes",
                           {"changements": [{"categorie": "sqli", "mode": "escalate", "ban_seuil": 5, "ban_duree": "24h"}]})
    p.close()
    p = ouvrir(nav, 1280)
    p.locator('.cat[data-cat="sqli"] .pas button', has_text="Détection").click()
    p.click("#annuler")
    assert p.is_hidden("#attente") and p.postes == []
    p.close()


def test_leurres_cartes_et_messagerie(nav):
    p = ouvrir(nav, 1280, "?vue=leurres")
    assert p.locator("#leurres .carte").count() == 2 and p.locator("#leurresMail .carte").count() == 2
    assert p.locator('#leurresMail .carte[data-service="smtp"] button').first.is_disabled()
    p.locator('#leurres .carte[data-service="rdp"] button', has_text="Observer").click()
    p.wait_for_timeout(200)
    assert p.postes[-1][0] == "/api/v1/waf/leurres-service/modes"
    assert p.postes[-1][1]["modes"]["rdp"] == "observer"
    p.close()


@pytest.mark.parametrize("largeur", [1280, 400])
def test_aucune_injection_ni_debordement(nav, largeur):
    p = ouvrir(nav, largeur)
    p.uncheck("#avecTouches")
    for v in ("categories", "leurres", "php"):
        p.click("#o-" + v)
        assert p.evaluate("document.documentElement.scrollWidth") <= largeur, v
    assert p.evaluate("window.xss") is None and p.locator("#cadre img").count() == 0
    assert XSS in p.inner_text("#panLeurres")
    p.click("#o-categories")
    # cibles >= 40 px, texte >= .85rem (13,6 px pour 16 px)
    hauteurs = p.eval_on_selector_all("#cadre button:not([hidden]), #cadre select", "l => l.filter(e => e.offsetParent).map(e => e.getBoundingClientRect().height)")
    assert hauteurs and min(hauteurs) >= 39.5
    tailles = p.eval_on_selector_all("#panCats .cat *", "l => l.map(e => parseFloat(getComputedStyle(e).fontSize))")
    assert min(tailles) >= 13.5
    p.close()


def test_demo_coherente_et_inerte(nav):
    p = ouvrir(nav, 1280, "?demo=1")
    assert p.is_visible("#demo") and "Vulnerability Scanners" in p.inner_text("#cats")
    p.locator('.cat[data-cat="sqli"] .pas button', has_text="Détection").click()
    p.click("#appliquer")
    assert p.postes == [] and "Démonstration" in p.inner_text("#succes")
    p.close()


def test_source_textcontent_et_fragment_index():
    assert "innerHTML" not in PAGE and "insertAdjacentHTML" not in PAGE and "outerHTML" not in PAGE
    assert "<details" in PAGE and "En savoir plus" in PAGE
    assert "modes:(categories|leurres|php)" in INDEX and "sbxWafModes" in INDEX and "&vue=" in INDEX
