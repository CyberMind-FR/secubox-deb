# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3974 — /waf/modes.html, section « Sites PHP » : détectés, exceptions, compte des autres ; vrai navigateur."""
import json
import os
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "composants" / "waf" / "www" / "waf"
PAGE = (WWW / "modes.html").read_text(encoding="utf-8")
XSS = "<img src=x onerror=window.xss=1>"
CAPTURES = os.environ.get("SBX_CAPTURES")


def test_plus_de_liste_brute_ni_tout_ou_rien():
    assert "innerHTML" not in PAGE and "/php-sites" in PAGE and "/php-sites/detecter" in PAGE
    assert "hotesTous" not in PAGE and "Tout couvrir</button>" not in PAGE and "conteneur_php" not in PAGE


playwright = pytest.importorskip("playwright.sync_api")

SITES = {"detectes": [
    {"hote": "nc.ex.fr", "type": "appli", "preuve": "appli nextcloud (module installé)", "premiere": "2026-11-20T08:00:00Z",
     "derniere": "2026-11-26T09:00:00Z", "exclu": False, "couvert": "service"},
    {"hote": "boutique.ex.fr", "type": "fichier", "preuve": XSS, "premiere": "2026-11-26T09:00:00Z",
     "derniere": "2026-11-26T09:00:00Z", "exclu": False, "couvert": "site"},
    {"hote": "wiki.ex.fr", "type": "entete", "preuve": "X-Powered-By: PHP/8.2", "premiere": None, "derniere": None,
     "exclu": True, "couvert": None}],
    "forcer": [{"hote": "ancien.ex.fr", "le": "2026-11-26T08:00:00Z", "par": "migration", "servi": False, "couvert": "site"}],
    "exclure": [{"hote": "wiki.ex.fr", "le": None, "par": XSS, "servi": True, "couvert": None}],
    "autres": 212, "servis": ["nc.ex.fr", "boutique.ex.fr", "wiki.ex.fr", "blog.ex.fr"], "routes_lisibles": True,
    "derniere_detection": "2026-11-26T09:00:00Z", "migre": True, "tout_couvrir_herite": True,
    "motifs_livres": ["^(nc|nextcloud|cloud)\\."]}


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvrir(nav, largeur, demo=False):
    p = nav.new_page(viewport={"width": largeur, "height": 900})
    p.postes = []

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1]
        if u.startswith("/waf/modes.html"):
            return r.fulfill(status=200, content_type="text/html", body=PAGE)
        if r.request.method == "POST":
            p.postes.append((u, json.loads(r.request.post_data or "{}")))
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(SITES))
        corps = {"/api/v1/waf/php-sites": SITES, "/api/v1/waf/leurres-service/modes": {"leurres": []},
                 "/api/v1/waf/categories": {"categories": {}, "source": "box"}}.get(u.split("?")[0], {})
        return r.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/**", sert)
    p.goto("http://sbx.test/waf/modes.html" + ("?demo=1" if demo else ""))
    p.wait_for_selector("#sitesDetectes .site")
    return p


@pytest.mark.parametrize("largeur", [1280, 400])
def test_rendu_sans_injection_ni_debordement(nav, largeur):
    p = ouvrir(nav, largeur)
    t = p.inner_text("#panSites")
    assert "212 autres sites servis : non PHP, contrôles inutiles" in t and "2 sites PHP détectés" in t
    assert XSS in t and p.evaluate("window.xss") is None and p.locator("#panSites img").count() == 0
    assert "non servi" in t and "repris de l’ancien réglage" in t and "non excluable" in t
    assert p.is_visible("#sitesTous") and "10.55.0.1" not in t
    assert p.evaluate("document.documentElement.scrollWidth") <= largeur
    p.close()


def test_gestes_envoient_les_listes_completes(nav):
    p = ouvrir(nav, 1280)
    p.locator("#sitesDetectes .site", has_text="boutique.ex.fr").get_by_role("button", name="Exclure").click()
    p.wait_for_timeout(200)
    assert p.postes[-1] == ("/api/v1/waf/php-sites", {"exclure": ["wiki.ex.fr", "boutique.ex.fr"]})
    p.fill("#siteCherche", "blog.ex.fr")
    p.click("#siteForcer")
    p.wait_for_timeout(200)
    assert p.postes[-1] == ("/api/v1/waf/php-sites", {"forcer": ["ancien.ex.fr", "blog.ex.fr"], "exclure": ["wiki.ex.fr"]})
    p.fill("#siteCherche", "inconnu.ex.fr")
    p.click("#siteExclure")
    assert len(p.postes) == 2 and "site servi" in p.inner_text("#erreur")
    p.click("#sitesTousRetirer")
    p.wait_for_timeout(200)
    assert p.postes[-1] == ("/api/v1/waf/php-sites", {"retirer_tout_couvrir": True})
    p.click("#sitesDetecter")
    p.wait_for_timeout(200)
    assert p.postes[-1][0] == "/api/v1/waf/php-sites/detecter"
    p.close()


@pytest.mark.parametrize("largeur", [1280, 400])
def test_demo_inerte(nav, largeur):
    p = ouvrir(nav, largeur, demo=True)
    p.click("#sitesDetecter")
    assert p.postes == [] and p.evaluate("document.documentElement.scrollWidth") <= largeur
    if CAPTURES:
        p.locator("#panSites").screenshot(path=f"{CAPTURES}/php-hotes-{largeur}.png")
    p.close()


def test_suspendu_bandeau_et_reactivation(nav):
    SITES.update(suspendu=True, suspendu_le="2026-11-26T08:00:00Z")
    try:
        p = ouvrir(nav, 400)
        assert p.is_visible("#sitesSuspendu") and "Détection suspendue" in p.inner_text("#sitesSuspendu")
        p.click("#sitesReactiver")
        p.wait_for_timeout(200)
        assert p.postes[-1] == ("/api/v1/waf/php-sites", {"reactiver": True})
        p.close()
    finally:
        SITES.update(suspendu=False, suspendu_le=None)


def test_tout_texte_de_l_api_en_textcontent():
    bloc = PAGE[PAGE.index("function rendreSites"):PAGE.index("function rendre(){")]
    assert "innerHTML" not in PAGE and "insertAdjacentHTML" not in PAGE and "outerHTML" not in PAGE
    assert "textContent" in bloc and "cree(" in bloc
