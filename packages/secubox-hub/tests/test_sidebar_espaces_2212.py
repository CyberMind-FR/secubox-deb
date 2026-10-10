# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2212 : la barre latérale propose la navigation à six espaces derrière un drapeau, sans rien changer par défaut ; vrai navigateur, API simulée."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
SIDEBAR = Path(__file__).resolve().parents[1] / "www" / "shared" / "sidebar.js"
PAGE = "<!doctype html><html><head><meta charset=utf-8><title>t</title></head><body><nav class='sidebar' id='sidebar'></nav><main>contenu</main><script src='/shared/sidebar.js'></script></body></html>"


def item(i, nom, path, cat, espace, objet=None, ordre=100):
    return {"id": i, "name": nom, "icon": "🔹", "path": path, "category": cat, "order": ordre, "theme": "socle", "installed": True, "active": True, "espace": espace, "objet": objet}


WAF, NAC, BACKUP, HUB = (item("waf", "WAF", "/waf/", "wall", "protection", None, 105), item("nac", "NAC", "/nac/", "auth", "surveillance", "DEVICE", 130),
                         item("backup", "Backup", "/backup/", "boot", "systeme", "BACKUP", 550), item("hub", "Dashboard", "/", "root", "apercu", "BOX", 0))
MENU = {"categories": [{"id": "wall", "name": "Wall", "icon": "🧱", "order": 2, "items": [WAF]}, {"id": "auth", "name": "Auth", "icon": "🔑", "order": 1, "items": [NAC]},
                       {"id": "boot", "name": "Boot", "icon": "🚀", "order": 3, "items": [BACKUP]}, {"id": "root", "name": "Root", "icon": "🔧", "order": 4, "items": [HUB]}],
        "themes": [], "total_installed": 4, "total_active": 4,
        "espaces": [{"id": "apercu", "nom": "Vue d'ensemble", "icone": "🏠", "ordre": 1, "items": [HUB]}, {"id": "protection", "nom": "Protection", "icone": "🛡️", "ordre": 2, "items": [WAF]},
                    {"id": "surveillance", "nom": "Surveillance", "icone": "👁️", "ordre": 3, "items": [NAC]}, {"id": "systeme", "nom": "Système", "icone": "⚙️", "ordre": 6, "items": [BACKUP]}]}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, menu, url="http://sbx.test/waf/"):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(route):
        u = route.request.url
        corps = menu if u.endswith("/public/menu") else {}
        route.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/shared/**", lambda r: r.fulfill(status=200, content_type="text/css", body=""))         # d'abord le général : le dernier enregistré l'emporte
    p.route("http://sbx.test/api/**", api)
    p.route("http://sbx.test/shared/sidebar.js", lambda r: r.fulfill(status=200, content_type="application/javascript", body=SIDEBAR.read_text(encoding="utf-8")))
    base = url.split("?")[0]
    p.route(lambda u: u.split("?")[0] == base, lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE))
    p.goto(url)
    p.wait_for_selector("#sidebar .nav-section", timeout=15000)
    p.wait_for_function("document.querySelectorAll('#sidebar .nav-item').length >= 4", timeout=15000)
    return ctx, p, erreurs


def titres(p):
    return [t.strip() for t in p.locator("#sidebar .nav-section-title span.cat-label, #sidebar .nav-section-title > span:first-child").all_inner_texts()]


def test_par_defaut_la_navigation_reste_celle_des_categories(navigateur):
    ctx, p, erreurs = ouvre(navigateur, MENU)
    texte = p.inner_text("#sidebar")
    assert "WALL" in texte and "AUTH" in texte and "BOOT" in texte and "PROTECTION" not in texte and "SURVEILLANCE" not in texte
    assert not erreurs
    ctx.close()


def test_le_drapeau_nav_espaces_bascule_sur_les_six_espaces_et_se_souvient(navigateur):
    ctx, p, erreurs = ouvre(navigateur, MENU, "http://sbx.test/waf/?nav=espaces")
    texte = p.inner_text("#sidebar")
    for nom in ("VUE D'ENSEMBLE", "PROTECTION", "SURVEILLANCE", "SYSTÈME"):
        assert nom in texte, nom
    assert "WALL" not in texte and "AUTH" not in texte
    assert p.evaluate("localStorage.getItem('sbx_nav')") == "espaces"
    assert p.locator("#sidebar .nav-item").count() == 4                                      # aucune entrée perdue
    p.goto("http://sbx.test/waf/")                                                            # sans paramètre : le choix est mémorisé
    p.wait_for_function("document.querySelectorAll('#sidebar .nav-item').length >= 4")
    assert "PROTECTION" in p.inner_text("#sidebar") and "WALL" not in p.inner_text("#sidebar")
    assert not erreurs
    ctx.close()


def test_la_section_de_la_page_courante_est_ouverte_et_marquee_active(navigateur):
    ctx, p, _ = ouvre(navigateur, MENU, "http://sbx.test/waf/?nav=espaces")
    actif = p.locator("#sidebar .nav-item.active")
    assert actif.count() == 1 and "WAF" in actif.inner_text()
    assert p.locator("#sidebar .nav-section:not(.collapsed)").count() >= 1
    ctx.close()


def test_nav_categories_revient_a_l_ancienne_navigation(navigateur):
    ctx, p, _ = ouvre(navigateur, MENU, "http://sbx.test/waf/?nav=espaces")
    p.goto("http://sbx.test/waf/?nav=categories")
    p.wait_for_function("document.querySelectorAll('#sidebar .nav-item').length >= 4")
    assert "WALL" in p.inner_text("#sidebar") and p.evaluate("localStorage.getItem('sbx_nav')") is None
    ctx.close()


def test_un_hub_sans_espaces_garde_les_categories_meme_avec_le_drapeau(navigateur):
    ancien = {k: v for k, v in MENU.items() if k != "espaces"}
    ctx, p, erreurs = ouvre(navigateur, ancien, "http://sbx.test/waf/?nav=espaces")
    assert "WALL" in p.inner_text("#sidebar") and not erreurs                                  # jamais de menu vide parce que l'API est ancienne
    ctx.close()


def test_le_cache_html_ne_melange_pas_les_deux_modes(navigateur):
    ctx, p, _ = ouvre(navigateur, MENU)
    cles = p.evaluate("Object.keys(localStorage).filter(k => k.startsWith('sbx_sidebar_html'))")
    p.goto("http://sbx.test/waf/?nav=espaces")
    p.wait_for_function("document.querySelectorAll('#sidebar .nav-item').length >= 4")
    cles2 = p.evaluate("Object.keys(localStorage).filter(k => k.startsWith('sbx_sidebar_html'))")
    assert set(cles2) - set(cles)                                                              # une clé distincte pour les espaces : pas de HTML périmé de l'autre mode
    ctx.close()


def test_un_lien_permet_de_changer_de_mode(navigateur):
    ctx, p, _ = ouvre(navigateur, MENU)
    lien = p.locator("#sidebar a.nav-mode-link")
    assert lien.count() == 1 and "nav=espaces" in lien.get_attribute("href")
    ctx.close()
