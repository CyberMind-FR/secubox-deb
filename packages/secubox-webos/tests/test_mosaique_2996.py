# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 (phase 4, mosaïque) — « Modules » et les rubriques ouvrent une mosaïque de tuiles cliquables : modules du
registre (icône de catégorie, nom, hôte, pastille) qui s'ouvrent dans le Hall, sites metablogizer avec vignette."""
import json
import mimetypes
import os
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"
CAPTURES = os.environ.get("SBX_CAPTURES")
SERVICES = {"services": [
    {"id": "radio", "name": "Radio", "category": "mind", "icon": "R", "description": "Webradio", "installed": True, "active": True, "status": "active", "health": {"state": "online"}, "path": "/radio/"},
    {"id": "waf", "name": "WAF", "category": "wall", "icon": "W", "description": "Pare-feu applicatif", "installed": True, "active": True, "status": "active", "health": {"state": "online"}, "path": "/waf/"},
    {"id": "ad-guard", "name": "Guardian", "category": "wall", "icon": "G", "description": "DNS filtrant", "installed": True, "active": True, "status": "stale", "health": {"state": "degraded"}, "path": "/ad-guard/"},
    {"id": "wireguard", "name": "WireGuard", "category": "mesh", "icon": "V", "description": "VPN du réseau", "installed": True, "active": True, "status": "offline", "health": {"state": "offline"}, "path": "/wireguard/"},
    {"id": "zia", "name": "ZIA", "category": "mind", "icon": "Z", "description": "Assistant IA", "installed": True, "active": True, "status": "idle", "health": {"state": "online"}, "path": "/zia/"},
], "computed_at": time.time(), "releve": "2026-10-21T07:10:52+00:00", "intervalle_s": 15}
MOSAIQUE = {"sites": [{"name": "blog", "domain": "blog.sbx.test", "title": "Le blog", "category": "perso", "vignette": True},
                      {"name": "sans", "domain": "sans.sbx.test", "title": "Sans image", "category": None, "vignette": False}], "total": 2}
PNG = b"\x89PNG\r\n\x1a\n" + bytes.fromhex("0000000d4948445200000001000000010806000000" "1f15c489" "0000000a49444154789c6300010000050001" "0d0a2db4" "0000000049454e44ae426082")

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, largeur=1440):
    ctx = nav.new_context(viewport={"width": largeur, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/api/v1/webos/public/services":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(SERVICES))
        if u == "/api/v1/metablogizer/public/mosaique":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(MOSAIQUE))
        if u == "/api/v1/metablogizer/site/blog/screenshot":
            return r.fulfill(status=200, content_type="image/png", body=PNG)
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.17.0-1", "en_ligne": true}')
        if u.startswith("/api/"):
            return r.fulfill(status=401, content_type="application/json", body="{}")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.route("https://**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>x</p>"))
    p.goto("http://sbx.test/?hall=v2")
    p.wait_for_selector(".fcard[data-status]", state="attached")
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    return ctx, p, erreurs


def test_modules_ouvre_la_mosaique_de_tous_les_modules(nav):
    ctx, p, erreurs = ouvre(nav)
    p.click(".sbx-side .sbx-rub[data-rub='modules']")
    p.wait_for_selector("#view-mosaique:not(.hidden) .sbx-mtuile", state="attached")
    assert p.evaluate("document.getElementById('view-accueil').classList.contains('hidden')")
    assert p.evaluate("document.querySelectorAll('#view-mosaique .sbx-mtuile').length") == 5
    noms = p.evaluate("[...document.querySelectorAll('#view-mosaique .sbx-mtuile b')].map(e=>e.textContent)")
    assert noms == sorted(noms, key=str.casefold)
    assert p.evaluate("[...document.querySelectorAll('#view-mosaique .sbx-mtuile')].every(t=>{const o=t.querySelector('button.ouvre');return o&&o.getAttribute('data-open')&&o.getAttribute('data-mode')==='embed'&&t.querySelector('svg.sbx-ico')&&t.querySelector('.sbx-led')})")
    # accès rapides comme dans les menus Services / Système : ⚙ console admin et ⧉ onglet réel
    assert p.evaluate("[...document.querySelectorAll('#view-mosaique .sbx-mtuile')].every(t=>t.querySelector('.sbx-actions [data-admin]')&&t.querySelector('.sbx-actions [data-open][data-mode=tab]'))")
    assert p.evaluate("document.querySelector('#view-mosaique .sbx-mtuile[data-module=zia] .sbx-led').getAttribute('data-ton')") == "info"
    assert p.evaluate("document.querySelector('#view-mosaique .sbx-mtuile[data-module=wireguard]').getAttribute('data-status')") == "offline"
    # les menus Services / Système de la barre restent accessibles en v2
    assert p.evaluate("getComputedStyle(document.querySelector('.mnav')).display") != "none"
    assert p.evaluate("document.querySelector('.sbx-side .sbx-rub.on').getAttribute('data-rub')") == "modules"
    if CAPTURES:
        p.screenshot(path=str(Path(CAPTURES) / "hall-v2-mosaique.png"))
    assert erreurs == []
    ctx.close()


def test_rubrique_securite_filtre_et_l_onglet_sites_montre_les_vignettes(nav):
    ctx, p, erreurs = ouvre(nav)
    p.click(".sbx-side .sbx-rub[data-rub='securite']")
    p.wait_for_selector("#view-mosaique:not(.hidden) .sbx-mtuile", state="attached")
    assert p.inner_text("#view-mosaique .sbx-mosaique-titre") == "Sécurité"
    assert sorted(p.evaluate("[...document.querySelectorAll('#view-mosaique .sbx-mtuile')].map(t=>t.getAttribute('data-module'))")) == ["ad-guard", "waf"]
    assert p.evaluate("document.querySelector('#view-mosaique [role=tab][aria-selected=true]').getAttribute('data-id')") == "securite"
    p.click("#view-mosaique [role=tab][data-id='sites']")
    p.wait_for_selector("#view-mosaique .sbx-stuile", state="attached")
    tuiles = p.evaluate("[...document.querySelectorAll('#view-mosaique .sbx-stuile')].map(a=>[a.href,a.target,a.rel,!!a.querySelector('img'),a.querySelector('b').textContent])")
    assert tuiles == [["https://blog.sbx.test/", "_blank", "noopener", True, "Le blog"], ["https://sans.sbx.test/", "_blank", "noopener", False, "Sans image"]]
    assert p.evaluate("document.querySelector('#view-mosaique .sbx-stuile img').getAttribute('src')") == "/api/v1/metablogizer/site/blog/screenshot"
    assert p.evaluate("getComputedStyle(document.querySelector('#view-mosaique .sbx-stuile .vig')).aspectRatio") in ("16 / 10", "1.6")
    if CAPTURES:
        p.screenshot(path=str(Path(CAPTURES) / "hall-v2-mosaique-sites.png"))
    assert erreurs == []
    ctx.close()


def test_mes_sites_dans_la_sidebar_ouvre_la_mosaique_des_sites(nav):
    ctx, p, erreurs = ouvre(nav)
    p.click(".sbx-side .sbx-rub[data-rub='sites']")
    p.wait_for_selector("#view-mosaique:not(.hidden) .sbx-stuile", state="attached")
    assert p.inner_text("#view-mosaique .sbx-mosaique-titre") == "Mes sites"
    assert p.evaluate("document.querySelector('#view-mosaique [role=tab][aria-selected=true]').getAttribute('data-id')") == "sites"
    assert p.evaluate("document.querySelectorAll('#view-mosaique .sbx-stuile').length") == 2
    assert p.evaluate("document.querySelector('.sbx-side .sbx-rub.on').getAttribute('data-rub')") == "sites"
    assert erreurs == []
    ctx.close()


def test_une_tuile_ouvre_le_service_dans_le_hall_et_nourrit_les_recents(nav):
    ctx, p, erreurs = ouvre(nav)
    p.click(".sbx-side .sbx-rub[data-rub='modules']")
    p.wait_for_selector("#view-mosaique:not(.hidden) .sbx-mtuile[data-module=radio]", state="attached")
    p.click("#view-mosaique .sbx-mtuile[data-module=radio] .ouvre")
    p.wait_for_selector("#view-embed:not(.hidden)", state="attached")
    assert p.evaluate("document.getElementById('view-mosaique').classList.contains('hidden')")
    assert p.evaluate("JSON.parse(localStorage.getItem('sbx.hall.recents'))") == ["radio"]
    p.click(".sbx-side .sbx-rub[data-rub='modules']")
    p.click("#view-mosaique [role=tab][data-id='recents']")
    assert p.evaluate("[...document.querySelectorAll('#view-mosaique .sbx-mtuile')].map(t=>t.getAttribute('data-module'))") == ["radio"]
    p.click("#view-mosaique [role=tab][data-id='favoris']")
    assert not p.evaluate("document.querySelector('#view-mosaique .sbx-mosaique-vide').hidden")
    assert erreurs == []
    ctx.close()


def test_mobile_barre_basse_modules_puis_retour_accueil(nav):
    ctx, p, erreurs = ouvre(nav, 390)
    p.click(".sbx-tabbar button[data-rub='modules']")
    p.wait_for_selector("#view-mosaique:not(.hidden) .sbx-mtuile", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert p.evaluate("document.querySelector('.sbx-tabbar button.on').getAttribute('data-rub')") == "modules"
    p.click(".sbx-tabbar button[data-rub='accueil']")
    assert p.evaluate("document.getElementById('view-mosaique').classList.contains('hidden')")
    assert not p.evaluate("document.getElementById('view-accueil').classList.contains('hidden')")
    assert erreurs == []
    ctx.close()
