# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 — menus liés hall ↔ admin : une rubrique de la sidebar se déplie sur ses modules (ouverts embarqués), le module
embarqué est marqué et sa sous-navigation (GET /public/menu/{id}) apparaît sous lui ; la sidebar se replie en rail
pendant l'embarquement et rend la largeur au cadre."""
import json
import mimetypes
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"
SERVICES = {"services": [
    {"id": "radio", "name": "Radio", "category": "mind", "icon": "R", "description": "Webradio souveraine", "installed": True, "active": True, "status": "active", "health": {"state": "online"}, "path": "/radio/"},
    {"id": "bbs", "name": "BBS", "category": "mind", "icon": "B", "description": "Forums et gazette", "installed": True, "active": True, "status": "active", "health": {"state": "online"}, "path": "/bbs/"},
    {"id": "waf", "name": "WAF", "category": "wall", "icon": "W", "description": "Pare-feu applicatif", "installed": True, "active": True, "status": "active", "health": {"state": "online"}, "path": "/waf/"},
    {"id": "peertube", "name": "PeerTube", "category": "mesh", "icon": "P", "description": "Vidéo fédérée", "installed": True, "active": True, "status": "idle", "health": {"state": "online"}, "path": "/pt/"},
], "computed_at": time.time(), "releve": "2026-10-21T07:10:52+00:00", "intervalle_s": 15}
MENU_BBS = {"id": "bbs", "items": [{"slug": "atelier", "title": "Atelier", "threads": 15}, {"slug": "place", "title": "Place publique", "threads": 9}, {"path": "/gazette", "title": "Gazette"}]}

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
        if u == "/api/v1/webos/public/menu/bbs":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(MENU_BBS))
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.18.0-1", "en_ligne": true}')
        if u.startswith("/api/"):
            return r.fulfill(status=404, content_type="application/json", body="{}")
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


def test_une_rubrique_se_deplie_sur_ses_modules_et_les_ouvre(nav):
    ctx, p, erreurs = ouvre(nav)
    assert p.evaluate("[...document.querySelectorAll('.sbx-side .sbx-plier')].every(b=>b.getAttribute('aria-expanded')==='false')")
    p.click(".sbx-grp[data-grp='communication'] .sbx-plier")
    assert p.evaluate("document.querySelector('.sbx-grp[data-grp=communication] .sbx-plier').getAttribute('aria-expanded')") == "true"
    items = p.evaluate("[...document.querySelectorAll('.sbx-grp[data-grp=communication] .sbx-sous-item')].map(b=>[b.getAttribute('data-open'),b.getAttribute('data-mode'),b.textContent.trim()])")
    assert ["bbs", "embed", "BBS"] in items and all(i[0] != "waf" for i in items)
    # chaque module déplié porte ses accès rapides ⚙ admin et ⧉ onglet
    assert p.evaluate("[...document.querySelectorAll('.sbx-grp[data-grp=communication] .sbx-sous-ligne')].every(l=>l.querySelector('[data-admin]')&&l.querySelector('[data-open][data-mode=tab]'))")
    p.click(".sbx-grp[data-grp='communication'] .sbx-plier")
    assert p.evaluate("document.querySelector('.sbx-grp[data-grp=communication] .sbx-sous').hidden")
    assert erreurs == []
    ctx.close()


def test_le_module_embarque_est_marque_et_sa_sous_navigation_apparait(nav):
    ctx, p, erreurs = ouvre(nav)
    p.evaluate("openService('bbs','embed')")
    p.wait_for_selector(".sbx-grp[data-grp='communication'] .sbx-sous-item.on[data-open='bbs']", state="attached")
    p.wait_for_selector(".sbx-ctx-liste .sbx-ctx", state="attached")
    rows = p.evaluate("[...document.querySelectorAll('.sbx-ctx-liste .sbx-ctx')].map(a=>[a.getAttribute('data-ctx'),a.getAttribute('data-ctxt'),a.querySelector('small')&&a.querySelector('small').textContent])")
    assert rows == [["/c/atelier", "Atelier", "15"], ["/c/place", "Place publique", "9"], ["/gazette", "Gazette", None]]
    assert p.evaluate("document.querySelector('.sbx-side .sbx-rub.on[data-rub]').getAttribute('data-rub')") == "communication"
    # la sidebar est repliée en rail pendant l'embarquement, et rend la largeur au cadre
    assert round(p.evaluate("document.querySelector('.sbx-side').getBoundingClientRect().width")) == 64
    assert p.evaluate("document.querySelector('.shell').getBoundingClientRect().width") >= 1440 - 64 - 1
    # au survol, le rail redevient la sidebar complète ; un clic sur une rubrique du service l'ouvre dans le cadre et la marque
    p.hover(".sbx-side")
    p.wait_for_function("document.querySelector('.sbx-side').getBoundingClientRect().width > 200")
    p.click(".sbx-ctx[data-ctx='/c/place']")
    # le Hall redessine #ctx, la liste est reconstruite : la rubrique courante (_sub) ressort marquée
    p.wait_for_function("(()=>{const a=document.querySelector('.sbx-ctx[data-ctx=\"/c/place\"]');return !!a && a.classList.contains('on')})()")
    assert "Place publique" in p.inner_text("#sb-loc")
    assert erreurs == []
    ctx.close()


def test_retour_a_l_accueil_redonne_la_sidebar_complete(nav):
    ctx, p, erreurs = ouvre(nav)
    p.evaluate("openService('radio','embed')")
    p.wait_for_selector("#view-embed:not(.hidden)", state="attached")
    assert round(p.evaluate("document.querySelector('.sbx-side').getBoundingClientRect().width")) == 64
    p.click(".sbx-side .sbx-rub[data-rub='accueil']", force=True)
    p.wait_for_function("document.querySelector('.sbx-side').getBoundingClientRect().width > 200")
    assert erreurs == []
    ctx.close()
