# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 (phase 4) — plus de double en-tête : un cardlet du Hall habillé en `Card` perd sa propre marque (icône, titre,
sous-titre), la Card la porte déjà ; ses commandes (rafraîchir, réglages) restent. Le Hall le lui dit par postMessage
`{sbx:'carte'}` (même origine, seulement les cardlets servis par le Hall) ; `sonde.js`, chargé par chaque cardlet, pose la
classe `sbx-carte` et la règle. Un cardlet hors Card, ou ouvert seul, garde son en-tête."""
import json
import mimetypes
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"
JS = (HALL_DIR / "hall-v2.js").read_text(encoding="utf-8")
SONDE = (HALL_DIR / "sonde.js").read_text(encoding="utf-8")

SERVICES = {"services": [{"id": "sbxid", "status": "active", "health": {"state": "online"}}], "intervalle_s": 15}


def test_declaration_statique():
    assert "sbx:'carte'" in JS or '"carte"' in JS
    assert "new URL(src).origin" in JS      # un micro d'une autre origine reçoit le message à SON origine, jamais '*'
    assert "sbx-carte" in SONDE and "header.tete" in SONDE and ".marque" in SONDE
    assert "e.origin" in SONDE          # jamais un message d'une autre origine
    # tout cardlet qui porte un en-tête charge sonde.js
    for f in sorted((HALL_DIR / "cardlets").glob("*.html")):
        src = f.read_text(encoding="utf-8")
        if 'class="tete' in src:
            assert "sonde.js" in src, f.name


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, v2=True):
    ctx = nav.new_context(viewport={"width": 1440, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/api/v1/webos/public/services":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(dict(SERVICES, computed_at=time.time())))
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.19.18-1", "en_ligne": true}')
        if u == "/api/v1/webos/public/hotes.js":
            return r.fulfill(status=200, content_type="application/javascript", body="")
        if u.startswith("/api/"):
            return r.fulfill(status=404, content_type="application/json", body="{}")
        if u.startswith(("/guardian/", "/dpi-vue/", "/actor-intelligence/")):
            return r.fulfill(status=200, content_type="text/html", body="<p>x</p>")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    # un micro d'une autre origine qui sait se ranger (MetaNews, BBS, Billets) : il attend {sbx:'carte'}
    p.route("https://**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>x</p>"))
    p.route("http://micro.test/**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>x</p><script>addEventListener('message',function(e){if(e.data&&e.data.sbx==='carte')document.documentElement.classList.add('sbx-carte')})</script>"))
    p.goto("http://sbx.test/" + ("?hall=v2" if v2 else ""))
    p.wait_for_selector(".fcard[data-embed='activite'] iframe", state="attached")
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    return ctx, p, erreurs


def cadre(p, nom):
    for _ in range(50):
        for f in p.frames:
            if nom in f.url:
                return f
        p.wait_for_timeout(100)
    raise AssertionError("cadre absent : " + nom)


def test_un_cardlet_habille_perd_sa_marque_mais_garde_ses_commandes(nav):
    ctx, p, erreurs = ouvre(nav)
    p.wait_for_selector(".fcard[data-embed='activite'].sbx-card", state="attached")
    f = cadre(p, "/cardlets/activite.html")
    f.wait_for_function("document.documentElement.classList.contains('sbx-carte')", timeout=5000)
    assert f.evaluate("getComputedStyle(document.querySelector('header.tete .marque')).display") == "none"
    # un cardlet dont l'en-tête porte des commandes les garde (Éphéméride : rouage des réglages)
    p.wait_for_selector(".fcard[data-embed='ephemeride'].sbx-card", state="attached")
    g = cadre(p, "/cardlets/ephemeride.html")
    g.wait_for_function("document.documentElement.classList.contains('sbx-carte')", timeout=5000)
    assert g.evaluate("getComputedStyle(document.querySelector('header.tete .marque')).display") == "none"
    assert g.evaluate("getComputedStyle(document.getElementById('rouage')).display") != "none"
    assert erreurs == []
    ctx.close()


def test_un_micro_d_une_autre_origine_recoit_le_message_a_son_origine(nav):
    ctx, p, erreurs = ouvre(nav)
    p.wait_for_selector(".fcard[data-embed='metanews'].sbx-card", state="attached")
    # Chromium de test ne charge pas un cadre https intercepté : on donne aux deux micros une autre origine http, interceptée,
    # et on les amène à l'écran (cadres paresseux). Le message part à l'origine du cadre au moment de l'envoi.
    for i in ("metanews", "podcaster"):
        p.evaluate("(i=>{const c=document.querySelector(`.fcard[data-embed='${i}']`);c.scrollIntoView({block:'center'});c.querySelector('iframe').setAttribute('src','http://micro.test/micro?m='+i)})('%s')" % i)
        p.wait_for_timeout(300)
    f = cadre(p, "micro.test/micro?m=metanews")
    f.wait_for_function("document.documentElement.classList.contains('sbx-carte')", timeout=5000)
    # une carte hors lot (Podcaster) ne reçoit rien
    g = cadre(p, "micro.test/micro?m=podcaster")
    p.wait_for_timeout(500)
    assert g.evaluate("document.documentElement.classList.contains('sbx-carte')") is False
    assert erreurs == []
    ctx.close()


def test_un_cardlet_hors_card_garde_son_en_tete(nav):
    ctx, p, erreurs = ouvre(nav)
    # Surf & Viewer n'est pas dans le lot : pas de Card, pas de message, en-tête intact
    f = cadre(p, "/cardlets/surfviewer.html")
    p.wait_for_timeout(800)
    assert f.evaluate("document.documentElement.classList.contains('sbx-carte')") is False
    assert f.evaluate("getComputedStyle(document.querySelector('header.tete .marque')).display") != "none"
    assert erreurs == []
    ctx.close()


def test_hall_v1_ne_touche_pas_aux_cardlets(nav):
    ctx, p, erreurs = ouvre(nav, v2=False)
    f = cadre(p, "/cardlets/activite.html")
    p.wait_for_timeout(800)
    assert f.evaluate("document.documentElement.classList.contains('sbx-carte')") is False
    assert erreurs == []
    ctx.close()
