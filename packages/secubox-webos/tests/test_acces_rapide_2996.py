# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 (phase 4) — carte « Accès rapide » : une `Card` native sous le Hero, huit `Tile` au plus vers les services
embarqués — les favoris d'abord, puis les récents, puis la curation. Chaque tuile est un vrai bouton `data-open`
(délégation du Hall) avec la pastille du statut typé. Hall v1 : rien."""
import json
import mimetypes
import re
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"
JS = (HALL_DIR / "hall-v2.js").read_text(encoding="utf-8")
COMPOSANTS = (HALL_DIR / "composants.js").read_text(encoding="utf-8")

SERVICES = {"services": [
    {"id": "radio", "name": "Radio", "category": "mind", "status": "active", "health": {"state": "online"}},
    {"id": "peertube", "name": "PeerTube", "category": "mesh", "status": "idle", "health": {"state": "online"}},
    {"id": "dpi", "name": "DPI", "category": "mesh", "status": "active", "health": {"state": "online"}},
    {"id": "waf", "name": "WAF", "category": "wall", "status": "active", "health": {"state": "online"}},
], "intervalle_s": 15}


def test_declaration_statique():
    assert "function accesRapide(" in JS
    assert "o.attrs" in COMPOSANTS   # Tile porte des attributs (data-open, data-mode)
    assert re.search(r"\.sbx-acces", (HALL_DIR / "hall-v2.css").read_text(encoding="utf-8"))


def test_boutique_epinglee_apres_les_recents_avant_la_curation():
    assert "var EPINGLES=['boutique']" in JS
    i = JS.index("function accesRapide(")
    corps = JS[i:i + 1600]
    assert corps.index("recents().forEach(pousse)") < corps.index("EPINGLES.forEach(pousse)") < corps.index("FEATURED")
    assert "boutique:'grille'" in JS and "boutique:'appstore'" in JS


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, largeur=1440, v2=True, recents=("dpi", "peertube")):
    ctx = nav.new_context(viewport={"width": largeur, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/api/v1/webos/public/services":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(dict(SERVICES, computed_at=time.time())))
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.19.14-1", "en_ligne": true}')
        if u.startswith("/api/"):
            return r.fulfill(status=404, content_type="application/json", body="{}")
        if u.startswith(("/cardlets/", "/guardian/", "/dpi-vue/", "/actor-intelligence/")):
            return r.fulfill(status=200, content_type="text/html", body="<p>cardlet</p>")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.route("https://**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>x</p>"))
    p.add_init_script("try{localStorage.setItem('sbx.hall.recents',%s)}catch(e){}" % json.dumps(json.dumps(list(recents))))
    p.goto("http://sbx.test/" + ("?hall=v2" if v2 else ""))
    p.wait_for_selector(".fcard[data-embed]", state="attached")
    if v2:
        p.wait_for_selector(".sbx-acces .sbx-tile", state="attached")
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    return ctx, p, erreurs


def test_la_carte_acces_rapide_suit_le_hero_avec_huit_tuiles_au_plus(nav):
    ctx, p, erreurs = ouvre(nav)
    c = "#view-accueil .sbx-card.sbx-acces"
    assert p.inner_text(c + " .sbx-card-titre") == "Accès rapide"
    assert p.evaluate("document.querySelector(\"%s\").previousElementSibling.classList.contains('sbx-hero')" % c)
    tuiles = p.evaluate("[...document.querySelectorAll(\"%s .sbx-tiles .sbx-tile\")].map(t=>[t.tagName,t.getAttribute('data-open'),t.getAttribute('data-mode'),t.textContent.trim()])" % c)
    assert 1 <= len(tuiles) <= 8
    for t in tuiles:
        assert t[0] == "BUTTON" and t[1] and t[2] == "embed" and t[3], t
    # récents d'abord (pas de favori ici), puis la curation ; jamais deux fois le même
    ids = [t[1] for t in tuiles]
    assert ids[:2] == ["dpi", "peertube"], ids
    assert len(set(ids)) == len(ids)
    # pastille du statut typé sur chaque tuile
    assert p.evaluate("document.querySelector(\"%s .sbx-tile[data-open='dpi'] .sbx-led\").getAttribute('data-ton')" % c) == "ok"
    assert p.evaluate("document.querySelector(\"%s .sbx-tile[data-open='peertube'] .sbx-led\").getAttribute('data-ton')" % c) == "info"
    # l'action › mène à la mosaïque des modules
    p.click(c + " .sbx-card-action")
    p.wait_for_selector("#view-mosaique:not(.hidden)", state="attached")
    assert erreurs == []
    ctx.close()


def test_un_favori_passe_en_tete(nav):
    ctx, p, erreurs = ouvre(nav)
    c = "#view-accueil .sbx-card.sbx-acces"
    # l'étoile de la carte Radio la met dans la bande des favoris → première tuile
    p.evaluate("document.querySelector(\".fcard[data-embed='radio'] .cl-vedette\").click()")
    p.wait_for_function("document.querySelector(\"%s .sbx-tile\").getAttribute('data-open')==='radio'" % c, timeout=5000)
    assert erreurs == []
    ctx.close()


def test_mobile_390_tuiles_tactiles_sans_debordement(nav):
    ctx, p, erreurs = ouvre(nav, 390)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    h = p.evaluate("Math.min(...[...document.querySelectorAll('.sbx-acces .sbx-tile')].map(t=>t.getBoundingClientRect().height))")
    assert h >= 44
    assert erreurs == []
    ctx.close()


def test_hall_v1_sans_acces_rapide(nav):
    ctx, p, erreurs = ouvre(nav, v2=False)
    assert p.evaluate("document.querySelector('.sbx-acces')") is None
    assert erreurs == []
    ctx.close()
