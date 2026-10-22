# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3011 — l'affichage n'applique que des caches REMPLIS : une réponse vide du registre laisse le dernier
relevé visible (cartes, mosaïque), au lieu de basculer toutes les cartes en « aucune source »."""
import json
import mimetypes
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"
PLEIN = {"services": [
    {"id": "radio", "name": "Radio", "category": "mind", "icon": "R", "description": "Webradio", "installed": True, "active": True, "status": "active", "health": {"state": "online"}, "path": "/radio/"},
    {"id": "metanews", "name": "MetaNews", "category": "mind", "icon": "M", "description": "Actualités", "installed": True, "active": True, "status": "stale", "health": {"state": "degraded"}, "path": "/metanews/"},
], "computed_at": time.time(), "releve": "2026-10-22T04:10:52+00:00", "intervalle_s": 15}
VIDE = {"services": [], "computed_at": time.time() + 15, "releve": "2026-10-22T04:11:07+00:00", "intervalle_s": 15}

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, reponses):
    ctx = nav.new_context(viewport={"width": 1440, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/api/v1/webos/public/services":
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(reponses["services"]))
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.19.10-1", "en_ligne": true}')
        if u.startswith("/api/"):
            return r.fulfill(status=401, content_type="application/json", body="{}")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.route("https://**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>x</p>"))
    # `commit` : les micro-cadres des cartes (https://…) retiennent l'événement `load` ; ce qu'on attend, c'est la première carte statuée.
    p.goto("http://sbx.test/?hall=v2", wait_until="commit")
    p.wait_for_selector(".fcard[data-embed='radio'][data-status='active']", state="attached", timeout=20000)
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    return ctx, p, erreurs


def _resonde(p):
    """Déclenche une nouvelle sonde du registre (retour au premier plan) et attend sa réponse."""
    with p.expect_response(lambda r: r.url.endswith("/api/v1/webos/public/services")):
        p.evaluate("document.dispatchEvent(new Event('visibilitychange'))")


def test_une_reponse_vide_laisse_le_dernier_releve_visible(nav):
    reponses = {"services": PLEIN}
    ctx, p, erreurs = ouvre(nav, reponses)
    reponses["services"] = VIDE
    _resonde(p)
    p.wait_for_timeout(200)
    assert p.get_attribute(".fcard[data-embed='radio']", "data-status") == "active"
    assert p.get_attribute(".fcard[data-embed='metanews']", "data-status") == "stale"
    # Le pied garde l'heure du relevé PLEIN : rien n'a été appliqué du vide.
    assert "04:10:52" in p.inner_text(".fcard[data-embed='radio'] .sbx-fcard-pied") or "Relevé" in p.inner_text(".fcard[data-embed='radio'] .sbx-fcard-pied")
    # La mosaïque aussi dessine le dernier relevé rempli.
    p.click("#sbx-side [data-rub='modules']")
    p.wait_for_selector(".sbx-mtuile[data-module='radio']", state="attached")
    assert p.get_attribute(".sbx-mtuile[data-module='radio']", "data-status") == "active"
    assert erreurs == []
    ctx.close()


def test_une_reponse_pleine_suivante_s_applique(nav):
    reponses = {"services": PLEIN}
    ctx, p, erreurs = ouvre(nav, reponses)
    suivant = json.loads(json.dumps(PLEIN))
    suivant["services"][0]["status"] = "offline"
    reponses["services"] = suivant
    _resonde(p)
    p.wait_for_selector(".fcard[data-embed='radio'][data-status='offline']", state="attached")
    assert erreurs == []
    ctx.close()
