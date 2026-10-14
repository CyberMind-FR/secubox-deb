# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2649 — /grafana/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "composants/grafana/www/grafana/index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-" not in SRC and "fonts.googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onsubmit="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'grafana'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer ' + t" in SRC


def test_aucun_secret_ni_stockage():
    assert "setItem" not in SRC and "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "grafana":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/grafana", 1)[1]
        appels.append((r.request.method, chemin, r.request.post_data))
        cle = chemin.split("?")[0]
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, routes.get(cle, (404, {})))
        else:
            statut, corps = routes.get(cle, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/grafana/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


COMP = {"module": "grafana", "components": [{"name": "lxc", "state": "running", "detail": "grafana @ 10.0.0.5"},
                                            {"name": "daemon", "state": "stopped", "detail": "grafana-server"}]}
STAT = {"module": "grafana", "overall": "yellow"}
ACC = {"module": "grafana", "access": [{"url": "http://10.0.0.5:3000/", "auth": "lan-only", "scope": "lan"},
                                       {"url": "javascript:alert(1)", "auth": "x", "scope": "public"}]}
API = {"/components": (200, COMP), "/status": (200, STAT), "/access": (200, ACC)}
URL = "http://sbx.test/grafana/"


def test_routes_et_iframe_a_l_identique():
    for r in ("'/components'", "'/status'", "'/access'", "/grafana/d/secubox-services/secubox-services-overview?kiosk=tv&theme=light"):
        assert r in SRC
    assert "'POST'" not in SRC and "'DELETE'" not in SRC


def test_tuiles_composants_et_acces(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, API)
    p.wait_for_selector("#lComp .elt")
    assert [p.inner_text(i) for i in ("#tGlobal", "#tComp", "#tAcces")] == ["DÉGRADÉ", "1 / 2", "2"]
    assert p.inner_text("#etat") == "DÉGRADÉ" and "grafana @ 10.0.0.5" in p.inner_text("#lComp")
    # une adresse non http(s) n'est jamais un lien ; le bouton natif retient une adresse sûre ou se cache
    assert p.locator("#lAcces a").count() == 1 and p.get_attribute("#natif", "href") is None and p.is_hidden("#natif")
    assert err == []
    ctx.close()


def test_bouton_natif_prefere_l_adresse_publique(navigateur):
    acc = {"access": [{"url": "http://10.0.0.5:3000/", "scope": "lan"}, {"url": "https://g.example.org/", "scope": "public"}]}
    ctx, p, _, _ = ouvre(navigateur, URL, {**API, "/access": (200, acc)})
    p.wait_for_selector("#lAcces .elt")
    assert p.get_attribute("#natif", "href") == "https://g.example.org/" and p.get_attribute("#natif", "rel") == "noopener"
    ctx.close()


def test_iframe_charge_hors_demo(navigateur):
    ctx, p, _, _ = ouvre(navigateur, URL, API)
    p.wait_for_selector("#lComp .elt")
    assert p.get_attribute("#graf", "src").startswith("/grafana/d/secubox-services/")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, URL, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tGlobal", "#tComp", "#tAcces")] == ["—"] * 3 and err == []
    ctx.close()


def test_demonstration_annoncee_sans_appel(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_selector("#lComp .elt")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.is_hidden("#graf") and p.get_attribute("#graf", "src") is None
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#lComp .elt")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
