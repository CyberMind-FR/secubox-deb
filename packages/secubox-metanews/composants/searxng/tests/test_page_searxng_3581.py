# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3581 — /searxng/ au profil Aurora : test statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "searxng" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif_ni_innerhtml():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-light" not in SRC and "design-tokens" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "onclick=", "eval("):
        assert interdit not in SRC, interdit
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'searxng'" in SRC and "Q.get('demo')" in SRC and "Q.get('embed')" in SRC


def test_routes_et_seule_ecriture():
    for lecture in ("lire('/status')", "lire('/components')", "lire('/engines')", "lire('/rechercher?q='"):
        assert lecture in SRC
    assert re.findall(r"appel\('([^']+)', 'POST'\)", SRC) == ["/reload"]
    assert "encodeURIComponent(q)" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "Bearer" in SRC
    assert "rel = 'noopener noreferrer'" in SRC and "textContent" in SRC
    assert 'maxlength="256"' in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STAT = {"module": "searxng", "version": "0.6.0", "overall": "yellow", "conteneur": "running", "service": "stopped", "api": "running",
        "adresse": "192.0.2.85:8888"}
COMP = {"components": [{"name": "lxc", "state": "running", "detail": "searxng @ 192.0.2.85"},
                       {"name": "searxng", "state": "stopped", "detail": "<b>SearXNG</b>"},
                       {"name": "host-api", "state": "running", "detail": "secubox-searxng"}]}
MOT = {"source": "searxng", "actifs": [{"nom": "wikipedia"}, {"nom": "<i>bing</i>"}], "desactives": ["brave"],
       "sans_reponse_recente": {"moteurs": []}}
RES = {"q": "x", "page": 1, "nombre": 3, "moteurs_sans_reponse": [{"moteur": "qwant", "raison": "too many requests"}],
       "resultats": [{"titre": "<img src=x onerror=alert(1)>", "url": "https://ex.example/a", "extrait": "<script>x</script>", "moteur": "bing"},
                     {"titre": "piège", "url": "javascript:alert(1)", "extrait": "", "moteur": "bing"},
                     {"titre": "Deux", "url": "http://ex.example/b", "extrait": "e", "moteur": "mojeek"}]}
API = {"/status": (200, STAT), "/components": (200, COMP), "/engines": (200, MOT), "/rechercher": (200, RES),
       "/reload": (200, {"issue": "applique"})}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    if jeton:
        ctx.add_init_script("localStorage.setItem('sbx_token', '%s')" % jeton)
    p = ctx.new_page()
    erreurs, appels, dialogues = [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (dialogues.append(d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "searxng":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/searxng", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.url, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/searxng/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels, dialogues


def test_etat_composants_moteurs(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/searxng/", API, jeton="jeton-de-test")
    p.wait_for_function("document.getElementById('tMoteurs').textContent !== '—'")
    assert p.inner_text("#etat") == "DÉGRADÉ" and p.inner_text("#tConteneur") == "EN MARCHE" and p.inner_text("#tService") == "ARRÊTÉ"
    assert p.inner_text("#tMoteurs") == "2" and p.locator("#lActifs i").count() == 0 and "<i>bing</i>" in p.inner_text("#lActifs")
    assert p.locator("#lComp b").count() == 0 and "<b>SearXNG</b>" in p.inner_text("#lComp")
    assert {a[1] for a in appels} == {"/status", "/components", "/engines"} and all(a[0] == "GET" for a in appels)
    assert all(a[3] == "Bearer jeton-de-test" for a in appels) and err == []
    ctx.close()


def test_recherche_textcontent_et_liens_surs(navigateur):
    ctx, p, err, appels, dialogues = ouvre(navigateur, "http://sbx.test/searxng/", API)
    p.fill("#q", "été & co")
    p.click("#bChercher")
    p.wait_for_selector("#lResultats li")
    assert p.locator("#lResultats li").count() == 3
    assert p.locator("#lResultats img, #lResultats script").count() == 0
    assert "<img src=x onerror=alert(1)>" in p.inner_text("#lResultats")
    liens = p.locator("#lResultats a")
    assert liens.count() == 2 and p.locator("#lResultats a[href^=javascript]").count() == 0
    for i in range(2):
        assert liens.nth(i).get_attribute("rel") == "noopener noreferrer" and liens.nth(i).get_attribute("target") == "_blank"
    assert "qwant" in p.inner_text("#rRetour")
    url = [a[2] for a in appels if a[1] == "/rechercher"][0]
    assert "q=%C3%A9t%C3%A9%20%26%20co" in url and "page=1" in url
    assert dialogues == [] and err == []
    ctx.close()


def test_recherche_refusee_sans_administrateur(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/searxng/", {**API, "/rechercher": (401, {"detail": "jeton requis"})})
    p.fill("#q", "x")
    p.click("#bChercher")
    p.wait_for_selector("#rRetour.ko")
    assert "administrateur" in p.inner_text("#rRetour") and p.locator("#lResultats li").count() == 0 and err == []
    ctx.close()


def test_recharger_demande_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels, dialogues = ouvre(navigateur, "http://sbx.test/searxng/", API)
    p.wait_for_function("document.getElementById('tMoteurs').textContent !== '—'")
    p.click("#bRecharger")
    assert p.is_visible("#conf") and "Recharger la configuration" in p.inner_text("#confTexte")
    p.click("#confNon")
    assert not p.is_visible("#conf") and not [a for a in appels if a[0] == "POST"]
    p.click("#bRecharger")
    p.click("#confOui")
    p.wait_for_selector("#cRetour.ok")
    assert [a[1] for a in appels if a[0] == "POST"] == ["/reload"] and "rechargée" in p.inner_text("#cRetour")
    assert dialogues == [] and err == []
    ctx.close()


def test_recharger_retour_arriere_affiche(navigateur):
    routes = {**API, "/reload": (409, {"detail": {"issue": "retour-arriere", "detail": "SearXNG ne répond pas"}})}
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/searxng/", routes)
    p.wait_for_function("document.getElementById('tMoteurs').textContent !== '—'")
    p.click("#bRecharger")
    p.click("#confOui")
    p.wait_for_selector("#cRetour.ko")
    assert "ancienne configuration rétablie" in p.inner_text("#cRetour") and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/searxng/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tGlobal", "#tConteneur", "#tService", "#tMoteurs")] == ["—"] * 4 and err == []
    ctx.close()


def test_api_injoignable(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/searxng/", {k: (500, {}) for k in API})
    p.wait_for_selector("#erreur:not([hidden])")
    assert p.inner_text("#etat") == "HORS LIGNE" and err == []
    ctx.close()


def test_demonstration_sans_aucun_appel(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/searxng/?demo=1", {})
    p.wait_for_function("document.getElementById('tMoteurs').textContent === '5'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.fill("#q", "test")
    p.click("#bChercher")
    p.wait_for_selector("#lResultats li")
    p.click("#bRecharger")
    p.click("#confOui")
    p.wait_for_selector("#cRetour:not([hidden])")
    assert "aucune action" in p.inner_text("#cRetour")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_420_sans_debordement(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/searxng/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tMoteurs').textContent !== '—'")
    p.fill("#q", "x")
    p.click("#bChercher")
    p.wait_for_selector("#lResultats li")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
