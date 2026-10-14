# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2651 — /yacy/ au profil Aurora : test statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "yacy" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-light" not in SRC and "design-tokens" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'yacy'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_lecture_seule_memes_routes():
    for lecture in ("lire('/components')", "lire('/status')", "lire('/access')"):
        assert lecture in SRC
    assert "method:" not in SRC and "POST" not in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "Bearer" in SRC and "try {" in SRC
    assert "'public'" in SRC and "'lan'" in SRC and "referrerpolicy" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


COMP = {"components": [{"name": "lxc", "state": "running", "detail": "yacy @ 192.0.2.80"}, {"name": "daemon", "state": "stopped", "detail": "<b>yacy</b>"},
                       {"name": "host-api", "state": "running", "detail": "secubox-yacy"}]}
STAT = {"module": "yacy", "version": "1.0.0", "overall": "yellow"}
ACCES = {"access": [{"url": "http://192.0.2.80:8090", "auth": "lan-only", "scope": "lan"}, {"url": "https://yacy.example.test", "auth": "LAN-gated", "scope": "public"}]}
API = {"/components": (200, COMP), "/status": (200, STAT), "/access": (200, ACCES)}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    if jeton:
        ctx.add_init_script("localStorage.setItem('sbx_token', '%s')" % jeton)
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "yacy":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    p.route("https://yacy.example.test/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body="<p>YaCy</p>"))

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/yacy", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/yacy/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_composants_etat_et_acces_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/yacy/", API, jeton="jeton-de-test")
    p.wait_for_function("document.getElementById('tComp').textContent !== '—'")
    assert p.inner_text("#etat") == "DÉGRADÉ" and p.inner_text("#tComp") == "2 / 3" and p.inner_text("#tAcces") == "2"
    assert p.locator("#lComp .ligne").count() == 3 and "<b>yacy</b>" in p.inner_text("#lComp") and p.locator("#lComp b").count() == 0
    assert p.get_attribute("#cGlobal", "title") and p.get_attribute("#cComp", "title")
    assert p.get_attribute("#natif", "href") == "https://yacy.example.test"          # public d'abord
    p.wait_for_selector("#cadreYacy iframe")
    assert p.get_attribute("#cadreYacy iframe", "src") == "https://yacy.example.test"
    assert {a[1] for a in appels} == {"/components", "/status", "/access"} and all(a[0] == "GET" for a in appels)
    assert all(a[2] == "Bearer jeton-de-test" for a in appels) and err == []
    ctx.close()


def test_adresse_http_seule_pas_de_cadre_sous_https_ni_lien_dangereux(navigateur):
    acces = {"access": [{"url": "javascript:alert(1)", "scope": "public"}, {"url": "http://192.0.2.80:8090", "scope": "lan"}]}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/yacy/", {**API, "/access": (200, acces)})
    p.wait_for_function("document.getElementById('tAcces').textContent === '2'")
    assert p.get_attribute("#natif", "href") == "http://192.0.2.80:8090"
    assert p.locator("#lAcces a").count() == 1 and p.locator("#lAcces a[href^=javascript]").count() == 0 and err == []
    ctx.close()


def test_sans_adresse_ni_cadre(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/yacy/", {**API, "/access": (200, {"access": []})})
    p.wait_for_function("document.getElementById('tAcces').textContent === '0'")
    assert "Aucune adresse" in p.inner_text("#cadreYacy") and not p.is_visible("#natif") and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/yacy/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE" and "session requise" in p.inner_text("#session")
    assert [p.inner_text(i) for i in ("#tGlobal", "#tComp", "#tAcces")] == ["—"] * 3
    assert p.url.endswith("/yacy/") and err == []
    ctx.close()


def test_api_injoignable(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/yacy/", {k: (500, {}) for k in API})
    p.wait_for_selector("#erreur:not([hidden])")
    assert p.inner_text("#etat") == "HORS LIGNE" and err == []
    ctx.close()


def test_demonstration_annoncee_sans_cadre(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/yacy/?demo=1", {})
    p.wait_for_function("document.getElementById('tComp').textContent === '3 / 3'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and p.locator("iframe").count() == 0
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/yacy/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tComp').textContent !== '—'")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
