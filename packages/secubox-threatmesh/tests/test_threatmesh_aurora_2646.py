# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2646 — /threatmesh/ au profil Aurora : page statique + vrai navigateur, API simulée (adresses RFC 5737)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "threatmesh" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-" not in SRC and "googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'threatmesh'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_a_l_identique():
    for r in ("'/status'", "'/peers'", "'/decisions?min_consensus=1&limit=40'", "'/feeds/refresh'", "'/mesh/gossip'", "method: 'POST'"):
        assert r in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer '" in SRC
    assert "DELETE" not in SRC and "'PUT'" not in SRC


def test_aucun_secret_ni_serie_inventee():
    assert "setItem" not in SRC and "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"mode": "sovereign", "node": "sb-test", "capi": False, "feeds": {"feed:a": 100, "feed:b": 50}, "feed_total": 150,
          "mesh": {"mesh:sb-2": 20}, "mesh_total": 20, "peers": 1, "sources": {"feed:a": 100, "feed:b": 50, "mesh:sb-2": 20, "manual": 2}}
PEERS = {"node": "sb-test", "peers": [{"id": "sb-2", "name": "Deux", "address": "10.10.0.2"}]}
DECISIONS = [{"value": "198.51.100.1", "consensus": 1, "sources": "feed:a"},
             {"value": "203.0.113.9", "consensus": 3, "sources": "feed:a,feed:b,<b>x</b>"}]
API = {"/status": (200, STATUS), "/peers": (200, PEERS), "/decisions": (200, DECISIONS)}
URL = "http://sbx.test/threatmesh/"


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    if jeton:
        p.add_init_script("localStorage.setItem('sbx_token', '%s')" % jeton)
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "threatmesh":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/threatmesh", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (200, {"ok": True}) if r.request.method != "GET" else (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/threatmesh/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_tableau_et_jeton_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API, jeton="jeton-test")
    p.wait_for_selector("#bAgg tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tTotal", "#tFeeds", "#tMesh", "#tMode", "#tNoeud")] == ["172", "150", "20", "sovereign", "sb-test"]
    assert p.inner_text("#etat") == "SOUVERAIN"
    lignes = p.locator("#bAgg tr")
    assert lignes.first.inner_text().startswith("203.0.113.9")        # tri par consensus décroissant
    assert "<b>x</b>" in p.inner_text("#bAgg") and p.locator("#bAgg b").count() == 0
    assert "Deux" in p.inner_text("#pairs") and "feed:a" in p.inner_text("#sources")
    assert {a[2] for a in appels} == {"Bearer jeton-test"}
    assert err == []
    ctx.close()


def test_filtre_cote_client(navigateur):
    ctx, p, _, _ = ouvre(navigateur, URL, API)
    p.wait_for_selector("#bAgg tr td.mono", state="attached")
    p.fill("#filtre", "198.51")
    assert p.locator("#bAgg tr").count() == 1 and "198.51.100.1" in p.inner_text("#bAgg")
    ctx.close()


def test_actions_post_a_l_identique(navigateur):
    routes = {**API, "/mesh/gossip": (200, {"pushed": 1, "peers": 1, "shared": 5})}
    ctx, p, _, appels = ouvre(navigateur, URL, routes, jeton="t")
    p.wait_for_selector("#bAgg tr td.mono", state="attached")
    p.click("#btnFeeds")
    p.wait_for_function("document.getElementById('rActions').textContent.includes('lancée')")
    p.click("#btnGossip")
    p.wait_for_function("document.getElementById('rActions').textContent.includes('1/1 pairs')")
    assert ("POST", "/feeds/refresh", "Bearer t") in appels and ("POST", "/mesh/gossip", "Bearer t") in appels
    ctx.close()


def test_action_refusee_sans_session(navigateur):
    ctx, p, _, _ = ouvre(navigateur, URL, {**API, "/feeds/refresh": (401, {"detail": "jeton requis"})})
    p.wait_for_selector("#bAgg tr td.mono", state="attached")
    p.click("#btnFeeds")
    p.wait_for_function("document.getElementById('rActions').textContent.includes('requise')")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, URL, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tTotal", "#tFeeds", "#tMesh", "#tMode", "#tNoeud")] == ["—"] * 5 and err == []
    ctx.close()


def test_service_arrete_hors_ligne(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, {})
    p.wait_for_function("document.getElementById('etat').textContent === 'HORS LIGNE'")
    assert not p.is_hidden("#erreur") and p.inner_text("#tTotal") == "—" and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_selector("#bAgg tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#btnFeeds")
    p.wait_for_function("document.getElementById('rActions').textContent.includes('inerte')")
    p.click("#btnGossip")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bAgg tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
