# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2681 — /releases/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "composants" / "release" / "www" / "releases" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r"<script src=", SRC) == []          # le menu est injecté dynamiquement
    assert "'/shared/sidebar.js'" in SRC and "EMBED || DEMO" in SRC
    assert "hybrid-dark" not in SRC and "hybrid-skin" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'releases'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_et_corps_a_l_identique():
    for r in ("lire('/evolutions')", "ecrire('/' + act, { evo_id: evo })", "ecrire('/publish', { artifacts: artefacts, notes: notes })",
              "ecrire('/assign', { box_did: box, ring: anneau })", "const API = '/api/v1/release'"):
        assert r in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer ' + t" in SRC
    assert "setItem" not in SRC and "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as e:  # pragma: no cover
            pytest.skip(str(e))
        yield b
        b.close()


EVOS = {"evolutions": [{"evo_id": "evo-a", "ring": "published"}, {"evo_id": "evo-b", "ring": "internal"},
                       {"evo_id": "evo-c", "ring": "draft"}, {"evo_id": "evo-d", "ring": "draft"}]}
API = {"/evolutions": (200, EVOS)}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    if jeton:
        ctx.add_init_script("localStorage.setItem('sbx_token','%s')" % jeton)
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif " + d.type), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="application/javascript", body="")
        elif chemin.rstrip("/") == "releases":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/release", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (200, {"ok": True}) if r.request.method != "GET" else (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/release/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableau_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/releases/", API, jeton="jt-test")
    p.wait_for_selector("#bEvo tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tTotal", "#tPub", "#tInt", "#tDraft")] == ["4", "1", "1", "2"]
    assert p.inner_text("#etat") == "EN LIGNE"
    assert p.locator("#bEvo tr").count() == 4
    assert appels[0][0] == "GET" and appels[0][3] == "Bearer jt-test"
    assert p.get_attribute("#tTotal >> xpath=..", "title")
    assert err == []
    ctx.close()


def test_filtre_et_recherche_cote_client(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/releases/", API)
    p.wait_for_selector("#bEvo tr td.mono", state="attached")
    p.select_option("#fAnneau", "draft")
    assert p.locator("#bEvo tr").count() == 2
    p.select_option("#fAnneau", ""); p.fill("#rech", "evo-b")
    assert p.locator("#bEvo tr").count() == 1
    p.fill("#rech", "zzz")
    assert "ne correspond" in p.inner_text("#bEvo")
    assert err == []
    ctx.close()


def test_promouvoir_et_retrograder_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/releases/", API)
    p.wait_for_selector("#bEvo tr td.mono", state="attached")
    p.locator("#bEvo tr").nth(1).get_by_text("Promouvoir").click()
    p.wait_for_function("document.getElementById('rEvo').textContent.includes('Promue : evo-b')")
    p.locator("#bEvo tr").nth(2).get_by_text("Rétrograder").click()
    p.wait_for_function("document.getElementById('rEvo').textContent.includes('Rétrogradée : evo-c')")
    posts = [(a[1], a[2]) for a in appels if a[0] == "POST"]
    assert ("/promote", '{"evo_id":"evo-b"}') in posts and ("/demote", '{"evo_id":"evo-c"}') in posts
    assert err == []
    ctx.close()


def test_publier_envoie_artifacts_et_notes_et_json_invalide(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/releases/", API)
    p.wait_for_selector("#bEvo tr td.mono", state="attached")
    p.fill("#pubArtefacts", "pas du json"); p.click("#btnPub")
    assert "JSON invalide" in p.inner_text("#rPub") and not [a for a in appels if a[0] == "POST"]
    p.fill("#pubArtefacts", '["a.deb"]'); p.fill("#pubNotes", "n1"); p.click("#btnPub")
    p.wait_for_function("document.getElementById('rPub').textContent.includes('publiée')")
    assert ("POST", "/publish", '{"artifacts":["a.deb"],"notes":"n1"}') in [a[:3] for a in appels]
    assert p.input_value("#pubArtefacts") == ""
    ctx.close()


def test_assigner_et_box_did_requis(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/releases/", API)
    p.wait_for_selector("#bEvo tr td.mono", state="attached")
    p.click("#btnAss")
    assert "box_did requis" in p.inner_text("#rAss") and not [a for a in appels if a[0] == "POST"]
    p.fill("#assBox", "did:plc:abc"); p.select_option("#assAnneau", "internal"); p.click("#btnAss")
    p.wait_for_function("document.getElementById('rAss').textContent.includes('assigné')")
    assert ("POST", "/assign", '{"box_did":"did:plc:abc","ring":"internal"}') in [a[:3] for a in appels]
    ctx.close()


def test_erreur_d_api_affichee_dans_la_page(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/releases/", {**API, "/promote": (400, {"detail": "evo inconnue"})})
    p.wait_for_selector("#bEvo tr td.mono", state="attached")
    p.locator("#bEvo tr").first.get_by_text("Promouvoir").click()
    p.wait_for_function("document.getElementById('rEvo').textContent.includes('evo inconnue')")
    assert p.is_visible("#rEvo.ko")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/releases/", {"/evolutions": (401, {"detail": "jeton requis"})})
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tTotal", "#tPub", "#tInt", "#tDraft")] == ["—"] * 4 and err == []
    ctx.close()


def test_service_arrete_hors_ligne(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/releases/", {"/evolutions": (502, {})})
    p.wait_for_selector("#erreur:not([hidden])")
    assert p.inner_text("#etat") == "HORS LIGNE" and p.inner_text("#tTotal") == "—" and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/releases/?demo=1", {})
    p.wait_for_selector("#bEvo tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bEvo tr").first.get_by_text("Promouvoir").click()
    p.wait_for_function("document.getElementById('rEvo').textContent.includes('inerte')")
    p.fill("#pubArtefacts", "[]"); p.click("#btnPub")
    p.wait_for_function("document.getElementById('rPub').textContent.includes('inerte')")
    assert appels == [] and err == [] and not p.is_visible("#sidebar")
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/releases/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bEvo tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
