# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2681 — /centers/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "centers" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r"<script src=", SRC) == []
    assert "'/shared/sidebar.js'" in SRC and "EMBED || DEMO" in SRC
    assert "hybrid-dark" not in SRC and "hybrid-skin" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'centers'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_et_corps_a_l_identique():
    for r in ("lire('/centers/ownership')", "lire('/centers')", "lire('/centers/proposals')", "'/centers/effective/' + encodeURIComponent(scope)",
              "ecrire('/centers/revoke', { grant_id: grantId })", "ecrire('/centers/grant', { center_did: centerDid, scope: scope, layer: layer })",
              "ecrire('/centers/proposal/accept', { center_did: centerDid, scope: scope, layer: layer })", "const API = '/api/v1/annuaire'"):
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


A, B = "did:plc:centre-a-doc-0123456789abcdef", "did:plc:centre-b-doc-fedcba9876543210"
OWN = {"ownership": [{"scope": "firewall", "layer": "baseline", "owner": A, "grant_id": "g1"},
                     {"scope": "firewall", "layer": "override", "owner": B, "grant_id": "g2"},
                     {"scope": "dns", "layer": "baseline", "owner": A, "grant_id": "g3"}]}
CEN = {"centers": [{"center_did": A, "grants": [{"grant_id": "g1", "scope": "firewall", "layer": "baseline"}, {"grant_id": "g3", "scope": "dns", "layer": "baseline"}]},
                   {"center_did": B, "grants": [{"grant_id": "g2", "scope": "firewall", "layer": "override"}]}]}
PRO = {"proposals": [{"publisher": B, "scope": "wireguard", "layer": "override", "reason": "no-grant"}]}
API = {"/centers/ownership": (200, OWN), "/centers": (200, CEN), "/centers/proposals": (200, PRO)}


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
        elif chemin.rstrip("/") == "centers":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/annuaire", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (200, {"ok": True}) if r.request.method != "GET" else (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/annuaire/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def prete(p):
    p.wait_for_selector("#bMat tr td.sc", state="attached")


def test_tuiles_matrice_centres_et_propositions(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/centers/", API, jeton="jt-test")
    prete(p)
    assert [p.inner_text(i) for i in ("#tCentres", "#tOctrois", "#tScopes", "#tProp")] == ["2", "3", "2", "1"]
    assert p.inner_text("#etat") == "PANNEAU ACTIF"
    assert p.locator("#bMat tr").count() == 2
    assert "box-local" in p.inner_text("#bMat tr:nth-child(2)") and "— vide —" in p.inner_text("#bMat tr:nth-child(1)")  # dns : override vide
    assert "wireguard" in p.inner_text("#lProp") and "no-grant" in p.inner_text("#lProp")
    assert p.locator("#lCentres li").count() == 2
    assert all(a[3] == "Bearer jt-test" for a in appels) and len(appels) == 3
    assert p.get_attribute("#tOctrois >> xpath=..", "title")
    assert err == []
    ctx.close()


def test_revocation_demande_confirmation_puis_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/centers/", API)
    prete(p)
    p.locator("#bMat tr").first.get_by_text("Révoquer").first.click()
    assert not [a for a in appels if a[0] == "POST"]
    p.locator("#bMat tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rMat').textContent.includes('révoqué')")
    assert ("POST", "/centers/revoke", '{"grant_id":"g3"}') in [a[:3] for a in appels]
    assert err == []
    ctx.close()


def test_annuler_la_revocation_n_ecrit_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/centers/", API)
    prete(p)
    p.locator("#bMat tr").first.get_by_text("Révoquer").first.click()
    p.locator("#bMat tr").first.get_by_text("Annuler").click()
    assert not [a for a in appels if a[0] == "POST"]
    ctx.close()


def test_nouvel_octroi_envoie_le_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/centers/", API)
    prete(p)
    p.fill("#gScope", "nftables"); p.select_option("#gCalque", "override"); p.fill("#gDid", "did:plc:xyz")
    assert "nftables" in p.inner_text("#bMat")          # le scope saisi apparaît dans la matrice
    p.click("#btnOctroi")
    p.wait_for_function("document.getElementById('rOctroi').textContent.includes('accordé')")
    assert ("POST", "/centers/grant", '{"center_did":"did:plc:xyz","scope":"nftables","layer":"override"}') in [a[:3] for a in appels]
    assert p.input_value("#gScope") == "" and err == []
    ctx.close()


def test_accepter_une_proposition_avec_confirmation(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/centers/", API)
    prete(p)
    p.locator("#lProp").get_by_role("button", name="Accepter").click()
    assert not [a for a in appels if a[0] == "POST"]
    p.locator("#lProp").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rProp').textContent.includes('acceptée')")
    assert ("POST", "/centers/proposal/accept", json.dumps({"center_did": B, "scope": "wireguard", "layer": "override"}, separators=(",", ":"))) in [a[:3] for a in appels]
    assert err == []
    ctx.close()


def test_erreur_d_ecriture_affichee(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/centers/", {**API, "/centers/grant": (400, {"detail": "layer local interdit"})})
    prete(p)
    p.fill("#gScope", "x"); p.fill("#gDid", "did:plc:y"); p.click("#btnOctroi")
    p.wait_for_function("document.getElementById('rOctroi').textContent.includes('interdit')")
    assert p.is_visible("#rOctroi.ko")
    ctx.close()


def test_diff_effectif(navigateur):
    routes = {**API, "/centers/effective/firewall": (200, {"scope": "firewall", "status": "ok", "effective": "a = 1", "local": None})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/centers/", routes)
    prete(p)
    p.fill("#eScope", "firewall"); p.click("#btnDiff")
    p.wait_for_function("document.getElementById('eStatut').textContent.includes('ok')")
    assert p.inner_text("#eEff") == "a = 1" and p.inner_text("#eLoc") == "(vide)"
    assert ("GET", "/centers/effective/firewall") in [a[:2] for a in appels] and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/centers/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tCentres", "#tOctrois", "#tScopes", "#tProp")] == ["—"] * 4 and err == []
    ctx.close()


def test_service_arrete_hors_ligne(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/centers/", {k: (502, {}) for k in API})
    p.wait_for_selector("#erreur:not([hidden])")
    assert p.inner_text("#etat") == "HORS LIGNE" and p.inner_text("#tOctrois") == "—" and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/centers/?demo=1", {})
    prete(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.fill("#gScope", "x"); p.fill("#gDid", "did:plc:y"); p.click("#btnOctroi")
    p.wait_for_function("document.getElementById('rOctroi').textContent.includes('inerte')")
    p.locator("#bMat tr").first.get_by_text("Révoquer").first.click()
    p.locator("#bMat tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rMat').textContent.includes('inerte')")
    assert appels == [] and err == [] and not p.is_visible("#sidebar")
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/centers/?embed=1", API, taille={"width": 420, "height": 800})
    prete(p)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
