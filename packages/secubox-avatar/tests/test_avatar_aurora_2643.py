# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2643 — /avatar/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "avatar" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-" not in SRC and "fonts.googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "Math.random"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'avatar'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_et_methodes_a_l_identique():
    for r in ("'/identities'", "'/services'", "'/vault/list'", "ecrire('PUT', '/identity/' + id", "ecrire('POST', '/identity'",
              "ecrire('DELETE', '/identity/' + EDIT", "ecrire('POST', '/sync', { identity_id: id }", "ecrire('DELETE', cheminVault(",
              "'/vault/' + encodeURIComponent(p)", "API + '/avatar/upload'", "fd.append('identity_id'", "fd.append('file'",
              "const API = '/api/v1/avatar'"):
        assert r in SRC, r
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer ' + t" in SRC
    assert "try { return localStorage" in SRC


def test_aucun_secret_et_aucune_ecriture_de_stockage():
    assert "setItem" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


IDENTS = {"identities": [
    {"id": "i1", "username": "alice", "display_name": "Alice Test", "email": "alice@example.org", "avatar_url": "/api/v1/avatar/avatar/i1", "services": ["gitea"]},
    {"id": "i2", "username": "bob", "display_name": "Bob Exemple", "email": None, "avatar_url": None, "services": []}]}
SERVICES = {"services": [
    {"id": "gitea", "name": "Gitea", "icon": "git", "enabled": True, "configured": True},
    {"id": "mail", "name": "Courrier", "icon": "mail", "enabled": False, "configured": False}]}
VAULT = {"backups": [
    {"profile": "p1", "domain": "a.example.org", "meta": {"cookie_count": 4}, "saved_at": "2026-10-01T10:00:00"},
    {"profile": "p1", "domain": "b.example.org", "meta": {}, "saved_at": "2026-10-02T10:00:00"},
    {"profile": "p2", "domain": "c.example.org", "meta": {"cookie_count": 2}, "saved_at": "2026-10-03T10:00:00"}]}
API = {"/identities": (200, IDENTS), "/services": (200, SERVICES), "/vault/list": (200, VAULT)}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    if jeton:
        p.add_init_script("localStorage.setItem('sbx_token', %s)" % json.dumps(jeton))
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "avatar":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/avatar", 1)[1].split("?")[0]
        h = r.request.headers
        appels.append((r.request.method, chemin, r.request.post_data, h.get("authorization"), h.get("content-type")))
        statut, corps = routes.get(chemin, (200, {"success": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/avatar/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def charge(p):
    p.wait_for_selector("#lIdent .carte", state="attached")


def test_tuiles_et_listes_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/avatar/", API)
    charge(p)
    assert [p.inner_text(i) for i in ("#tTotal", "#tAvatars", "#tServices", "#tPersonas", "#tSites", "#tCookies")] == ["2", "1", "1", "2", "3", "6"]
    assert "partiel" in p.inner_text("#tCookiesS")
    assert p.inner_text("#etat") == "2 IDENTITÉS"
    t = p.inner_text("#lIdent")
    assert "Alice Test" in t and "@bob" in t and "alice@example.org" in t and "gitea" in t
    assert p.get_attribute("#lIdent img", "src") == "/api/v1/avatar/avatar/i1"
    p.click("#o-services")
    t = p.inner_text("#lServices")
    assert "Gitea" in t and "ACTIVÉ" in t and "DÉSACTIVÉ" in t and "NON CONFIGURÉ" in t
    p.click("#o-personas")
    t = p.inner_text("#lVault")
    assert "p1" in t and "a.example.org (4 c)" in t and "b.example.org (— c)" in t
    assert [a[:2] for a in appels if a[0] != "GET"] == [] and err == []
    ctx.close()


def test_infobulles_de_definition_sur_les_tuiles(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/avatar/", API)
    charge(p)
    assert p.locator(".tuile").count() == 6
    assert all(len(t) > 20 for t in p.eval_on_selector_all(".tuile", "e => e.map(x => x.title)"))
    ctx.close()


def test_creation_envoie_le_meme_corps_et_les_memes_en_tetes(navigateur):
    routes = {**API, "/identity": (200, {"success": True, "identity": {"id": "i3"}})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/avatar/", routes, jeton="jeton-test")
    charge(p)
    p.click("#nouvelle")
    p.fill("#fUser", "carol"); p.fill("#fNom", "Carol Test"); p.fill("#fMail", "carol@example.org")
    p.check("#coches input[value=gitea]")
    assert p.is_disabled("#coches input[value=mail]")
    p.click("#bSave")
    p.wait_for_selector("#voileIdent", state="hidden")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/identity"][0]
    assert json.loads(post[2]) == {"username": "carol", "display_name": "Carol Test", "email": "carol@example.org", "services": ["gitea"]}
    assert post[3] == "Bearer jeton-test" and post[4] == "application/json"
    assert err == []
    ctx.close()


def test_modification_put_et_depot_d_avatar(navigateur, tmp_path):
    routes = {**API, "/identity/i2": (200, {"success": True, "identity": {"id": "i2"}}), "/avatar/upload": (200, {"success": True})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/avatar/", routes)
    charge(p)
    p.locator("#lIdent .carte").nth(1).click()
    assert p.input_value("#fUser") == "bob" and p.input_value("#fMail") == ""
    png = tmp_path / "a.png"
    png.write_bytes(bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da63f8ffff3f0005fe02fea7d6050000000049454e44ae426082"))
    p.set_input_files("#fichier", str(png))
    p.wait_for_selector("#apercu img")
    p.fill("#fNom", "Bob Modifié")
    p.click("#bSave")
    p.wait_for_selector("#voileIdent", state="hidden")
    put = [a for a in appels if a[0] == "PUT"][0]
    assert put[1] == "/identity/i2" and json.loads(put[2])["display_name"] == "Bob Modifié" and json.loads(put[2])["email"] is None
    up = [a for a in appels if a[1] == "/avatar/upload"][0]
    assert up[0] == "POST" and up[4].startswith("multipart/form-data")
    assert err == []
    ctx.close()


def test_erreur_de_creation_affichee_dans_la_page(navigateur):
    routes = {**API, "/identity": (400, {"detail": "Username already exists"})}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/avatar/", routes)
    charge(p)
    p.click("#nouvelle"); p.fill("#fUser", "alice"); p.fill("#fNom", "Alice"); p.click("#bSave")
    p.wait_for_selector("#rForm.ko")
    assert "Username already exists" in p.inner_text("#rForm") and p.is_visible("#voileIdent")
    ctx.close()


def test_suppression_d_identite_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/avatar/", API)
    charge(p)
    p.locator("#lIdent .carte").first.click()
    p.click("#bSupp")
    assert not [a for a in appels if a[0] == "DELETE"]
    p.click("#bAnnul")
    p.locator("#lIdent .carte").first.click()
    p.click("#bSupp"); p.click("#bSuppOui")
    p.wait_for_selector("#voileIdent", state="hidden")
    assert [a[:2] for a in appels if a[0] == "DELETE"] == [("DELETE", "/identity/i1")]
    ctx.close()


def test_oubli_d_un_site_et_d_un_persona(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/avatar/", API)
    charge(p)
    p.click("#o-personas")
    p.locator("#lVault .persona").first.get_by_text("Oublier", exact=True).first.click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#lVault .persona").first.get_by_text("Annuler").click()
    p.locator("#lVault .persona").first.get_by_text("Tout oublier").click()
    p.locator("#lVault .persona").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rVault').textContent.includes('oublié')")
    dels = [a[:2] for a in appels if a[0] == "DELETE"]
    assert dels == [("DELETE", "/vault/p1/a.example.org"), ("DELETE", "/vault/p1/b.example.org")]
    assert err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/avatar/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tTotal", "#tAvatars", "#tServices", "#tPersonas", "#tSites", "#tCookies")] == ["—"] * 6
    assert err == [] and p.url.startswith("http://sbx.test/avatar/")     # plus de redirection brutale vers /login.html
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/avatar/?demo=1", {})
    charge(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#nouvelle"); p.fill("#fUser", "x-demo"); p.fill("#fNom", "X"); p.click("#bSave")
    p.wait_for_function("document.getElementById('rForm').textContent.includes('inerte')")
    p.click("#bAnnul"); p.click("#o-personas")
    p.locator("#lVault .persona").first.get_by_text("Tout oublier").click()
    p.locator("#lVault .persona").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rVault').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_donnees_de_l_api_jamais_interpretees_comme_html(navigateur):
    idents = {"identities": [{"id": "x", "username": "<img src=x onerror=window.pwn=1>", "display_name": "<b>Gras</b>", "email": None,
                              "avatar_url": "https://externe.example/x.png", "services": ["<i>s</i>"]}]}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/avatar/", {**API, "/identities": (200, idents)})
    charge(p)
    assert "<b>Gras</b>" in p.inner_text("#lIdent") and p.locator("#lIdent b").count() == 0
    assert p.locator("#lIdent img").count() == 0                       # adresse externe refusée
    assert p.evaluate("window.pwn") is None and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    for url in ("http://sbx.test/avatar/?embed=1", "http://sbx.test/avatar/?demo=1&embed=1"):
        ctx, p, err, _ = ouvre(navigateur, url, API, taille={"width": 420, "height": 800})
        charge(p)
        for onglet in ("services", "personas", "identites"):
            p.click("#o-" + onglet)
            assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
        p.click("#nouvelle")
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
        assert not p.is_visible("#sidebar") and err == []
        ctx.close()
