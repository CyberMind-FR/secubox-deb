# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2687 — page de connexion /login.html au profil Aurora : statique + vrai navigateur, API simulée (jetons factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "login.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert not re.search(r"<script[^>]+src=", SRC)                      # aucun script externe, pas de /shared/sidebar.js
    assert not re.search(r"<link[^>]+href=\"https?:", SRC)               # plus de police distante
    assert "fonts.googleapis" not in SRC and "sidebar" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onsubmit="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower() and "100vh" in SRC               # pleine page de connexion : pas une page encadrée


def test_appels_d_api_a_l_identique():
    for r in ("/api/v1/auth/login'", "/api/v1/auth/login/mfa", "/api/v1/auth/set-password", "/api/v1/auth/totp/enroll",
              "/api/v1/auth/totp/confirm", "/api/v1/auth/auth/logout", "/api/v1/sbxid/elevation/echange",
              "/api/v1/hub/status", "/api/v1/portal/theme", "/__console/jeton"):
        assert r in SRC, r
    assert "JSON.stringify({username: _username, password: password})" in SRC
    assert "JSON.stringify({code: code})" in SRC and "JSON.stringify({new_password: pw})" in SRC
    assert "'Authorization': 'Bearer ' + _mfaToken" in SRC and "'Authorization': 'Bearer ' + _enrollToken" in SRC
    assert "'Authorization': 'Bearer ' + _setupToken" in SRC
    assert "credentials: 'include'" in SRC
    for cle in ("sbx_token", "secubox_token", "secubox_user", "secubox_role"):
        assert f"localStorage.setItem('{cle}'" in SRC


def test_champs_pour_gestionnaires_de_mots_de_passe():
    for auto in ('autocomplete="username"', 'autocomplete="current-password"', 'autocomplete="new-password"',
                 'autocomplete="one-time-code"'):
        assert auto in SRC
    assert SRC.count('autocomplete="new-password"') == 2
    assert re.search(r'<input type="password" id="password"[^>]*(?<!required)>', SRC) and \
        "required" not in re.search(r'<input type="password" id="password"[^>]*>', SRC).group(0)   # #1709 : champ vide permis
    assert 'minlength="10"' in SRC


def test_validation_de_redirection_conservee_et_durcie():
    assert r"/^\/(?![\/\\])/.test(p)" in SRC
    assert "u0000-" in SRC          # caractères de contrôle refusés (« /<TAB>/hote » deviendrait « //hote »)


def test_pas_de_mode_demonstration():
    assert "demo" not in SRC.lower()


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


JETON = "jeton-factice-session"


def ouvre(navigateur, chemin, routes=None, taille=None, init=None):
    """Ouvre la page sur http://sbx.test ; routes = {(METHODE, chemin API): (statut, corps)}."""
    routes = routes or {}
    ctx = navigateur.new_context(viewport=taille or {"width": 1000, "height": 800})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    if init:
        p.add_init_script(init)

    def fichier(r, *_):
        url = r.request.url
        chemin_req = url.split("http://sbx.test", 1)[1].split("?")[0].split("#")[0]
        if chemin_req == "/login.html":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        elif chemin_req.startswith("/api/"):
            appels.append((r.request.method, chemin_req, r.request.post_data, dict(r.request.headers)))
            statut, corps = routes.get((r.request.method, chemin_req), (404, {"detail": "absent"}))
            r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
        else:
            r.fulfill(status=200, content_type="text/html", body="<html><body>destination</body></html>")
    p.route("http://sbx.test/**", fichier)
    p.goto("http://sbx.test" + chemin)
    return ctx, p, erreurs, appels


def saisir(p, user="alice", pw="un-mot-de-passe-factice"):
    p.fill("#username", user)
    p.fill("#password", pw)
    p.click("#btn-submit")


def stocke(p):
    return p.evaluate("[localStorage.getItem('sbx_token'),localStorage.getItem('secubox_token'),"
                      "localStorage.getItem('secubox_user'),localStorage.getItem('secubox_role')]")


def test_rendu_et_champs(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "/login.html", {("GET", "/api/v1/portal/theme"): (200, {"name": "Mochabin", "badge": "GK2"})})
    p.wait_for_function("document.getElementById('logo-sub').textContent.includes('Mochabin')")
    assert p.is_visible("#login-form") and not p.is_visible("#mfa-form") and not p.is_visible("#setup-form")
    assert p.get_attribute("#username", "autocomplete") == "username" and p.get_attribute("#username", "name") == "username"
    assert p.get_attribute("#password", "autocomplete") == "current-password" and p.get_attribute("#password", "type") == "password"
    assert p.inner_text("#device-badge") == "GK2" and err == []
    ctx.close()


def test_connexion_reussie_jeton_stocke_et_redirection_sure(navigateur):
    routes = {("POST", "/api/v1/auth/login"): (200, {"access_token": JETON})}
    ctx, p, err, appels = ouvre(navigateur, "/login.html?redirect=/metablogizer/", routes)
    saisir(p)
    p.wait_for_url("http://sbx.test/metablogizer/")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/api/v1/auth/login"][0]
    assert json.loads(post[2]) == {"username": "alice", "password": "un-mot-de-passe-factice"}
    assert post[3]["content-type"] == "application/json"
    assert stocke(p) == [JETON, JETON, "alice", "admin"]
    assert err == []
    ctx.close()


def test_connexion_sans_redirect_va_a_la_racine(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "/login.html", {("POST", "/api/v1/auth/login"): (200, {"access_token": JETON})})
    saisir(p)
    p.wait_for_url("http://sbx.test/")
    ctx.close()


def test_echec_message_et_pas_de_jeton(navigateur):
    routes = {("POST", "/api/v1/auth/login"): (401, {"detail": "Identifiants refusés"})}
    ctx, p, err, _ = ouvre(navigateur, "/login.html", routes)
    saisir(p)
    p.wait_for_selector("#msg.error")
    assert "Identifiants refusés" in p.inner_text("#msg")
    assert stocke(p) == [None] * 4 and p.is_visible("#login-form") and p.inner_text("#btn-submit") == "Se connecter"
    assert err == []
    ctx.close()


def test_echec_sans_corps_json_message_de_repli(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "/login.html", {("POST", "/api/v1/auth/login"): (500, {})})
    saisir(p)
    p.wait_for_selector("#msg.error")
    assert p.inner_text("#msg") == "Identifiants invalides" and err == []
    ctx.close()


def test_totp_requis_puis_connexion(navigateur):
    routes = {("POST", "/api/v1/auth/login"): (200, {"mfa_required": True, "mfa_token": "mfa-factice"}),
              ("POST", "/api/v1/auth/login/mfa"): (200, {"access_token": JETON})}
    ctx, p, err, appels = ouvre(navigateur, "/login.html?redirect=/soc/", routes)
    saisir(p)
    p.wait_for_selector("#mfa-form.active")
    assert p.get_attribute("#mfa-code", "autocomplete") == "one-time-code"
    assert stocke(p) == [None] * 4                       # pas de jeton avant le second facteur
    p.fill("#mfa-code", " 123456 ")
    p.click("#btn-mfa")
    p.wait_for_url("http://sbx.test/soc/")
    post = [a for a in appels if a[1] == "/api/v1/auth/login/mfa"][0]
    assert json.loads(post[2]) == {"code": "123456"} and post[3]["authorization"] == "Bearer mfa-factice"
    assert stocke(p) == [JETON, JETON, "alice", "admin"] and err == []
    ctx.close()


def test_code_totp_refuse_garde_l_etape(navigateur):
    routes = {("POST", "/api/v1/auth/login"): (200, {"mfa_required": True, "mfa_token": "m"}),
              ("POST", "/api/v1/auth/login/mfa"): (401, {"detail": "Code invalide"})}
    ctx, p, _, _ = ouvre(navigateur, "/login.html", routes)
    saisir(p)
    p.wait_for_selector("#mfa-form.active")
    p.fill("#mfa-code", "000000"); p.click("#btn-mfa")
    p.wait_for_selector("#msg.error")
    assert "Code invalide" in p.inner_text("#msg") and p.input_value("#mfa-code") == "" and stocke(p) == [None] * 4
    p.click("#mfa-form [data-retour]")
    assert p.is_visible("#login-form") and not p.is_visible("#mfa-form")
    ctx.close()


@pytest.mark.parametrize("cible", ["//evil.example/x", "/\\evil.example/x", "https://evil.example/", "javascript:alert(1)",
                                   "/%09/evil.example/x", "/%0a/evil.example/x", "evil.example", "/%0d/evil.example"])
def test_redirection_ouverte_refusee(navigateur, cible):
    routes = {("POST", "/api/v1/auth/login"): (200, {"access_token": JETON})}
    ctx, p, err, _ = ouvre(navigateur, "/login.html?redirect=" + cible.replace("\\", "%5C"), routes)
    saisir(p)
    p.wait_for_url("http://sbx.test/")                     # repli sur la racine, jamais l'hôte étranger
    assert p.evaluate("location.host") == "sbx.test" and err == []
    ctx.close()


def test_redirect_present_efface_le_jeton_perime(navigateur):
    init = "try{localStorage.setItem('sbx_token','vieux');localStorage.setItem('secubox_token','vieux')}catch(e){}"
    ctx, p, _, appels = ouvre(navigateur, "/login.html?redirect=/x/", {}, init=init)
    assert stocke(p)[:2] == [None, None] and p.is_visible("#login-form")
    assert not [a for a in appels if a[1] == "/api/v1/hub/status"]       # pas de rebond complaisant
    ctx.close()


def test_deconnexion_efface_et_termine_la_session(navigateur):
    init = ("try{if(!sessionStorage.getItem('f')){sessionStorage.setItem('f','1');"
            "localStorage.setItem('sbx_token','t1');localStorage.setItem('secubox_user','alice')}}catch(e){}")
    ctx, p, _, appels = ouvre(navigateur, "/login.html?deconnexion=1", {("POST", "/api/v1/auth/auth/logout"): (200, {})}, init=init)
    p.wait_for_function("localStorage.getItem('sbx_token') === null")
    out = [a for a in appels if a[1] == "/api/v1/auth/auth/logout"]
    assert out and out[0][3]["authorization"] == "Bearer t1" and "deconnexion" not in p.url
    assert p.is_visible("#login-form")
    ctx.close()


def test_premiere_configuration_du_mot_de_passe(navigateur):
    routes = {("POST", "/api/v1/auth/login"): (200, {"setup_required": True, "setup_token": "setup-factice"}),
              ("POST", "/api/v1/auth/set-password"): (200, {"ok": True})}
    ctx, p, err, appels = ouvre(navigateur, "/login.html", routes)
    saisir(p, pw="")
    p.wait_for_selector("#setup-form.active")
    p.fill("#setup-pw", "court"); p.fill("#setup-pw2", "court")
    p.evaluate("document.getElementById('setup-form').noValidate = true")
    p.click("#btn-setup")
    assert "10 caractères" in p.inner_text("#msg")
    p.fill("#setup-pw", "nouveau-mdp-factice"); p.fill("#setup-pw2", "different-factice")
    p.click("#btn-setup")
    assert "diffèrent" in p.inner_text("#msg")
    assert not [a for a in appels if a[1] == "/api/v1/auth/set-password"]
    p.fill("#setup-pw2", "nouveau-mdp-factice")
    routes[("POST", "/api/v1/auth/login")] = (200, {"access_token": JETON})
    p.click("#btn-setup")
    p.wait_for_url("http://sbx.test/")
    post = [a for a in appels if a[1] == "/api/v1/auth/set-password"][0]
    assert json.loads(post[2]) == {"new_password": "nouveau-mdp-factice"} and post[3]["authorization"] == "Bearer setup-factice"
    assert stocke(p)[0] == JETON and err == []
    ctx.close()


def test_inscription_totp_codes_de_secours_en_texte(navigateur):
    png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
    routes = {("POST", "/api/v1/auth/login"): (200, {"enrollment_required": True, "enrollment_token": "enr-factice"}),
              ("POST", "/api/v1/auth/totp/enroll"): (200, {"qr_png_b64": png, "secret": "JBSWY3DPEHPK3PXP"}),
              ("POST", "/api/v1/auth/totp/confirm"): (200, {"access_token": JETON, "backup_codes": ["aaaa-1111", "<b>x</b>"]})}
    ctx, p, err, appels = ouvre(navigateur, "/login.html?redirect=/admin/", routes)
    saisir(p)
    p.wait_for_selector("#enroll-form.active")
    assert p.inner_text("#enroll-secret-val") == "JBSWY3DPEHPK3PXP"
    assert p.get_attribute("#enroll-qr", "src").startswith("data:image/png;base64,")
    p.fill("#enroll-code", "654321"); p.click("#btn-enroll")
    p.wait_for_selector("#backup-step.active")
    assert p.locator("#backup-codes code").all_inner_texts() == ["aaaa-1111", "<b>x</b>"]   # texte, jamais du HTML
    assert p.locator("#backup-codes b").count() == 0
    assert stocke(p)[0] == JETON and p.url.endswith("/login.html?redirect=/admin/")       # pas de rebond avant accusé
    p.click("#btn-backup")
    p.wait_for_url("http://sbx.test/admin/")
    conf = [a for a in appels if a[1] == "/api/v1/auth/totp/confirm"][0]
    assert json.loads(conf[2]) == {"code": "654321"} and conf[3]["authorization"] == "Bearer enr-factice" and err == []
    ctx.close()


def test_elevation_efface_le_fragment_et_echange_le_bon(navigateur):
    bon = "A" * 44
    routes = {("POST", "/api/v1/sbxid/elevation/echange"): (200, {"access_token": JETON, "compte": "alice"})}
    ctx, p, err, appels = ouvre(navigateur, "/login.html?redirect=/hall/#elevation=" + bon, routes)
    p.wait_for_url("http://sbx.test/hall/")
    post = [a for a in appels if a[1] == "/api/v1/sbxid/elevation/echange"][0]
    assert json.loads(post[2]) == {"bon": bon} and stocke(p) == [JETON, JETON, "alice", "admin"] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "/login.html", {}, taille={"width": 420, "height": 800})
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth")
    for step in ("setup-form", "mfa-form", "enroll-form", "backup-step"):
        p.evaluate("id => {document.querySelectorAll('.step').forEach(s => s.classList.remove('active')); document.getElementById(id).classList.add('active')}", step)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth"), step
    assert err == []
    ctx.close()
