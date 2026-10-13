# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2571 — /users/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "users" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif_ni_secret():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "hybrid-dark" not in SRC and "hybrid-skin" not in SRC and "crt-engine" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'users'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "localStorage.setItem" not in SRC and "sessionStorage" not in SRC and "document.cookie" not in SRC
    # jamais de mot de passe provisoire affiché
    assert "mot_de_passe" not in SRC


def test_routes_d_ecriture_a_l_identique():
    attendues = [
        "appel('POST', API, '/user',", "appel('PUT', API, '/user/' + encodeURIComponent(nom),", "'/password', { password: mdp }",
        "appel('DELETE', API, '/user/' + encodeURIComponent(nom))", "/totp/disable", "'/services/tout'", "'/password/reinitialiser'",
        "'/services/' + encodeURIComponent(svc) + '/' + encodeURIComponent(act)", "appel('POST', API, '/import', fd, true)",
        "appel('DELETE', API, '/session/' + encodeURIComponent(id))", "appel('POST', API, '/sessions/revoke-all')",
        "appel('POST', AUTH, '/settings', { otp_lan: valeur })", "'/admin/demandes/' + encodeURIComponent(x.did) + '/' + verbe",
    ]
    for a in attendues:
        assert a in SRC, a
    # routes de lecture
    for r in ("'/status'", "'/services'", "'/users'", "'/sessions'", "'/settings', AUTH", "'/admin/personnes', SBX", "'/admin/appareils', SBX", "'/admin/demandes', SBX", "'/export'"):
        assert r in SRC, r
    # ancienne redirection vers une page de connexion inexistante
    assert "'/login'" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
USERS = {"users": [
    {"username": "admin", "email": "admin@example.org", "enabled": True, "totp_enabled": True, "services": ["nextcloud"], "created": "2026-05-02T09:12:00"},
    {"username": "jdupont", "email": "jdupont@example.org", "enabled": False, "totp_enabled": False, "services": [], "created": "2026-08-19T14:30:00"}], "total": 2}
SERVICES = {"services": {"nextcloud": {"running": True}, "gitea": {"running": False}, "email": {"running": True}}}
SESSIONS = {"sessions": [
    {"id": "s-cur", "username": "admin", "email": "admin@example.org", "ip": "192.0.2.10", "user_agent": "Firefox", "created_at": NOW - 600, "expires_at": "2026-10-14T10:00:00", "current": True},
    {"id": "s-autre", "username": "sbx-aaaa", "email": "", "ip": "198.51.100.5", "user_agent": "Companion", "created_at": NOW - 60, "expires_at": "2026-10-14T11:00:00", "current": False}], "total": 2}
PERSONNES = {"personnes": [{"user_uuid": "a1b2c3d4-0000", "pseudo": "gandalf", "tier": "free", "status": "active", "roles": ["member"], "appareils": 2, "liens": {"nextcloud": ["gandalf"]}}]}
APPAREILS = {"appareils": {"sbx-aaaa": {"pseudo": "gandalf", "appareil": "Téléphone", "etat": "acceptee", "revoque": False}}}
DEMANDES = {"en_attente": [{"did": "did:sbx:x1", "nom": "Sam", "appareil": "Tablette", "message": "", "email": "", "demandee_le": NOW - 100, "empreinte": "aaaa bbbb cccc"}], "closes": [], "revoques": []}
REGLAGES = {"otp_lan": "facultatif", "otp_wan": "obligatoire", "require_admin_totp": False}
ROUTES = {
    ("GET", "/api/v1/users/status"): (200, {"user_count": 2, "service_count": 3}),
    ("GET", "/api/v1/users/services"): (200, SERVICES),
    ("GET", "/api/v1/users/users"): (200, USERS),
    ("GET", "/api/v1/users/sessions"): (200, SESSIONS),
    ("GET", "/api/v1/auth/settings"): (200, REGLAGES),
    ("GET", "/api/v1/sbxid/admin/personnes"): (200, PERSONNES),
    ("GET", "/api/v1/sbxid/admin/appareils"): (200, APPAREILS),
    ("GET", "/api/v1/sbxid/admin/demandes"): (200, DEMANDES),
}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "users":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get((r.request.method, chemin), (404, {}) if r.request.method == "GET" else (200, {"success": True, "ok": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/users/", ROUTES)
    p.wait_for_selector("#bComptes tr td small", state="attached")
    assert [p.inner_text(i) for i in ("#tComptes", "#tServices", "#tPersonnes", "#tDem", "#tSess", "#tOtp")] == ["2", "2", "1", "1", "2", "Facultatif"]
    assert p.inner_text("#etat") == "EN LIGNE" and "admin@example.org" in p.inner_text("#bComptes") and "DÉSACTIVÉ" in p.inner_text("#bComptes")
    assert p.inner_text("#sServices") == "sur 3 gérés"
    # un seul compte a le 2FA : un seul bouton de réinitialisation
    assert p.locator("#bComptes").get_by_text("Réinitialiser le 2FA").count() == 1
    # la date de session est en secondes : jamais 1970
    p.click("#o-sessions")
    assert "1970" not in p.inner_text("#bSess") and "CETTE SESSION" in p.inner_text("#bSess") and "gandalf · Téléphone" in p.inner_text("#bSess")
    assert p.locator("#bSess").get_by_text("Révoquer").count() == 1
    p.click("#o-sbx")
    assert "gandalf" in p.inner_text("#bSbx") and "2 appareils" in p.inner_text("#bSbx")
    assert err == []
    ctx.close()


def test_supprimer_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/users/", ROUTES)
    p.wait_for_selector("#bComptes tr td small", state="attached")
    p.locator("#bComptes tr").nth(1).get_by_text("Supprimer").click()
    assert p.is_visible("#conf") and "jdupont" in p.inner_text("#confTexte")
    assert not [a for a in appels if a[0] == "DELETE"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rComptes').textContent.includes('supprimé')")
    assert ("DELETE", "/api/v1/users/user/jdupont", None) in appels
    ctx.close()


def test_annuler_ne_supprime_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/users/", ROUTES)
    p.wait_for_selector("#bComptes tr td small", state="attached")
    p.locator("#bComptes tr").first.get_by_text("Supprimer").click()
    p.click("#confNon")
    assert not p.is_visible("#conf") and not [a for a in appels if a[0] != "GET"]
    ctx.close()


def test_ajouter_un_compte_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/users/", ROUTES)
    p.wait_for_selector("#cases input", state="attached")
    p.click("#addUser")
    p.fill("#nNom", "zorro"); p.fill("#nMail", "zorro@example.org"); p.fill("#nMdp", "Un-Mot-De-Passe-Long-42")
    p.check("#cases input[value=nextcloud]")
    p.click("#fAjout button[type=submit]")
    p.wait_for_function("document.getElementById('rComptes').textContent.includes('créé')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/api/v1/users/user"][0]
    assert json.loads(post[2]) == {"username": "zorro", "email": "zorro@example.org", "password": "Un-Mot-De-Passe-Long-42", "services": ["nextcloud"], "email_recuperation": None}
    # le mot de passe saisi n'est affiché nulle part
    assert "Un-Mot-De-Passe" not in p.inner_text("body")
    ctx.close()


def test_modifier_envoie_put_et_mot_de_passe(navigateur):
    routes = {**ROUTES, ("GET", "/api/v1/users/user/jdupont"): (200, USERS["users"][1])}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/users/", routes)
    p.wait_for_selector("#bComptes tr td small", state="attached")
    p.locator("#bComptes tr").nth(1).get_by_text("Modifier").click()
    p.wait_for_selector("#pEdit:not([hidden])")
    p.select_option("#eEtat", "true"); p.fill("#eMdp", "Nouveau-Mdp-Solide-77")
    p.click("#fEdit button[type=submit]")
    p.wait_for_function("document.getElementById('rComptes').textContent.includes('mis à jour')")
    put = [a for a in appels if a[0] == "PUT"][0]
    assert put[1] == "/api/v1/users/user/jdupont" and json.loads(put[2]) == {"email": "jdupont@example.org", "enabled": True, "email_recuperation": ""}
    pw = [a for a in appels if a[1].endswith("/jdupont/password")][0]
    assert json.loads(pw[2]) == {"password": "Nouveau-Mdp-Solide-77"}
    ctx.close()


def test_reinitialiser_2fa_et_revoquer_session(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/users/", ROUTES)
    p.wait_for_selector("#bComptes tr td small", state="attached")
    p.get_by_text("Réinitialiser le 2FA").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('rComptes').textContent.includes('Second facteur')")
    assert ("POST", "/api/v1/users/user/admin/totp/disable", None) in appels
    p.click("#o-sessions"); p.locator("#bSess").get_by_text("Révoquer").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('rSess').textContent.includes('révoquée')")
    assert ("DELETE", "/api/v1/users/session/s-autre", None) in appels
    ctx.close()


def test_demande_acceptee_envoie_role_et_personne(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/users/", ROUTES)
    p.wait_for_selector("#bDem tr td.act", state="attached"); p.click("#o-demandes")
    p.locator("#bDem select").nth(0).select_option("a1b2c3d4-0000")
    p.locator("#bDem").get_by_text("Accepter").click()
    p.wait_for_function("document.getElementById('rDem').textContent.includes('rattaché')")
    post = [a for a in appels if a[1] == "/api/v1/sbxid/admin/demandes/did%3Asbx%3Ax1/accepter"][0]
    assert json.loads(post[2]) == {"role": "member", "personne": "a1b2c3d4-0000"}
    ctx.close()


def test_import_lit_created_skipped_errors(navigateur, tmp_path):
    routes = {**ROUTES, ("POST", "/api/v1/users/import"): (200, {"created": ["a", "b"], "skipped": ["c"], "errors": []})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/users/", routes)
    p.wait_for_selector("#bComptes tr td small", state="attached")
    f = tmp_path / "u.json"; f.write_text('{"users": []}')
    p.click("#impUser"); p.set_input_files("#iFichier", str(f)); p.click("#fImport button[type=submit]")
    p.wait_for_function("document.getElementById('rComptes').textContent.includes('Import')")
    assert "2 créé(s), 1 ignoré(s), 0 erreur(s)" in p.inner_text("#rComptes")
    ctx.close()


def test_service_mot_de_passe_jamais_affiche_et_envoi_exige(navigateur):
    detail = {"username": "jdupont", "email": "jdupont@example.org", "email_recuperation": "jd@example.net", "defaut": ["nextcloud"],
              "services": {"nextcloud": {"libelle": "Nextcloud", "existe": False, "disponible": True}}}
    routes = {**ROUTES, ("GET", "/api/v1/users/user/jdupont/services"): (200, detail),
              ("POST", "/api/v1/users/user/jdupont/services/nextcloud/creer"): (200, {"ok": True, "etapes": ["creer"], "mot_de_passe": "SECRET-PROVISOIRE-XYZ", "envoye_a": "jd@example.net"})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/users/", routes)
    p.wait_for_selector("#bComptes tr td small", state="attached")
    p.locator("#bComptes tr").nth(1).get_by_text("Services").click()
    p.wait_for_selector("#sListe .svc")
    p.locator("#sListe").get_by_text("Créer").click()          # sans envoi coché : refusé, aucun appel
    assert "jamais affiché" in p.inner_text("#rSvc") and not [a for a in appels if a[0] == "POST"]
    p.check("#sEnvoyer"); p.locator("#sListe").get_by_text("Créer").click()
    p.wait_for_function("document.getElementById('rSvc').textContent.includes('envoyé à')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert json.loads(post[2]) == {"envoyer": True}
    assert "SECRET-PROVISOIRE-XYZ" not in p.inner_text("body")
    ctx.close()


def test_otp_lan_obligatoire_demande_confirmation(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/users/", {**ROUTES, ("POST", "/api/v1/auth/settings"): (200, {"otp_lan": "obligatoire"})})
    p.wait_for_selector("#bComptes tr td small", state="attached"); p.click("#o-sessions")
    p.click("#otpBascule")
    assert p.is_visible("#conf") and not [a for a in appels if a[0] == "POST"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('tOtp').textContent === 'Obligatoire'")
    assert json.loads([a for a in appels if a[0] == "POST"][0][2]) == {"otp_lan": "obligatoire"}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in ROUTES}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/users/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tComptes", "#tServices", "#tPersonnes", "#tDem", "#tSess", "#tOtp")] == ["—"] * 6 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/users/?demo=1", {})
    p.wait_for_selector("#bComptes tr td small", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bComptes tr").first.get_by_text("Supprimer").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('rComptes').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/users/?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bComptes tr td small", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
