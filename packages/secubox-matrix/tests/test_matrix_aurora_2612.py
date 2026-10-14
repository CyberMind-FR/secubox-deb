# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2612 — /matrix/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "matrix" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-light" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "insertAdjacentHTML"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'matrix'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("'POST', '/config'", "'/users'", "/reset-password?password=", "/federation/block", "/media/purge?before_days=",
              "'/registrations/token'", "'DELETE', '/registrations/token/'", "/install?server_name=", "'/start'", "'/stop'", "'/restart'",
              "/element/install", "'/backup'"):
        assert r in SRC, r
    # corps conservés
    assert "{ username: f.username.value, password: f.password.value, admin: f.admin.checked }" in SRC
    assert "{ server_name: srv }" in SRC
    assert "enable_registration: $('cReg').checked" in SRC and "allow_guest_access: $('cGuest').checked" in SRC and "max_upload_size: $('cUp').value" in SRC
    # routes jamais utilisées par l'ancienne page : pas d'écriture inventée
    for absent in ("/uninstall", "/deactivate", "/bridges", "'DELETE', '/room", "'DELETE', '/users"):
        assert absent not in SRC, absent


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
STATUS = {"container_exists": True, "running": True, "container_ip": "192.0.2.50", "version": "1.99.0", "server_name": "matrix.example.org",
          "synapse_port": 8008, "federation_port": 8448, "disk_usage": "1,8G"}
USERS = {"users": [{"username": "@alice:matrix.example.org", "admin": True, "created": str(NOW - 86400)},
                   {"username": "@bob:matrix.example.org", "admin": False, "created": str(NOW - 3600)}]}
ROOMS = {"rooms": [{"room_id": "!abc:matrix.example.org", "creator": "@alice:matrix.example.org", "public": True}]}
CONFIG = {"server_name": "matrix.example.org", "enable_registration": True, "allow_guest_access": False, "federation_enabled": True, "max_upload_size": "100M"}
FEDST = {"enabled": True, "total_peers": 4, "active_peers": 3}
FEDP = {"peers": [{"destination": "chat.example.net", "retry_last_ts": 0, "retry_interval": 0, "failure_ts": None, "last_successful": True},
                  {"destination": "down.example.net", "retry_last_ts": 1, "retry_interval": 60000, "failure_ts": NOW * 1000, "last_successful": False}], "total": 4}
MEDIA = {"local_media_size_bytes": 5 * 1048576, "local_media_size_mb": 5.0, "remote_media_size_bytes": 10 * 1048576, "remote_media_size_mb": 10.0, "total_size_mb": 15.0}
REG = {"enabled": True, "tokens": [{"token": "SecretTokenABCDEFGH", "uses_allowed": 3, "pending": 1, "completed": 2, "expiry_time": None}]}
LOGS = {"logs": ["ligne un", "GET /sync?access_token=syt_abcdef 200"]}
API = {"/status": (200, STATUS), "/users": (200, USERS), "/rooms": (200, ROOMS), "/config": (200, CONFIG), "/federation/status": (200, FEDST),
       "/federation/peers": (200, FEDP), "/media/stats": (200, MEDIA), "/registrations": (200, REG), "/logs": (200, LOGS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "matrix":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/matrix", 1)[1].split("?")[0]
        appels.append((r.request.method, r.request.url.split("/api/v1/matrix", 1)[1], r.request.post_data))
        statut, corps = routes.get(chemin, (200, {"success": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/matrix/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def attend_chargement(p):
    p.wait_for_selector("#bUsers tr td.mono", state="attached")


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/matrix/", API)
    attend_chargement(p)
    assert [p.inner_text(i) for i in ("#tEtat", "#tVer", "#tDisque", "#tUsers", "#tRooms", "#tFed")] == ["Actif", "1.99.0", "1,8G", "2", "1", "3 / 4"]
    assert p.inner_text("#etat") == "EN LIGNE" and p.inner_text("#kNom") == "matrix.example.org" and p.inner_text("#kIp") == "192.0.2.50"
    assert "@alice:matrix.example.org" in p.inner_text("#bUsers") and "ADMIN" in p.inner_text("#bUsers")
    assert "1970" not in p.inner_text("#bUsers")          # création en secondes, jamais 1970
    assert p.is_checked("#cReg") and not p.is_checked("#cGuest") and p.input_value("#cUp") == "100M"
    assert p.get_attribute("#bOuvrir", "href") == "http://192.0.2.50/"
    p.click("#o-rooms"); assert "!abc:matrix.example.org" in p.inner_text("#bRooms") and "PUBLIC" in p.inner_text("#bRooms")
    p.click("#o-fed"); p.wait_for_selector("#bFed tr td.mono")
    assert "chat.example.net" in p.inner_text("#bFed") and "ACTIF" in p.inner_text("#bFed") and "ÉCHEC" in p.inner_text("#bFed")
    p.click("#o-media"); p.wait_for_function("document.getElementById('mTotal').textContent.includes('15')")
    assert [p.inner_text(i) for i in ("#mLocal", "#mRemote", "#mTotal")] == ["5,0 Mo", "10,0 Mo", "15,0 Mo"]
    p.click("#o-logs"); p.wait_for_function("document.getElementById('journal').textContent.includes('ligne un')")
    assert "syt_abcdef" not in p.inner_text("#journal") and "••••" in p.inner_text("#journal")
    assert err == []
    ctx.close()


def test_jetons_jamais_affiches_et_suppression_confirmee(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/matrix/", {**API, "/registrations/token/SecretTokenABCDEFGH": (200, {"success": True})})
    p.click("#o-reg"); p.wait_for_selector("#bReg tr td.mono")
    assert "SecretTokenABCDEFGH" not in p.inner_text("body") and "Secr" in p.inner_text("#bReg") and "2 / 3" in p.inner_text("#bReg")
    p.get_by_text("Supprimer", exact=True).click()
    assert not [a for a in appels if a[0] == "DELETE"] and "Supprimer le jeton" in p.inner_text("#c-reg")
    p.locator("#c-reg").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('r-reg').textContent.includes('supprimé')")
    assert ("DELETE", "/registrations/token/SecretTokenABCDEFGH", None) in appels
    ctx.close()


def test_creer_utilisateur_envoie_le_meme_corps_et_ne_l_affiche_pas(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/matrix/", API)
    attend_chargement(p)
    p.click("#o-users"); p.click("#addUser")
    p.fill("#fUser [name=username]", "carole"); p.fill("#fUser [name=password]", "motdepasse-test"); p.check("#fUser [name=admin]")
    p.click("#fUser button[type=submit]")
    p.wait_for_function("document.getElementById('r-users').textContent.includes('créé')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/users"][0]
    assert json.loads(post[2]) == {"username": "carole", "password": "motdepasse-test", "admin": True}
    assert "motdepasse-test" not in p.inner_text("body")
    ctx.close()


def test_reinitialiser_le_mot_de_passe_meme_route(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/matrix/", API)
    attend_chargement(p)
    p.click("#o-users"); p.locator("#bUsers tr").first.get_by_text("Réinitialiser").click()
    assert p.input_value("#fMdp [name=cible]") == "@alice:matrix.example.org"
    p.fill("#fMdp [name=password]", "nouveau-mdp-12"); p.click("#fMdp button[type=submit]")
    p.wait_for_function("document.getElementById('r-users').textContent.includes('réinitialisé')")
    assert ("POST", "/users/%40alice%3Amatrix.example.org/reset-password?password=nouveau-mdp-12", None) in appels
    ctx.close()


def test_arret_et_purge_demandent_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/matrix/", API)
    attend_chargement(p)
    p.click("#bStop")
    assert not [a for a in appels if a[1] == "/stop"] and "Arrêter Matrix" in p.inner_text("#c-service")
    p.locator("#c-service").get_by_text("Annuler").click()
    assert not [a for a in appels if a[1] == "/stop"] and not p.is_visible("#c-service")
    p.click("#bStop"); p.locator("#c-service").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('r-service').textContent.includes('arrêté')")
    assert ("POST", "/stop", None) in appels
    p.click("#o-media"); p.fill("#fPurge [name=jours]", "45"); p.click("#fPurge button[type=submit]")
    assert not [a for a in appels if "purge" in a[1]]
    p.locator("#c-media").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('r-media').textContent.includes('Purge')")
    assert ("POST", "/media/purge?before_days=45", None) in appels
    ctx.close()


def test_reglages_et_blocage_et_jeton(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/matrix/", {**API, "/registrations/token": (200, {"success": True, "token": "NouveauJeton123"})})
    attend_chargement(p)
    p.uncheck("#cReg"); p.check("#cGuest"); p.select_option("#cUp", "50M"); p.click("#bConf")
    p.wait_for_function("document.getElementById('r-serveur').textContent.includes('enregistrés')")
    assert json.loads([a for a in appels if a[1] == "/config" and a[0] == "POST"][0][2]) == {"enable_registration": False, "allow_guest_access": True, "max_upload_size": "50M"}
    p.click("#o-fed"); p.click("#addBloc"); p.fill("#fBloc [name=serveur]", "evil.example.net"); p.click("#fBloc button[type=submit]")
    assert not [a for a in appels if a[1] == "/federation/block"]
    p.locator("#c-fed").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('r-fed').textContent.includes('bloqué')")
    assert json.loads([a for a in appels if a[1] == "/federation/block"][0][2]) == {"server_name": "evil.example.net"}
    p.click("#o-reg"); p.fill("#fTok [name=uses]", "5"); p.click("#fTok button[type=submit]")
    p.wait_for_function("document.getElementById('r-reg').textContent.includes('Jeton créé')")
    assert json.loads([a for a in appels if a[1] == "/registrations/token" and a[0] == "POST"][0][2]) == {"uses_allowed": 5}
    assert "NouveauJeton123" not in p.inner_text("body")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/matrix/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tEtat", "#tVer", "#tUsers", "#tRooms", "#tFed")] == ["—"] * 5 and err == []
    ctx.close()


def test_non_installe_propose_l_installation(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/matrix/", {**API, "/status": (200, {"container_exists": False, "running": False})})
    p.wait_for_selector("#zone-install:not([hidden])")
    assert p.inner_text("#etat") == "NON INSTALLÉ" and not p.is_visible("#onglets")
    p.fill("#iNom", "matrix.example.com"); p.click("#bInstall")
    assert not [a for a in appels if "install" in a[1]]
    p.locator("#c-install").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('r-install').textContent.length > 0")
    assert ("POST", "/install?server_name=matrix.example.com", None) in appels and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/matrix/?demo=1", {})
    p.wait_for_selector("#bUsers tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and p.inner_text("#tFed") == "3 / 4"
    p.click("#bStop")
    assert "inerte" in p.inner_text("#r-service")
    p.click("#bStart") if not p.is_disabled("#bStart") else None
    p.click("#o-reg"); p.fill("#fTok [name=uses]", "2"); p.click("#fTok button[type=submit]")
    p.wait_for_function("document.getElementById('r-reg').textContent.includes('inerte')")
    assert appels == [] and err == []
    assert "DemoJeton0001ZzYyXx" not in p.inner_text("body")
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/matrix/?embed=1", API, taille={"width": 420, "height": 800})
    attend_chargement(p)
    for t in ("o-users", "o-fed", "o-media", "o-reg", "o-logs", "o-serveur"):
        p.click("#" + t)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
