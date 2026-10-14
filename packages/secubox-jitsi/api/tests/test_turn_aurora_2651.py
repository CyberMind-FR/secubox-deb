# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2651 — /turn/ au profil Aurora : test statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[2] / "composants" / "turn" / "www" / "turn" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "hybrid-dark" not in SRC and "crt-light" not in SRC and "crt-engine" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onsubmit="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'turn'" in SRC and "demo" in SRC and "embed" in SRC


def test_routes_et_corps_identiques_a_l_ancienne_page():
    for ecriture in ("ecrire('POST', '/' + action)", "ecrire('POST', '/users', { username, password })",
                     "ecrire('DELETE', '/users/' + encodeURIComponent(nom))", "ecrire('POST', '/generate_secret')",
                     "ecrire('POST', '/realm', data)", "ecrire('POST', '/credentials', { username, ttl })",
                     "ecrire('POST', '/config', { content: restaurer("):
        assert ecriture in SRC, ecriture
    for action in ("'start'", "'stop'", "'restart'"):
        assert "service(" + action in SRC
    for lecture in ("'/status'", "'/stats'", "'/access'", "'/sessions'", "'/users'", "'/config'", "'/logs?lines='"):
        assert lecture in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "Bearer" in SRC and "try {" in SRC


def test_le_secret_partage_n_est_jamais_affiche():
    assert "setItem" not in SRC
    assert "secret').type" not in SRC and "$('secret').type" not in SRC     # l'ancienne page démasquait le secret
    assert SRC.count('type="password"') >= 2 and 'id="secret" type="password"' in SRC
    assert "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


CONF = "# coturn\nlisten=1\nstatic-auth-secret=SECRET-QUI-NE-DOIT-JAMAIS-APPARAITRE\nuser=bob:MOTDEPASSE\nrealm=turn.example.org\n"
STATUS = {"service": {"active": True, "enabled": True, "pid": 42, "uptime_seconds": 3700}, "realm": "turn.example.org", "listening_port": "3478",
          "tls_port": "5349", "min_port": "49152", "max_port": "65535", "config_exists": True, "users_count": 2}
STATS = {"active_sessions": 0, "udp_connections": 3, "tcp_connections": 1, "total_allocations": 12, "auth_failures": 5}
ACCESS = {"endpoints": [{"name": "STUN UDP", "url": "stun:turn.example.org:3478"}, {"name": "TURNS TLS", "url": "turns:turn.example.org:5349"}]}
SESSIONS = {"sessions": [{"client_ip": "198.51.100.9", "client_port": "5000", "protocol": "udp", "local_addr": "192.0.2.1:3478", "state": "ESTAB"},
                         {"client_ip": "203.0.113.4", "client_port": "6000", "protocol": "tcp", "local_addr": "192.0.2.1:3478", "state": "LISTEN"}], "count": 2}
USERS = {"users": [{"username": "alice", "created": 1760000000}, {"username": "<b>x</b>", "created": 1760000100}]}
CREDS = {"username": "1760086400:webrtc", "password": "mdp-temporaire", "ttl": 86400, "expires": 1760086400, "realm": "turn.example.org",
         "turn_urls": ["turn:turn.example.org:3478"], "stun_urls": ["stun:turn.example.org:3478"]}
API = {"/status": (200, STATUS), "/stats": (200, STATS), "/access": (200, ACCESS), "/sessions": (200, SESSIONS), "/users": (200, USERS),
       "/config": (200, {"content": CONF, "parsed": {}}), "/logs": (200, {"lines": ["ligne un", "<b>ligne deux</b>"]}),
       "/generate_secret": (200, {"secret": "NOUVEAU-SECRET-HEX"}), "/credentials": (200, CREDS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels, dialogues = [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (dialogues.append(d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "turn":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/turn", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        if chemin.startswith("/users/") and r.request.method == "DELETE":
            statut, corps = 200, {"success": True}
        else:
            statut, corps = routes.get(chemin, (200, {"success": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/turn/**", api)
    p.goto(url)
    p.dialogues = dialogues
    return ctx, p, erreurs, appels


def posts(appels):
    return [a for a in appels if a[0] != "GET"]


def test_tuiles_tableaux_et_listes_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/turn/", API)
    p.wait_for_function("document.getElementById('tUdp').textContent !== '—'")
    assert p.inner_text("#etat") == "EN MARCHE" and p.inner_text("#tSvc") == "EN MARCHE"
    assert p.inner_text("#tSess") == "0"                                   # 0 est une mesure
    assert [p.inner_text(i) for i in ("#tUdp", "#tTcp", "#tAlloc", "#tAuth", "#tUsers")] == ["3", "1", "12", "5", "2"]
    assert p.inner_text("#tPorts") == "3478 · 5349" and "1 h" in p.inner_text("#iUp")
    assert p.locator("#lEp .ep").count() == 2 and p.locator("#bSess tr").count() == 2
    assert p.get_attribute("#cAuth", "title") and p.get_attribute("#cSvc", "title")
    p.click("#o-users")
    assert p.locator("#bUsers tr").count() == 2 and "<b>x</b>" in p.inner_text("#bUsers") and p.locator("#bUsers b").count() == 0
    assert err == [] and not posts(appels)
    ctx.close()


def test_jeton_sbx_token_en_bearer(navigateur):
    ctx = navigateur.new_context(viewport={"width": 1300, "height": 900})
    ctx.add_init_script("localStorage.setItem('sbx_token', 'jeton-de-test')")
    p = ctx.new_page()
    entetes = []

    def route(r, *_):
        url = r.request.url
        if "/api/v1/turn/" in url:
            entetes.append(r.request.headers.get("authorization"))
            r.fulfill(status=200, content_type="application/json", body=json.dumps(STATUS))
        elif url.rstrip("/").endswith("/turn"):
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=200, content_type="application/javascript", body="")
    p.route("http://sbx.test/**", route)
    p.goto("http://sbx.test/turn/")
    p.wait_for_function("document.getElementById('tUsers').textContent !== '—'")
    assert entetes and all(v == "Bearer jeton-de-test" for v in entetes)
    ctx.close()


def test_filtre_des_sessions(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/turn/", API)
    p.wait_for_function("document.getElementById('bSess').children.length === 2")
    p.click("#o-sessions")
    p.fill("#fSess", "listen")
    assert p.locator("#bSess tr").count() == 1 and "203.0.113.4" in p.inner_text("#bSess")
    p.fill("#fSess", "zzz")
    assert "ne correspond" in p.inner_text("#bSess") and err == []
    ctx.close()


def test_arreter_et_redemarrer_demandent_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/turn/", API)
    p.wait_for_function("!document.getElementById('bStop').disabled")
    p.click("#bStop")
    assert p.is_visible("#conf") and "coupés" in p.inner_text("#confTexte") and not posts(appels)
    p.click("#confNon")
    assert not p.is_visible("#conf") and not posts(appels)
    p.click("#bStop")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rSvc').textContent.includes('arrêté')")
    p.click("#bRestart")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rSvc').textContent.includes('redémarré')")
    p.click("#bStart")
    p.wait_for_function("document.getElementById('rSvc').textContent.includes('démarré')")
    assert [(a[0], a[1]) for a in posts(appels)] == [("POST", "/stop"), ("POST", "/restart"), ("POST", "/start")]
    assert p.dialogues == [] and err == []
    ctx.close()


def test_ajout_et_suppression_d_utilisateur(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/turn/", API)
    p.click("#o-users")
    p.fill("#nUser", "client")
    p.fill("#nPass", "pw-1234")
    p.click("#fUser button[type=submit]")
    p.wait_for_function("document.getElementById('rUser').textContent.includes('ajouté')")
    assert json.loads([a for a in appels if a[1] == "/users" and a[0] == "POST"][0][2]) == {"username": "client", "password": "pw-1234"}
    p.locator("#bUsers tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rUser').textContent.includes('supprimé')")
    assert [a[1] for a in appels if a[0] == "DELETE"] == ["/users/alice"]
    assert p.dialogues == [] and err == []
    ctx.close()


def test_secret_genere_reste_masque_et_realm_enregistre(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/turn/", API)
    p.click("#o-users")
    p.click("#genSecret")
    p.wait_for_function("document.getElementById('secret').value !== ''")
    assert p.get_attribute("#secret", "type") == "password" and "NOUVEAU-SECRET-HEX" not in p.inner_text("body")
    p.fill("#realm", "turn.autre.example")
    p.click("#fRealm button[type=submit]")
    assert "invalidera" in p.inner_text("#confTexte") or "cesseront" in p.inner_text("#confTexte")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rRealm').textContent.includes('enregistré')")
    assert json.loads([a for a in appels if a[1] == "/realm"][0][2]) == {"realm": "turn.autre.example", "secret": "NOUVEAU-SECRET-HEX"}
    assert p.input_value("#secret") == "" and err == []
    ctx.close()


def test_configuration_secrets_masques_et_restaures_a_l_enregistrement(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/turn/", API)
    p.click("#o-config")
    p.wait_for_function("document.getElementById('editeur').value !== ''")
    texte = p.input_value("#editeur")
    assert "SECRET-QUI-NE-DOIT-JAMAIS-APPARAITRE" not in texte and "MOTDEPASSE" not in texte
    assert "static-auth-secret=••••••••(masqué)" in texte and "realm=turn.example.org" in texte
    p.click("#confSave")
    assert not [a for a in appels if a[1] == "/config" and a[0] == "POST"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rConf').textContent.includes('enregistrée')")
    envoye = json.loads([a for a in appels if a[1] == "/config" and a[0] == "POST"][0][2])
    assert envoye == {"content": CONF}                                       # octet pour octet, secrets d'origine conservés
    # une valeur retapée est envoyée telle quelle
    p.fill("#editeur", texte.replace("static-auth-secret=••••••••(masqué)", "static-auth-secret=neuf"))
    p.click("#confSave")
    p.click("#confOui")
    p.wait_for_function("document.querySelectorAll('#rConf').length && document.getElementById('rConf').textContent.includes('enregistrée')")
    dernier = json.loads([a for a in appels if a[1] == "/config" and a[0] == "POST"][-1][2])["content"]
    assert "static-auth-secret=neuf" in dernier and "user=bob:MOTDEPASSE" in dernier
    assert "SECRET-QUI-NE-DOIT-JAMAIS-APPARAITRE" not in p.inner_text("body") and err == []
    ctx.close()


def test_journaux_en_texte_brut(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/turn/", API)
    p.click("#o-config")
    p.wait_for_function("document.getElementById('journal').textContent.includes('ligne un')")
    assert "<b>ligne deux</b>" in p.inner_text("#journal") and p.locator("#journal b").count() == 0
    assert any(a[1] == "/logs" for a in appels) and err == []
    ctx.close()


def test_identifiants_temporaires(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/turn/", API)
    p.fill("#credUser", "visio")
    p.fill("#credTtl", "3600")
    p.click("#fCred button[type=submit]")
    p.wait_for_selector("#credRes:not([hidden])")
    assert json.loads([a for a in appels if a[1] == "/credentials"][0][2]) == {"username": "visio", "ttl": 3600}
    assert p.inner_text("#cPass") == "mdp-temporaire" and "turn:turn.example.org:3478" in p.inner_text("#cTurn")
    assert p.is_visible("#copieIce") and err == []
    ctx.close()


def test_echec_d_identifiants_est_annonce(navigateur):
    routes = {**API, "/credentials": (200, {"error": "No static-auth-secret configured"})}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/turn/", routes)
    p.click("#fCred button[type=submit]")
    p.wait_for_function("document.getElementById('rCred').textContent.includes('static-auth-secret')")
    assert not p.is_visible("#credRes") and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/turn/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE" and "session requise" in p.inner_text("#session")
    assert [p.inner_text(i) for i in ("#tSvc", "#tSess", "#tUdp", "#tTcp", "#tAlloc", "#tAuth", "#tUsers", "#tPorts")] == ["—"] * 8
    assert p.url.endswith("/turn/") and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/turn/?demo=1", {})
    p.wait_for_function("document.getElementById('tUdp').textContent === '4'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#bRestart")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rSvc').textContent.includes('inerte')")
    p.click("#o-users")
    p.fill("#nUser", "x")
    p.fill("#nPass", "y")
    p.click("#fUser button[type=submit]")
    p.wait_for_function("document.getElementById('rUser').textContent.includes('inerte')")
    p.click("#o-config")
    p.wait_for_function("document.getElementById('editeur').value.includes('realm=')")
    assert "demo-sans-valeur" not in p.input_value("#editeur")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/turn/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tUdp').textContent !== '—'")
    for onglet in ("o-sessions", "o-users", "o-config", "o-tableau"):
        p.click("#" + onglet)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), onglet
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
