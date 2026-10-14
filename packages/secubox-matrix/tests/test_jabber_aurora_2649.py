# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2649 — /jabber/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "composants/jabber/www/jabber/index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-" not in SRC and "fonts.googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onsubmit="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'jabber'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer ' + t" in SRC


def test_aucun_secret_ni_stockage():
    assert "setItem" not in SRC and "Math.random" not in SRC
    assert "password" in SRC and "uPass').value = ''" in SRC and "localStorage" in SRC and "sbx_token" in SRC   # le mot de passe est vidé après envoi


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "jabber":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/jabber", 1)[1]
        appels.append((r.request.method, chemin, r.request.post_data))
        cle = chemin.split("?")[0]
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, routes.get(cle, (404, {})))
        else:
            statut, corps = routes.get(cle, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/jabber/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


STATUS = {"installed": True, "running": True, "users": 2, "hosts": ["chat.test"], "c2s_port": 5222, "s2s_port": 5269}
USERS = {"users": [{"username": "alice", "domain": "chat.test", "jid": "alice@chat.test"}, {"username": "bob", "domain": "chat.test", "jid": "bob@chat.test"}]}
HOSTS = {"hosts": [{"domain": "chat.test", "enabled": True, "registration": False}, {"domain": "<b>x</b>.test", "enabled": False, "registration": True}]}
API = {"/status": (200, STATUS), "/users": (200, USERS), "/hosts": (200, HOSTS), "/logs?lines=200": (200, {"logs": ["ligne un", "ligne deux"]})}
URL = "http://sbx.test/jabber/"


def test_routes_methodes_et_corps_a_l_identique():
    for r in ("'POST', '/install?domain='", "'POST', '/' + action", "'POST', '/users', { username:", "domain: $('uDom').value, password:",
              "'POST', '/hosts', { domain:", "enable_registration:", "'DELETE', '/users/'", "'DELETE', '/hosts/'", "/logs?lines=200",
              "'start'", "'stop'", "'restart'", "'reload'"):
        assert r in SRC


def test_tuiles_listes_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, API)
    p.wait_for_selector("#lUsers .elt")
    assert [p.inner_text(i) for i in ("#tSvc", "#tUsers", "#tHosts", "#tC2s", "#tS2s")] == ["Actif", "2", "1", "5222", "5269"]
    assert p.inner_text("#etat") == "ACTIF" and "alice@chat.test" in p.inner_text("#lUsers")
    assert p.is_disabled("#btnStart") and not p.is_disabled("#btnStop")
    p.click("#oHosts")
    assert "<b>x</b>.test" in p.inner_text("#lHosts") and p.locator("#lHosts b").count() == 0
    assert p.get_attribute("#oHosts", "aria-selected") == "true" and p.get_attribute("#oUsers", "aria-selected") == "false"
    assert err == []
    ctx.close()


def test_creer_un_utilisateur_envoie_le_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#lUsers .elt")
    p.fill("#uNom", "carol"); p.select_option("#uDom", "chat.test"); p.fill("#uPass", "secret123")
    p.click("#btnUser")
    p.wait_for_function("document.getElementById('rUser').textContent.includes('créé')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/users"][0]
    assert json.loads(post[2]) == {"username": "carol", "domain": "chat.test", "password": "secret123"}
    assert p.input_value("#uPass") == "" and err == []
    ctx.close()


def test_creer_un_domaine_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#lUsers .elt"); p.click("#oHosts")
    p.fill("#hDom", "nouveau.test"); p.check("#hReg"); p.click("#btnHost")
    p.wait_for_function("document.getElementById('rHost').textContent.includes('ajouté')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/hosts"][0]
    assert json.loads(post[2]) == {"domain": "nouveau.test", "enable_registration": True}
    ctx.close()


def test_suppression_utilisateur_avec_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#lUsers .elt")
    p.locator("#lUsers .elt").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#lUsers .elt").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rUser').textContent.includes('supprimé')")
    assert ("DELETE", "/users/alice%40chat.test", None) in appels
    ctx.close()


def test_annuler_ne_supprime_rien_et_domaine(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#lUsers .elt"); p.click("#oHosts")
    p.locator("#lHosts .elt").first.get_by_text("Supprimer").click()
    p.locator("#lHosts .elt").first.get_by_text("Annuler").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#lHosts .elt").first.get_by_text("Supprimer").click()
    p.locator("#lHosts .elt").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rHost').textContent.includes('supprimé')")
    assert ("DELETE", "/hosts/chat.test", None) in appels
    ctx.close()


def test_actions_de_service_et_journaux(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#lUsers .elt")
    p.click("#btnRestart")
    p.wait_for_function("document.getElementById('rSvc').textContent.includes('redémarré')")
    assert ("POST", "/restart", None) in appels
    p.click("#oLogs")
    p.wait_for_function("document.getElementById('journal').textContent.includes('ligne deux')")
    assert any(a[1] == "/logs?lines=200" for a in appels) and err == []
    ctx.close()


def test_non_installe_propose_l_installation(navigateur):
    routes = {"/status": (200, {"installed": False, "running": False, "users": 0, "hosts": [], "c2s_port": 5222, "s2s_port": 5269})}
    ctx, p, err, appels = ouvre(navigateur, URL, routes)
    p.wait_for_selector("#pInstall:not([hidden])")
    assert p.inner_text("#etat") == "NON INSTALLÉ" and p.is_hidden("#principal")
    p.fill("#instDomaine", "chat.neuf.test"); p.click("#btnInstall")
    p.wait_for_function("document.getElementById('rInstall').textContent.includes('installé')")
    assert ("POST", "/install?domain=chat.neuf.test", None) in appels and err == []
    ctx.close()


def test_service_arrete_listes_non_lues(navigateur):
    routes = {"/status": (200, {**STATUS, "running": False, "users": 0})}
    ctx, p, _, appels = ouvre(navigateur, URL, routes)
    p.wait_for_selector("#principal:not([hidden])")
    assert p.inner_text("#tSvc") == "Arrêté" and p.inner_text("#tUsers") == "—"
    assert not [a for a in appels if a[1] in ("/users", "/hosts")]
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, URL, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tUsers", "#tHosts", "#tC2s", "#tS2s")] == ["—"] * 4 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_selector("#lUsers .elt")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#btnRestart")
    p.wait_for_function("document.getElementById('rSvc').textContent.includes('inerte')")
    p.fill("#uNom", "x"); p.fill("#uPass", "123456"); p.click("#btnUser")
    p.wait_for_function("document.getElementById('rUser').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#lUsers .elt")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
