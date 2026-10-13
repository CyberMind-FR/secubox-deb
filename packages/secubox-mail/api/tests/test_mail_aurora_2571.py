# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2571 — /mail/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[2] / "www" / "mail" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "hybrid-skin" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onchange="):
        assert interdit not in SRC, interdit
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'mail'" in SRC and "demo" in SRC and "embed" in SRC


# (méthode, route) d'écriture de l'ancienne page : tous doivent subsister à l'identique.
ECRITURES = [
    ("POST", "/install"), ("POST", "/webmail/install"), ("POST", "/start"), ("POST", "/stop"), ("POST", "/restart"),
    ("POST", "/webmail/start"), ("POST", "/webmail/stop"),
    ("POST", "/dkim/setup"), ("POST", "/spam/enable"), ("POST", "/spam/disable"), ("POST", "/grey/enable"),
    ("POST", "/grey/disable"), ("POST", "/av/enable"), ("POST", "/av/disable"),
    ("POST", "/spam/setup"), ("POST", "/grey/setup"), ("POST", "/av/setup"),
    ("POST", "/maildir/reconcile"), ("POST", "/sieve/enable"), ("POST", "/antivirus/on"), ("POST", "/antivirus/off"),
    ("POST", "/ssl/renew"), ("POST", "/ssl/setup"), ("POST", "/acme/issue"), ("POST", "/backup"),
    ("POST", "/user"), ("POST", "/user/password"), ("POST", "/alias"), ("POST", "/settings"),
    ("POST", "/user/repair/"), ("DELETE", "/user/"), ("DELETE", "/alias/"),
]


def test_routes_d_ecriture_identiques_a_l_ancienne_page():
    for methode, route in ECRITURES:
        assert re.search(r"'%s',\s*'%s" % (methode, re.escape(route)), SRC), (methode, route)
    # route qui n'a jamais existé côté API
    assert "/external/status" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"module": "mail", "domain": "exemple.test", "user_count": 2, "storage": "412M", "running": True, "installed": True,
          "ports": {"25": True, "587": True, "465": True, "143": True, "993": True, "110": False, "995": False},
          "components": {"mail_server": {"name": "mail", "installed": True, "running": True, "ip": "192.0.2.10"},
                         "webmail": {"name": "webmail", "installed": True, "running": True, "port": 80}}}
ACCESS = {"domain": "exemple.test", "mail_server": "mail.exemple.test", "webmail": {"url": "https://webmail.exemple.test", "local_url": "http://192.0.2.11:80"},
          "apps": {"thunderbird": "https://autoconfig.exemple.test/mail/config-v1.1.xml", "outlook": "https://autodiscover.exemple.test/a.xml"}}
API = {
    "/status": (200, STATUS), "/access": (200, ACCESS),
    "/ssl": (200, {"installed": True, "type": "acme", "status": "valid", "days_remaining": 71}),
    "/users": (200, {"users": [{"email": "alice@exemple.test", "size": "210M"}, {"email": "bob@exemple.test", "size": "5M"}], "count": 2}),
    "/aliases": (200, {"aliases": [{"alias": "info@exemple.test", "target": "alice@exemple.test"}], "count": 1}),
    "/dkim/record": (200, {"record": "default._domainkey IN TXT (\"v=DKIM1\")"}),
    "/spam/status": (200, {"installed": True, "enabled": True, "via": "rspamd"}),
    "/av/status": (200, {"installed": True, "enabled": False, "running": False}),
    "/socle/status": (200, {"maildir": True, "mail_location": "maildir:~/Maildir", "sieve": True, "antivirus": "inactif"}),
    "/settings": (200, {"domain": "exemple.test", "hostname": "mail", "mail_ip": "192.0.2.10", "webmail_port": 80}),
    "/logs": (200, {"logs": ["ligne un", "ligne deux"]}),
}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif : " + d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "mail":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/mail", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(chemin, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/mail/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/mail/", API)
    p.wait_for_selector("#bUsers tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tBoites", "#tStock", "#tDomaine", "#tCert", "#tPorts")] == ["2", "412M", "exemple.test", "71 j", "5/7"]
    assert p.inner_text("#etat") == "EN MARCHE"
    # DKIM publié + antispam actif + ClamAV inactif ; le greylisting n'est pas mesurable
    assert p.inner_text("#tProt") == "2/3"
    assert "alice@exemple.test" in p.inner_text("#bUsers") and "info@exemple.test" in p.inner_text("#bAlias")
    # le lien webmail mène là où il le dit, jamais à l'adresse locale
    assert p.get_attribute("#webmailUrl", "href") == "https://webmail.exemple.test/"
    assert p.inner_text("#webmailUrl") == p.get_attribute("#webmailUrl", "href")
    assert "mail.exemple.test:993" in p.inner_text("#imapUrl")
    assert err == []
    ctx.close()


def test_donnees_d_api_jamais_interpretees_comme_du_html(navigateur):
    mauvais = {**API, "/users": (200, {"users": [{"email": "<img src=x onerror=window.pwn=1>@e.test", "size": "1M"}]}),
               "/access": (200, {**ACCESS, "webmail": {"url": "javascript:window.pwn=1"}})}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/mail/", mauvais)
    p.wait_for_selector("#bUsers tr td.mono", state="attached")
    assert p.evaluate("window.pwn") is None and p.locator("#bUsers img").count() == 0
    assert not p.get_attribute("#webmailUrl", "href") and err == []
    ctx.close()


def test_supprimer_une_boite_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/mail/", API)
    p.click("#o-boites"); p.wait_for_selector("#bUsers tr td.act")
    p.locator("#bUsers tr").first.get_by_text("Supprimer").click()
    assert p.is_visible("#conf") and "alice@exemple.test" in p.inner_text("#confTexte")
    assert not [a for a in appels if a[0] == "DELETE"]          # pas encore : il faut confirmer
    p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('fait')")
    assert ("DELETE", "/user/alice%40exemple.test", None) in appels
    # annuler n'envoie rien
    n = len(appels)
    p.click("#o-alias"); p.locator("#bAlias tr").first.get_by_text("Supprimer").click(); p.click("#confNon")
    assert len([a for a in appels if a[0] == "DELETE"]) == 1 and not p.is_visible("#conf") and err == []
    ctx.close()


def test_creer_une_boite_et_changer_un_mot_de_passe_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/mail/", API)
    p.click("#o-boites"); p.click("#addUser")
    p.fill("#fUser [name=email]", "carol@exemple.test"); p.fill("#fUser [name=password]", "S3cret!")
    p.click("#fUser button[type=submit]")
    p.wait_for_function("document.getElementById('retour').textContent.includes('créée')")
    assert json.loads([a for a in appels if a[0] == "POST" and a[1] == "/user"][0][2]) == {"email": "carol@exemple.test", "password": "S3cret!"}
    assert "S3cret!" not in p.inner_text("body")
    p.locator("#bUsers tr").first.get_by_text("Mot de passe").click()
    assert p.input_value("#fPwd [name=email]") == "alice@exemple.test"
    p.fill("#fPwd [name=password]", "N0uveau!"); p.click("#fPwd button[type=submit]")
    p.wait_for_function("document.getElementById('retour').textContent.includes('changé')")
    assert json.loads([a for a in appels if a[1] == "/user/password"][0][2]) == {"email": "alice@exemple.test", "password": "N0uveau!"}
    assert err == []
    ctx.close()


def test_alias_reglages_et_acme_envoient_les_memes_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/mail/", API)
    p.click("#o-alias"); p.click("#addAlias")
    p.fill("#fAlias [name=alias]", "a@exemple.test"); p.fill("#fAlias [name=target]", "b@exemple.test"); p.click("#fAlias button[type=submit]")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Alias créé')")
    assert json.loads([a for a in appels if a[1] == "/alias" and a[0] == "POST"][0][2]) == {"alias": "a@exemple.test", "target": "b@exemple.test"}
    p.click("#o-reglages"); p.wait_for_function("document.querySelector('#fReglages [name=domain]').value === 'exemple.test'")
    p.click("#fReglages button[type=submit]")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Réglages')")
    assert json.loads([a for a in appels if a[1] == "/settings" and a[0] == "POST"][0][2]) == {"domain": "exemple.test", "hostname": "mail", "mail_ip": "192.0.2.10", "webmail_port": 80}
    p.click("#o-actions"); p.click("#fAcme button[type=submit]")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Let’s Encrypt')")
    assert json.loads([a for a in appels if a[1] == "/acme/issue"][0][2]) == {"email": None}
    assert err == []
    ctx.close()


def test_arret_et_desactivation_demandent_confirmation(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/mail/", API)
    p.wait_for_selector("#bArreter:not([hidden])"); p.click("#bArreter")
    assert p.is_visible("#conf") and not [a for a in appels if a[1] == "/stop"]
    p.click("#confOui"); p.wait_for_function("document.getElementById('retour').textContent.includes('Arrêt')")
    assert ("POST", "/stop", None) in appels
    p.locator("#prot .ligne").nth(1).get_by_text("Désactiver").click()
    assert not [a for a in appels if a[1] == "/spam/disable"]
    p.click("#confOui"); p.wait_for_function("document.getElementById('retour').textContent.includes('antispam')")
    assert ("POST", "/spam/disable", None) in appels and err == []
    ctx.close()


def test_socle_charge_et_bascule_maildir_confirmee(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/mail/", API)
    p.click("#o-socle"); p.wait_for_function("document.getElementById('sSieve').textContent === 'actif'")
    assert p.inner_text("#sMaildir") == "Maildir"
    p.click("#sReconcile"); assert not [a for a in appels if a[1] == "/maildir/reconcile"]
    p.click("#confOui"); p.wait_for_function("document.getElementById('retour').textContent.includes('Maildir')")
    assert ("POST", "/maildir/reconcile", None) in appels and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/mail/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "Session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tBoites", "#tStock", "#tDomaine", "#tCert", "#tProt", "#tPorts")] == ["—"] * 6
    assert "/login.html" in p.get_attribute("#session a", "href") and err == []
    assert p.evaluate("location.pathname") == "/mail/"        # plus de redirection brutale vers la connexion
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/mail/?demo=1", {})
    p.wait_for_selector("#bUsers tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#o-boites"); p.locator("#bUsers tr").first.get_by_text("Réparer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    p.locator("#bUsers tr").first.get_by_text("Supprimer").click(); p.click("#confOui")
    p.click("#o-socle"); p.click("#sSieveOn"); p.click("#o-reglages"); p.click("#fReglages button[type=submit]")
    assert appels == [] and err == []
    ctx.close()


def test_tableaux_vides_et_installation(navigateur):
    pas = {**API, "/status": (200, {**STATUS, "running": False, "installed": False,
                                    "components": {"mail_server": {"installed": False, "running": False}, "webmail": {"installed": False, "running": False}}})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/mail/", pas)
    p.wait_for_selector("#installPan:not([hidden])")
    assert p.inner_text("#etat") == "NON INSTALLÉ"
    p.click("#fInstall button[type=submit]")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Installation')")
    assert ("POST", "/install", None) in appels and ("POST", "/webmail/install", None) in appels and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/mail/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bUsers tr td.mono", state="attached")
    for t in ("boites", "alias", "externe", "journaux", "reglages", "actions", "socle"):
        p.click("#o-" + t)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
