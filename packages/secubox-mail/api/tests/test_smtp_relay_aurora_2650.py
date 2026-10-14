# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2650 — /smtp-relay/ au profil Aurora (composant de secubox-mail) : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[2] / "composants" / "smtp-relay" / "www" / "smtp-relay" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    for interdit in ("hybrid-dark", "crt-light", "crt-engine", "fonts.googleapis", "confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onchange="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'smtp-relay'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "document.hidden" in SRC


def test_routes_et_ecritures_a_l_identique():
    assert "const API = '/api/v1/smtp-relay'" in SRC
    for r in ("appel('/status')", "appel('/stats')", "appel('/queue')", "appel('/config')", "'/logs?lines='",
              "'/queue/' + encodeURIComponent(id), { method: 'DELETE' }", "appel('/config', { method: 'POST', body: JSON.stringify(config) })",
              "'/start'", "'/stop'", "'/restart'", "'/queue/flush'", "appel('/test', { method: 'POST', body: JSON.stringify({ to, subject, body }) })"):
        assert r in SRC
    for c in ("smarthost:", "port:", "username:", "password:", "from_domain:", "tls:"):
        assert c in SRC


def test_aucun_mot_de_passe_lu_ni_affiche():
    # le champ n'est jamais prérempli depuis la réponse de l'API, et le masque ne sert qu'à « conserver l'existant »
    assert "cPass').value = d.password" not in SRC and ".value = data.password" not in SRC
    assert 'type="password"' in SRC and 'autocomplete="new-password"' in SRC
    assert "setItem" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"running": True, "queue_size": 2, "sent_count": 40, "failed_count": 3, "smarthost": "smtp.exemple.test", "configured": True}
STATS = {"sent": 40, "failed": 3, "queued": 2, "deferred": 2, "bounced": 1}
QUEUE = {"queue": [{"id": "A1B2C3D4E5", "sender": "a@exemple.test", "recipients": [{"address": "b@exemple.test"}, {"address": "c@exemple.test"}],
                    "arrival_time": 1760000000, "message_size": 2048, "reason": "<i>timeout</i>"}], "count": 1}
CONFIG = {"smarthost": "smtp.exemple.test", "port": 465, "username": "relais@exemple.test", "password": "********", "tls": True, "from_domain": "exemple.test"}
API = {"/status": (200, STATUS), "/stats": (200, STATS), "/queue": (200, QUEUE), "/config": (200, CONFIG),
       "/logs": (200, {"lines": ["ligne un", "ligne deux"], "count": 2})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "smtp-relay":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        complet = r.request.url.split("/api/v1/smtp-relay", 1)[1]
        chemin = complet.split("?")[0]
        appels.append((r.request.method, complet, r.request.post_data, r.request.headers.get("authorization")))
        if r.request.method != "GET":
            statut, corps = routes.get(r.request.method + " " + chemin, routes.get(chemin, (200, {"success": True})) if chemin != "/config" else (200, {"success": True}))
        else:
            statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/smtp-relay/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/smtp-relay/", API)
    p.wait_for_function("document.getElementById('tPostfix').textContent !== '—'")
    assert [p.inner_text(i) for i in ("#tPostfix", "#tConf", "#tFile", "#tEnv", "#tEch", "#tDif")] == ["En marche", "Configuré", "2", "40", "3", "2"]
    assert p.inner_text("#etat") == "EN SERVICE" and p.inner_text("#iHote") == "smtp.exemple.test"
    assert p.is_visible("#btnStop") and not p.is_visible("#btnStart")
    assert err == []
    ctx.close()


def test_file_d_attente_en_texte_et_suppression_confirmee(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/smtp-relay/", {**API, "/queue/A1B2C3D4E5": (200, {"success": True})})
    p.click("#o-file")
    p.wait_for_selector("#bFile tr td.mono", state="attached")
    t = p.inner_text("#bFile")
    assert "A1B2C3D4E5" in t and "b@exemple.test, c@exemple.test" in t and "2,0 Ko" in t and "<i>timeout</i>" in t
    assert p.locator("#bFile i").count() == 0
    p.locator("#bFile tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bFile tr").first.get_by_text("Annuler").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bFile tr").first.get_by_text("Supprimer").click()
    p.locator("#bFile tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rFile').textContent.includes('supprimé')")
    assert ("DELETE", "/queue/A1B2C3D4E5", None) in [a[:3] for a in appels] and err == []
    ctx.close()


def test_configuration_ne_montre_jamais_le_mot_de_passe_et_le_conserve(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/smtp-relay/", API)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.click("#o-config")
    p.wait_for_function("document.getElementById('cHote').value === 'smtp.exemple.test'")
    assert p.input_value("#cPort") == "465" and p.input_value("#cUser") == "relais@exemple.test"
    assert p.input_value("#cPass") == "" and "********" not in p.content().split("<body", 1)[1].split("<script", 1)[0]
    p.fill("#cDom", "autre.test")
    p.click("#btnConf")
    p.wait_for_function("document.getElementById('rConf').textContent.includes('enregistrée')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/config"][0]
    # mot de passe laissé vide et déjà défini : le masque part tel quel (l'API conserve alors l'existant)
    assert json.loads(post[2]) == {"smarthost": "smtp.exemple.test", "port": 465, "username": "relais@exemple.test", "password": "********",
                                    "from_domain": "autre.test", "tls": True}
    assert post[3] == "Bearer jeton-test" and err == []
    ctx.close()


def test_nouveau_mot_de_passe_est_envoye_et_smarthost_obligatoire(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/smtp-relay/", API)
    p.click("#o-config")
    p.wait_for_function("document.getElementById('cHote').value !== ''")
    p.fill("#cPass", "nouveau-secret")
    p.click("#btnConf")
    p.wait_for_function("document.getElementById('rConf').textContent.includes('enregistrée')")
    assert json.loads([a for a in appels if a[0] == "POST" and a[1] == "/config"][0][2])["password"] == "nouveau-secret"
    p.fill("#cHote", "")
    n = len(appels)
    p.click("#btnConf")
    assert "obligatoire" in p.inner_text("#rConf") and len(appels) == n
    ctx.close()


def test_arret_et_redemarrage_demandent_une_confirmation(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/smtp-relay/", API)
    p.wait_for_function("document.getElementById('tPostfix').textContent !== '—'")
    p.click("#btnStop")
    assert p.is_visible("#cnfServ") and not [a for a in appels if a[1] == "/stop"]
    p.click("#cnfNon")
    assert not [a for a in appels if a[1] == "/stop"]
    p.click("#btnStop"); p.click("#cnfOui")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('arrêté')")
    assert ("POST", "/stop", None) in [a[:3] for a in appels]
    p.click("#btnRestart"); p.click("#cnfOui")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('redémarre')")
    assert ("POST", "/restart", None) in [a[:3] for a in appels]
    p.click("#btnFlush")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('Relivraison')")
    assert ("POST", "/queue/flush", None) in [a[:3] for a in appels]
    ctx.close()


def test_courriel_d_essai_et_journaux(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/smtp-relay/", {**API, "/test": (200, {"success": True})})
    p.click("#btnTest")
    p.fill("#tDest", "dest@exemple.test")
    p.click("#btnEnvoi")
    p.wait_for_function("document.getElementById('rTest').textContent.includes('envoyé')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/test"][0]
    assert json.loads(post[2]) == {"to": "dest@exemple.test", "subject": "SecuBox SMTP Relay Test", "body": "This is a test email from SecuBox SMTP Relay."}
    p.click("#o-logs")
    p.wait_for_function("document.getElementById('journal').textContent.includes('ligne deux')")
    assert ("GET", "/logs?lines=100") in [a[:2] for a in appels] and err == []
    ctx.close()


def test_envoi_d_essai_refuse_affiche_le_motif(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/smtp-relay/", {**API, "/test": (400, {"detail": "Smarthost not configured"})})
    p.click("#btnTest"); p.fill("#tDest", "dest@exemple.test"); p.click("#btnEnvoi")
    p.wait_for_function("document.getElementById('rTest').textContent.includes('Smarthost not configured')")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/smtp-relay/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tPostfix", "#tConf", "#tFile", "#tEnv", "#tEch", "#tDif")] == ["—"] * 6
    assert not p.is_visible("#btnStart") and not p.is_visible("#btnStop") and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/smtp-relay/?demo=1", {})
    p.wait_for_function("document.getElementById('tPostfix').textContent !== '—'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#btnFlush")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('inerte')")
    p.click("#o-file")
    p.wait_for_selector("#bFile tr td.mono", state="attached")
    p.locator("#bFile tr").first.get_by_text("Supprimer").click()
    p.locator("#bFile tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rFile').textContent.includes('inerte')")
    p.click("#o-config")
    p.wait_for_function("document.getElementById('cHote').value !== ''")
    p.click("#btnConf")
    p.wait_for_function("document.getElementById('rConf').textContent.includes('inerte')")
    p.click("#o-logs")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/smtp-relay/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tPostfix').textContent !== '—'")
    for o in ("#o-file", "#o-config", "#o-logs", "#o-apercu"):
        p.click(o)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
