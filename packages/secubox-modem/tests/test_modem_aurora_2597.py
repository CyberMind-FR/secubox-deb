# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2597 — /modem/ au profil Aurora : test statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "modem" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert re.findall(r'<link[^>]+href="([^"]+)"', SRC) == ["/shared/sidebar-light.css"]
    for ancien in ("hybrid-dark", "crt-engine", "cdn.jsdelivr", "googleapis", "chart.js", "xterm", "js/modem.js"):
        assert ancien not in SRC.lower()
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "sbxVue" in SRC and "onglet: 'modem'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("'POST', '/sms/send'", "'DELETE', '/sms/'", "'POST', '/at/command'", "'POST', '/config'",
              "'/disconnect'", "'/connect'", "'/reset'", "'/power/off'", "'/power/on'", "/at/console"):
        assert r in SRC, r
    # lectures reprises de l'ancienne page
    for r in ("'/status'", "'/info'", "'/signal'", "/signal/history?minutes=60&limit=120", "'/sms'", "'/config'", "'/apn/database'"):
        assert r in SRC, r
    # le PIN de la SIM n'a jamais été manipulé par la page : il ne doit pas l'être maintenant
    assert "pin" not in SRC.lower().replace("pinning", "")


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"connected": True, "state": "connected", "operator_name": "Opérateur Test", "access_technology": "lte", "signal_quality": 64,
          "ip_address": "192.0.2.10", "model": "EC25", "imei": "000000000000000"}
INFO = {"manufacturer": "Quectel", "model": "EC25-EUX", "firmware": "FW1", "imei": "000000000000000", "imsi": "", "meid": ""}
SIGNAL = {"rssi": -70.0, "rsrp": -95.0, "rsrq": -11.0, "sinr": 0.0, "quality_percent": 47, "network_type": "LTE", "timestamp": "2026-10-13T10:00:00"}
HISTO = {"records": [{"timestamp": f"2026-10-13T10:{m:02d}:00", "rssi": -70, "rsrp": -100 + m, "rsrq": -11, "sinr": None if m == 3 else m, "quality_percent": 40 + m, "network_type": "LTE"} for m in range(10)],
         "stats": {"count": 10, "rsrp_avg": -95.5, "rsrp_min": -100, "rsrp_max": -91, "sinr_avg": 0.0}, "period_minutes": 60}
SMS = {"messages": [{"id": "7", "number": "+33639980001", "text": "<b>bonjour</b> `x` '); alert(1)//", "timestamp": "2026-10-13T09:00:00", "direction": "incoming", "state": "received"}], "total": 1}
CONFIG = {"apn": "internet", "user": "u", "ip_type": "ipv4v6", "auth": "none", "auto_connect": True, "has_pin": True}
APNS = {"apns": {"fr": [{"operator": "Orange", "apn": "orange", "user": "orange", "auth": "pap"}], "generic": [{"operator": "1nce", "apn": "iot.1nce.net", "user": "", "auth": "none"}]}}
API = {"/status": (200, STATUS), "/info": (200, INFO), "/signal": (200, SIGNAL), "/signal/history": (200, HISTO), "/sms": (200, SMS),
       "/config": (200, CONFIG), "/apn/database": (200, APNS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels, entetes = [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.add_init_script("window.__dialogues=0;window.alert=window.confirm=window.prompt=()=>{window.__dialogues++;return false}")

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "modem":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/modem", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        entetes.append(r.request.headers.get("authorization"))
        statut, corps = routes.get(chemin, (200, {"success": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/modem/**", api)
    p.add_init_script("try{localStorage.setItem('sbx_token','jeton-factice')}catch(e){}")
    p.goto(url)
    p.entetes = entetes
    return ctx, p, erreurs, appels


def test_tuiles_et_panneaux_viennent_de_l_api_avec_jeton(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/modem/", API)
    p.wait_for_function("document.getElementById('tOp').textContent.includes('Test')")
    assert [p.inner_text(i) for i in ("#tOp", "#tTech", "#tSig", "#tIp")] == ["Opérateur Test", "lte", "64 %", "192.0.2.10"]
    assert p.inner_text("#etat").lower() == "connected" and p.inner_text("#bascule") == "Déconnecter"
    assert p.inner_text("#iFab") == "Quectel" and p.inner_text("#iFw") == "FW1" and p.inner_text("#iImei") == "000000000000000"
    # SINR = 0 est une mesure, pas une absence (l'ancienne page affichait « - » pour 0)
    assert p.inner_text("#sSinr") == "0 dB" and p.inner_text("#sRsrp") == "-95 dBm" and p.inner_text("#sPct") == "47 %"
    assert set(p.entetes) == {"Bearer jeton-factice"}   # l'ancienne page n'envoyait aucun jeton
    assert err == []
    ctx.close()


def test_historique_courbe_et_statistiques(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/modem/", API)
    p.click("#o-signal")
    p.wait_for_selector("#courbe svg")
    assert p.inner_text("#stN") == "10" and p.inner_text("#stRange") == "-100 / -91 dBm" and p.inner_text("#stRsrp") == "-95.5 dBm"
    assert p.locator("#courbe circle").count() == 10
    p.select_option("#metrique", "sinr")
    # la mesure absente (m == 3) coupe la ligne et n'est pas tracée : 9 points
    assert p.locator("#courbe circle").count() == 9 and p.locator("#courbe path.ligne").count() == 2
    assert p.inner_text("#stSinr") == "0.0 dB" and err == []
    ctx.close()


def test_sms_texte_hostile_inerte_et_suppression_confirmee_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/modem/", API)
    p.click("#o-sms")
    p.wait_for_selector("#listeSms button")
    assert "<b>bonjour</b>" in p.inner_text("#listeSms") and p.locator("#listeSms b").count() == 0
    p.click("#listeSms button")
    assert "alert(1)" in p.inner_text("#dTexte") and p.inner_text("#dDe") == "+33639980001"
    p.click("#dSuppr")
    assert p.is_visible("#conf") and not [a for a in appels if a[0] == "DELETE"]
    p.click("#confOk")
    p.wait_for_function("document.getElementById('rSms').textContent.includes('supprimé')")
    assert ("DELETE", "/sms/7", None) in appels
    assert p.evaluate("window.__dialogues") == 0 and err == []
    ctx.close()


def test_envoi_sms_meme_corps_et_echec_visible(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/modem/", {**API, "/sms/send": (200, {"success": False, "error": "SIM absente"})})
    p.click("#o-sms"); p.click("#smsNouveau")
    p.fill("#smsA", "+33639980009"); p.fill("#smsT", "Essai")
    p.click("#fSms button[type=submit]")
    p.wait_for_function("document.getElementById('rSms').textContent.includes('SIM absente')")
    assert json.loads([a for a in appels if a[1] == "/sms/send"][0][2]) == {"number": "+33639980009", "text": "Essai"}
    ctx.close()


def test_deconnexion_et_reinitialisation_demandent_confirmation(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/modem/", API)
    p.wait_for_function("document.getElementById('bascule').textContent==='Déconnecter'")
    p.click("#bascule")
    assert p.is_visible("#conf") and "Déconnecter" in p.inner_text("#confTxt") and not [a for a in appels if a[1] == "/disconnect"]
    p.click("#confNon")
    assert not p.is_visible("#conf") and not [a for a in appels if a[1] == "/disconnect"]
    p.click("#bascule"); p.click("#confOk")
    p.wait_for_function("document.getElementById('rGlobal').textContent.includes('Déconnecté')")
    assert ("POST", "/disconnect", None) in appels
    p.click("#o-reglages"); p.click("#bReset")
    assert p.is_visible("#conf") and not [a for a in appels if a[1] == "/reset"]
    p.click("#confOk")
    p.wait_for_function("document.getElementById('rGlobal').textContent.includes('Réinitialisation')")
    assert ("POST", "/reset", None) in appels
    p.click("#bOff"); assert p.is_visible("#conf") and not [a for a in appels if a[1] == "/power/off"]
    assert p.evaluate("window.__dialogues") == 0 and err == []
    ctx.close()


def test_reglages_et_connexion_envoient_les_memes_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/modem/", {**API, "/status": (200, {**STATUS, "connected": False, "state": "registered"})})
    p.click("#o-reglages")
    p.wait_for_function("document.getElementById('cApn').value==='internet'")
    assert p.input_value("#cIp") == "ipv4v6" and p.is_checked("#cAuto") and p.input_value("#cPass") == ""
    p.get_by_text("Orange", exact=True).click()
    assert p.input_value("#cApn") == "orange" and p.input_value("#cUser") == "orange"
    p.fill("#cPass", "secret-factice")
    p.click("#fCfg button[type=submit]")
    p.wait_for_function("document.getElementById('rReg').textContent.includes('enregistrée')")
    cfg = [a for a in appels if a[1] == "/config" and a[0] == "POST"][0]
    assert json.loads(cfg[2]) == {"apn": "orange", "user": "orange", "password": "secret-factice", "ip_type": "ipv4v6", "auto_connect": True}
    assert p.input_value("#cPass") == ""
    p.fill("#cPass", "secret-factice")
    p.click("#bascule")   # connexion : aucune confirmation (rien n'est coupé)
    p.wait_for_function("document.getElementById('rGlobal').textContent.includes('Connexion demandée')")
    cx = [a for a in appels if a[1] == "/connect"][0]
    assert json.loads(cx[2]) == {"apn": "orange", "user": "orange", "password": "secret-factice", "ip_type": "ipv4v6"}
    ctx.close()


def test_console_at_repli_rest(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/modem/", {**API, "/at/command": (200, {"success": True, "response": ["OK", "+CSQ: 20,99"]})})
    p.click("#o-terminal")
    p.fill("#atCmd", "AT+CSQ"); p.press("#atCmd", "Enter")
    p.wait_for_function("document.getElementById('console').textContent.includes('+CSQ: 20,99')")
    assert json.loads([a for a in appels if a[1] == "/at/command"][0][2]) == {"command": "AT+CSQ"}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/modem/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat").lower() == "session requise"
    assert [p.inner_text(i) for i in ("#tOp", "#tTech", "#tSig", "#tIp", "#iImei", "#sPct")] == ["—"] * 6
    assert p.is_disabled("#bascule") and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/modem/?demo=1", {})
    p.wait_for_function("document.getElementById('tOp').textContent!=='—'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and "192.0.2." in p.inner_text("#tIp")
    p.click("#bascule"); p.click("#confOk")
    p.wait_for_function("document.getElementById('rGlobal').textContent.includes('inerte')")
    p.click("#o-sms"); p.click("#listeSms button"); p.click("#dSuppr"); p.click("#confOk")
    p.wait_for_function("document.getElementById('rSms').textContent.includes('inerte')")
    p.click("#o-signal"); p.wait_for_selector("#courbe svg")
    assert appels == [] and err == []
    ctx.close()


@pytest.mark.parametrize("url", ["http://sbx.test/modem/?embed=1&demo=1", "http://sbx.test/modem/?embed=1"])
def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur, url):
    ctx, p, err, _ = ouvre(navigateur, url, API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tOp').textContent!=='—'")
    for t in ("signal", "sms", "terminal", "reglages", "statut"):
        p.click("#o-" + t)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
