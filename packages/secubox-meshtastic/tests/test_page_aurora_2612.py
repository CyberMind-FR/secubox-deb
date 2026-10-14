# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2612 — /meshtastic/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "meshtastic" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid" not in SRC and "crt-engine" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'meshtastic'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_d_ecriture_identiques_et_aucune_nouvelle_action():
    for r in ("'POST', '/send'", "'POST', '/grid'", "'POST', '/mode'", "/channel-url", "/device-config", "lire('/status')"):
        assert r in SRC
    assert {m for m in re.findall(r"ecrire\('(\w+)'", SRC)} == {"POST"}
    assert sorted(re.findall(r"ecrire\('POST', '([^']+)'", SRC)) == ["/grid", "/mode", "/send"]
    assert "{ channel: e.canal, text: e.texte }" in SRC and "{ channel: nom, grid }" in SRC and "{ mode }" in SRC
    assert "sbx_token" in SRC


def test_aucun_secret_affiche():
    # le code d'appairage et le lien (clé du canal) ne sont jamais rendus, ni QR
    assert "ble_pin" not in SRC.replace("ble_pin: 123456", "")
    assert "qr_svg" not in SRC and "shareQr" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
STATUS = {
    "radio": "present", "mode": "both",
    "grids": {"LongFast": ["shared"], "Maison": ["on"]},
    "nodes": [
        {"id": "!aa000001", "short": "GK2", "long": "Passerelle", "role": "ROUTER", "pos": [45.0, 6.0], "battery": 101, "rssi": None, "snr": None, "last_heard": NOW - 5, "is_self": True},
        {"id": "!bb000002", "short": "EST", "long": "Relais est", "role": "ROUTER", "pos": [45.01, 6.02], "battery": 80, "rssi": -96, "snr": 7.5, "last_heard": NOW - 60},
        {"id": "!cc000003", "short": "MOB", "long": "Mobile", "role": "CLIENT", "pos": None, "battery": None, "rssi": -120, "snr": -6.5, "last_heard": NOW - 4000}],
    "messages_by_channel": {"0": [{"from": "!bb000002", "text": "<b>salut</b>", "ts": NOW - 90}], "1": [{"from": "!cc000003", "text": "second", "ts": NOW - 30}]},
    "census": [{"id": "!bb000002", "packets": 12, "rssi": -96, "snr": 7.5, "first_heard": NOW - 9000, "last_heard": NOW - 60}],
    "channel_stats": {"0": {"packets": 12, "decrypted": 12}, "1": {"packets": 3, "decrypted": 0}},
}
CFG = {"firmware": "2.5.0", "hw_model": "RAK4631", "node_id": "!aa000001", "long_name": "Passerelle", "short_name": "GK2", "region": "EU_868",
       "modem_preset": "LONG_FAST", "hop_limit": 3, "tx_enabled": True, "role": "ROUTER", "ble_enabled": True, "ble_pin": 424242, "ble_mode": "FIXED_PIN",
       "wifi_enabled": False, "channels": ["LongFast"]}
API = {"/status": (200, STATUS), "/device-config": (200, CFG), "/channel-url": (200, {"url": "https://meshtastic.org/e/#SECRET"}),
       "/send": (200, {"status": "sent", "channel": 0}), "/mode": (200, {"status": "applied"}), "/grid": (200, {"status": "applied"})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "meshtastic":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/meshtastic", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/meshtastic/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/meshtastic/", API)
    p.wait_for_selector("#bNoeuds tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tRadio", "#tMode", "#tNoeuds", "#tCanaux", "#tMsgs", "#tEntendus")] == ["Présente", "both", "3", "2", "2", "1"]
    assert p.inner_text("#etat") == "RADIO PRÉSENTE"
    t = p.inner_text("#bNoeuds")
    assert "Passerelle" in t and "secteur" in t and "-96 dBm" in t and "7.5 dB" in t and "1970" not in t and "45.0100, 6.0200" in t
    assert p.locator("#carte circle").count() == 2
    p.click("#o-ecoute")
    assert "12" in p.inner_text("#barres") and "!bb000002" in p.inner_text("#bCens")
    assert err == []
    ctx.close()


def test_messages_echappes_et_changement_de_canal(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/meshtastic/", API)
    p.click("#o-messages")
    p.wait_for_selector("#fil .msg")
    assert "<b>salut</b>" in p.inner_text("#fil") and p.locator("#fil b").count() == 0
    p.get_by_text("Canal 1 (1)").click()
    assert "second" in p.inner_text("#fil")
    ctx.close()


def test_emission_radio_demande_confirmation_puis_envoie_le_bon_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/meshtastic/", API)
    p.click("#o-messages")
    p.fill("#envCanal", "1"); p.fill("#envTexte", "test radio")
    p.click("#fEnvoi button[type=submit]")
    assert p.is_visible("#cEnvoi") and "test radio" in p.inner_text("#tEnvoi")
    assert not [a for a in appels if a[0] == "POST"]
    p.click("#okEnvoi")
    p.wait_for_function("document.getElementById('rEnvoi').textContent.includes('émis')")
    assert json.loads([a for a in appels if a[1] == "/send"][0][2]) == {"channel": 1, "text": "test radio"}
    ctx.close()


def test_envoi_radio_absente_n_est_pas_un_succes(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/meshtastic/", {**API, "/send": (200, {"status": "radio-absent"})})
    p.click("#o-messages"); p.fill("#envTexte", "x"); p.click("#fEnvoi button[type=submit]"); p.click("#okEnvoi")
    p.wait_for_function("document.getElementById('rEnvoi').textContent.includes('impossible')")
    assert "radio absente" in p.inner_text("#rEnvoi")
    ctx.close()


def test_grille_et_mode_confirmation_et_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/meshtastic/", API)
    p.click("#o-canaux"); p.wait_for_selector("#listeGrille .canal")
    ligne = p.locator("#listeGrille .canal").first          # LongFast (ordre alphabétique)
    ligne.get_by_role("button", name="on", exact=True).click()
    p.locator("#listeGrille .canal").first.get_by_text("Enregistrer").click()
    assert p.is_visible("#cGrille") and not [a for a in appels if a[1] == "/grid"]
    p.click("#okGrille")
    p.wait_for_function("document.getElementById('rGrille').textContent.includes('enregistrée')")
    corps = json.loads([a for a in appels if a[1] == "/grid"][0][2])
    assert corps["channel"] == "LongFast" and sorted(corps["grid"]) == ["on", "shared"]
    p.click("#o-radio"); p.select_option("#modeSel", "passive-listener"); p.click("#modeBtn")
    assert p.is_visible("#cMode") and not [a for a in appels if a[1] == "/mode"]
    p.click("#okMode")
    p.wait_for_function("document.getElementById('rMode').textContent.includes('appliqué')")
    assert json.loads([a for a in appels if a[1] == "/mode"][0][2]) == {"mode": "passive-listener"}
    ctx.close()


def test_ctl_en_erreur_n_est_pas_un_succes(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/meshtastic/", {**API, "/mode": (200, {"status": "error", "stderr": "sudo refusé"})})
    p.click("#o-radio"); p.select_option("#modeSel", "both"); p.select_option("#modeSel", "active-node"); p.click("#modeBtn"); p.click("#okMode")
    p.wait_for_function("document.getElementById('rMode').textContent.includes('impossible')")
    assert "sudo refusé" in p.inner_text("#rMode")
    ctx.close()


def test_configuration_sans_code_d_appairage_et_lien_jamais_affiche(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/meshtastic/", API)
    p.click("#o-radio"); p.click("#cfgBtn")
    p.wait_for_function("document.getElementById('kvCfg').textContent.includes('EU_868')")
    assert "424242" not in p.inner_text("body") and "code non affiché" in p.inner_text("#kvCfg")
    p.click("#o-canaux"); p.click("#lien")
    assert p.is_visible("#cLien") and not [a for a in appels if a[1] == "/channel-url"]
    p.click("#okLien")
    p.wait_for_function("document.getElementById('rLien').hidden === false")
    assert "SECRET" not in p.content() and "SECRET" not in p.inner_text("body")
    ctx.close()


@pytest.mark.parametrize("code", [401, 403])
def test_sans_session_bandeau_et_tirets(navigateur, code):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/meshtastic/", {"/status": (code, {"detail": "jeton requis"})})
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE" and "session requise" in p.inner_text("#session")
    assert [p.inner_text(i) for i in ("#tRadio", "#tMode", "#tNoeuds", "#tCanaux", "#tMsgs", "#tEntendus")] == ["—"] * 6 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/meshtastic/?demo=1", {})
    p.wait_for_selector("#bNoeuds tr td.mono", state="attached")
    assert "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#o-messages"); p.fill("#envTexte", "x"); p.click("#fEnvoi button[type=submit]"); p.click("#okEnvoi")
    p.wait_for_function("document.getElementById('rEnvoi').textContent.includes('inerte')")
    p.click("#o-canaux"); p.click("#lien"); p.click("#okLien")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/meshtastic/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bNoeuds tr td.mono", state="attached")
    for t in ("messages", "canaux", "ecoute", "radio", "noeuds"):
        p.click("#o-" + t)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
