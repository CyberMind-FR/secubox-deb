# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2597 — /freebox/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "freebox" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "hybrid-skin" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'freebox'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC


def test_le_jeton_d_application_n_est_jamais_lu_ni_affiche():
    # seul le jeton de session de l'administrateur (sbx_token) est lu ; rien qui ressemble au jeton d'application Freebox
    assert "app_token" not in SRC and "track_id" not in SRC


def test_routes_d_ecriture_a_l_identique():
    ecritures = set(re.findall(r"ecrire\('(/[a-z0-9/-]+)'", SRC))
    assert ecritures == {"/autoriser", "/revoquer"}
    for r in ("'/upnp'", "'/pare-feu/ipv6'", "'/autoconfig'"):
        assert "envoyerReglage(" + r in SRC
    # corps identiques à l'ancienne page
    assert "{ actif, confirme: true }" in SRC and "confirme_dmz = true" in SRC and "ids: liste.map(i => i.id), confirme: true" in SRC
    assert "'PUT'" not in SRC and "'DELETE'" not in SRC          # aucune écriture que l'ancienne page n'avait
    assert SRC.count("method: 'POST'") == 1                       # un seul point d'écriture, jamais de PUT/DELETE
    assert "TOUT le trafic entrant" in SRC and 'data-tab="autoconfig"' in SRC and 'id="t-autoconfig"' in SRC and "function appliqueAuto(" in SRC


def test_pas_de_sequence_d_echappement_dans_le_html_visible():
    visible = SRC[:SRC.index("<script>")]
    assert not re.search(r"\\u[0-9a-fA-F]{4}", visible)


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"etat": "autorise", "message": "Connecté à la Freebox.", "freebox": {"modele": "Freebox Test", "version": "10.0"}, "droits": {"settings": True},
          "droits_manquants": [], "aide_droits": {"settings": "Modification des réglages."}}
APPAREILS = {"appareils": [
    {"id": "a", "mac_fin": "aa:bb:cc", "nom": "Salon-TV", "type": "television", "fabricant": "Exemple", "actif": True, "joignable": True, "ipv4": ["192.0.2.20"], "ipv6_publiques": []},
    {"id": "b", "mac_fin": "11:22:33", "nom": "Portable", "type": "laptop", "fabricant": "", "actif": True, "joignable": True, "ipv4": ["192.0.2.21"], "ipv6_publiques": ["2001:db8::21"]},
    {"id": "c", "mac_fin": "44:55:66", "nom": "Imprimante", "type": "printer", "fabricant": "", "actif": False, "joignable": False, "ipv4": [], "ipv6_publiques": []}]}
CONNEXION = {"en_ligne": True, "media": "ftth", "ipv4_publique": "198.51.100.7", "ipv6": "", "debit_max_descendant_mbit": 2000, "debit_max_montant_mbit": 600,
             "ipv6_actif": True, "pare_feu_ipv6": False, "prefixes_ipv6": []}
PAREFEU = {"pare_feu_actif": False, "exceptions": [], "exceptions_lues": True}
REDIR = {"redirections": [{"id": 1, "actif": True, "protocole": "tcp", "port_externe_debut": 2222, "port_externe_fin": 2222, "appareil_ip": "192.0.2.22", "port_local": 22,
                           "source": "tout Internet", "commentaire": "SSH", "nom_appareil": "", "sensible": True}]}
UPNP = {"actif": True, "version": 2, "redirections": [{"protocole": "udp", "port_externe": 51820, "port_local": 51820, "appareil_ip": "192.0.2.21", "description": "VPN"}]}
AUTO = {"ecarts": 2, "ip_box": "192.0.2.10", "items": [
    {"id": "dns", "titre": "DNS distribué", "actuel": ["203.0.113.53"], "cible": ["192.0.2.10"], "sensible": False, "conforme": False, "pourquoi": "Filtrage."},
    {"id": "dmz", "titre": "DMZ", "actuel": {"enabled": False, "ip": ""}, "cible": {"enabled": True, "ip": "192.0.2.10"}, "sensible": True, "conforme": False, "pourquoi": "Services."}]}
API = {("GET", "/status"): (200, STATUS), ("GET", "/appareils"): (200, APPAREILS), ("GET", "/connexion"): (200, CONNEXION), ("GET", "/pare-feu"): (200, PAREFEU),
       ("GET", "/redirections"): (200, REDIR), ("GET", "/upnp"): (200, UPNP), ("GET", "/autoconfig"): (200, AUTO)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "freebox":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/freebox", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get((r.request.method, chemin), (200, {"message": "ok"}) if r.request.method != "GET" else (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/freebox/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/freebox/", API)
    p.wait_for_selector("#bApp tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tLigne", "#tAppareils", "#tDown", "#tUp", "#tPf", "#tRedir")] == ["En ligne", "2", "2000", "600", "Désactivé", "1"]
    assert "sur 3 connus" in p.inner_text("#sAppareils") and "1 sensible" in p.inner_text("#sRedir")
    assert p.inner_text("#etat") == "CONNECTÉE" and "Salon-TV" in p.inner_text("#bApp") and "IPv6 PUBLIC" in p.inner_text("#bApp")
    p.click("#o-redirections")
    assert "2222" in p.inner_text("#bRed") and "SENSIBLE" in p.inner_text("#bRed") and "VPN" in p.inner_text("#bUpnp")
    p.click("#o-connexion")
    assert "198.51.100.7" in p.inner_text("#cV4") and p.inner_text("#cDown") == "2000 Mb/s"
    assert err == []
    ctx.close()


def test_filtre_des_appareils_cote_client(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/freebox/", API)
    p.wait_for_selector("#bApp tr td.mono", state="attached")
    p.fill("#rechApp", "porta")
    assert "Portable" in p.inner_text("#bApp") and "Salon-TV" not in p.inner_text("#bApp")
    ctx.close()


def test_pare_feu_demande_une_confirmation_puis_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/freebox/", {**API, ("POST", "/pare-feu/ipv6"): (200, {"pare_feu_actif": True, "change": True})})
    p.click("#o-pare-feu")
    p.wait_for_selector("#pfAct button")
    p.click("#pfAct button")
    assert p.is_visible("#confirme") and "Activer le pare-feu IPv6" in p.inner_text("#confTitre")
    assert not [a for a in appels if a[0] == "POST"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('activé')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/pare-feu/ipv6" and json.loads(post[2]) == {"actif": True, "confirme": True}
    ctx.close()


def test_annuler_n_envoie_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/freebox/", API)
    p.click("#o-redirections")
    p.wait_for_selector("#upAct button")
    p.click("#upAct button")
    p.click("#confNon")
    assert not p.is_visible("#confirme") and not [a for a in appels if a[0] == "POST"]
    ctx.close()


def test_upnp_corps_identique(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/freebox/", {**API, ("POST", "/upnp"): (200, {"actif": False, "change": True})})
    p.click("#o-redirections")
    p.wait_for_selector("#upAct button")
    p.click("#upAct button")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('UPnP')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/upnp" and json.loads(post[2]) == {"actif": False, "confirme": True}
    ctx.close()


def test_autoconfig_dmz_demande_la_confirmation_dediee(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/freebox/", {**API, ("POST", "/autoconfig"): (200, {"appliques": ["dmz"]})})
    p.click("#o-autoconfig")
    p.wait_for_selector("#bAuto tr td.act button")
    p.get_by_text("Appliquer (sensible)").click()
    assert "TOUT le trafic entrant" in p.inner_text("#confCorps") and "DMZ" in p.inner_text("#confCorps")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Appliqué')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/autoconfig" and json.loads(post[2]) == {"ids": ["dmz"], "confirme": True, "confirme_dmz": True}
    ctx.close()


def test_le_jeton_de_session_est_envoye_y_compris_en_lecture(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/freebox/", API)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.click("#rafraichir")
    p.wait_for_timeout(300)
    assert any(a[0] == "GET" and a[3] == "Bearer jeton-test" for a in appels)
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/freebox/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tLigne", "#tAppareils", "#tDown", "#tUp", "#tPf", "#tRedir")] == ["—"] * 6 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/freebox/?demo=1", {})
    p.wait_for_selector("#bApp tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#o-pare-feu")
    p.click("#pfAct button")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


@pytest.mark.parametrize("onglet", ["appareils", "connexion", "pare-feu", "redirections", "autoconfig"])
def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur, onglet):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/freebox/?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bApp tr td.mono", state="attached")
    p.click("#o-" + onglet)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
