# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2571 — /tor/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "tor" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert not re.search(r'(googleapis|crt-engine|hybrid-dark|crt-light)', SRC)
    assert not re.search(r'https?://[^"\s]*\.(js|css)', SRC)
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'tor'" in SRC and "demo" in SRC and "embed" in SRC
    assert "sbx_token" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("'/enable'", "'/disable'", "'/new_identity'", "'/hidden_service/add'", "'/hidden_service/remove'",
              "'/admin/tor/on'", "'/admin/tor/off'", "'/exit_country'", "'/vpn/client'", "'/tor/bridge'", "'/tor/emancipate_webui'"):
        assert r in SRC, r
    for r in ("'/status'", "'/circuits'", "'/hidden_services'", "'/onion_dns'", "'/admin/tor/state'", "'/vpn/clients'", "'/tor/bridges'", "'/clients'"):
        assert r in SRC, r
    assert "DELETE" in SRC and "{ preset }" in SRC


def test_pas_de_cle_privee_ni_ligne_de_pont_affichee():
    assert "private_key" not in SRC.lower() and "PrivateKey" not in SRC
    assert "resumePont" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


PONT = "Bridge obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=SECRETCERTEXEMPLE iat-mode=0"
STATUS = {"enabled": True, "running": True, "mode": "transparent", "dns_over_tor": True, "kill_switch": True, "bridges_enabled": True, "bridge_type": "obfs4",
          "bootstrap": 100, "circuit_count": 2, "bytes_read": 2097152, "bytes_written": 1536, "exit_ip": "203.0.113.77", "is_tor": True}
CIRC = {"circuits": [{"id": "7", "nodes": [{"fingerprint": "AA", "name": "garde"}, {"fingerprint": "BB", "name": "sortie"}]}], "total": 1}
HS = {"services": [{"name": "webui", "onion_address": "exemple.onion", "has_address": True, "virtual_port": 80, "local_port": 9080},
                   {"name": "blog", "onion_address": "", "has_address": False, "virtual_port": 80, "local_port": 8080}], "total": 2}
DNSO = {"dnsport_up": True, "forward_zone_installed": True, "resolves": False}
NAC = {"clients": [{"ip": "192.0.2.42", "mac": "00:00:5e:00:53:01", "hostname": "poste", "online": True, "zone": "lan", "status": "enabled"},
                   {"ip": "192.0.2.43", "mac": "00:00:5e:00:53:02", "hostname": "q", "online": True, "zone": "quarantine", "status": "quarantine"},
                   {"ip": "2001:db8::1", "mac": "00:00:5e:00:53:03", "hostname": "v6", "online": True, "zone": "lan", "status": "enabled"}]}
ROUTES = {
    "tor": {"/status": (200, STATUS), "/circuits": (200, CIRC), "/hidden_services": (200, HS), "/onion_dns": (200, DNSO)},
    "toolbox": {"/admin/tor/state": (200, {"tor_mode": True}), "/exit_country": (200, {"countries": ["CH"]}),
                "/vpn/clients": (200, {"clients": [{"kind": "cidr", "selector": "198.51.100.0/28"}]}), "/tor/bridges": (200, {"bridges": [PONT]})},
    "nac": {"/clients": (200, NAC)},
}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    if jeton:
        p.add_init_script("localStorage.setItem('sbx_token','%s')" % jeton)

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "tor":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        m = re.match(r"http://sbx\.test/api/v1/([a-z]+)(/[^?]*)", r.request.url)
        mod, chemin = m.group(1), m.group(2)
        appels.append((r.request.method, mod, chemin, r.request.post_data, r.request.headers.get("authorization")))
        defaut = (200, {"success": True, "status": "ok"})
        statut, corps = routes.get(mod, {}).get(chemin, defaut if r.request.method != "GET" else (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def ecritures(appels):
    return [a for a in appels if a[0] != "GET"]


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/tor/", ROUTES)
    p.wait_for_selector("#bHs tr td.mono", state="attached")
    assert p.inner_text("#etat") == "CONNECTÉ"
    assert [p.inner_text(i) for i in ("#tBoot", "#tCirc", "#tRecu", "#tEmis", "#tSortie")] == ["100 %", "2", "2.0 Mo", "1.5 Ko", "ARMÉE"]
    assert p.inner_text("#kSortieIp") == "203.0.113.77"
    assert "garde" in p.inner_text("#listeCirc") and "sortie" in p.inner_text("#listeCirc")
    h = p.inner_text("#bHs")
    assert "exemple.onion" in h and "80 → 9080" in h and "Génération en cours" in h
    assert "NON" in p.inner_text("#dnsOnion")
    assert "CH" in p.inner_text("#paysActuel") and p.eval_on_selector("#selPays option[value=CH]", "o => o.selected")
    # NAC : quarantaine et IPv6 exclus
    nac = p.inner_text("#bNac")
    assert "192.0.2.42" in nac and "192.0.2.43" not in nac and "2001:db8" not in nac and "IPv6" in p.inner_text("#nNac")
    # la ligne de pont n'est jamais affichée en entier
    ponts = p.inner_text("#bPonts")
    assert "192.0.2.10:443" in ponts and "SECRETCERT" not in p.content() and "cert=" not in ponts
    assert err == []
    ctx.close()


def test_demon_arrete_mesures_en_tirets(navigateur):
    arrete = {"enabled": False, "running": False, "mode": "transparent", "bootstrap": 0, "circuit_count": 0, "bytes_read": 0, "bytes_written": 0}
    r = {**ROUTES, "tor": {**ROUTES["tor"], "/status": (200, arrete), "/circuits": (200, {"circuits": [], "total": 0})}}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/tor/", r)
    p.wait_for_function("document.getElementById('etat').textContent !== 'Chargement…'")
    assert p.inner_text("#etat") == "DÉSACTIVÉ"
    assert [p.inner_text(i) for i in ("#tBoot", "#tCirc", "#tRecu", "#tEmis", "#kSortieIp")] == ["—"] * 5
    assert err == []
    ctx.close()


def test_desactiver_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/tor/", ROUTES, jeton="jeton-test")
    p.wait_for_selector("#bHs tr td.mono", state="attached")
    p.click("#btnDesactiver")
    assert p.is_visible("#conf-controle") and "injoignables" in p.inner_text("#conf-controle")
    assert ecritures(appels) == []
    p.get_by_text("Confirmer — Désactiver").click()
    p.wait_for_function("document.getElementById('retour-controle').textContent.includes('désactivé')")
    w = ecritures(appels)
    assert [(a[0], a[1], a[2], a[3]) for a in w] == [("POST", "tor", "/disable", None), ("POST", "toolbox", "/admin/tor/off", None)]
    assert all(a[4] == "Bearer jeton-test" for a in w)
    ctx.close()


def test_mode_envoie_preset_puis_arme_la_sortie(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/tor/", ROUTES)
    p.wait_for_selector("#bHs tr td.mono", state="attached")
    p.click("[data-preset=stealth]"); p.get_by_text("Confirmer — furtif").click()
    p.wait_for_function("document.getElementById('retour-controle').textContent.includes('appliqué')")
    w = ecritures(appels)
    assert json.loads(w[0][3]) == {"preset": "stealth"} and w[0][2] == "/enable" and w[1][2] == "/admin/tor/on"
    ctx.close()


def test_echec_activation_n_arme_pas_la_sortie(navigateur):
    r = {**ROUTES, "tor": {**ROUTES["tor"], "/enable": (500, {"detail": "systemctl a échoué"})}}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/tor/", r)
    p.wait_for_selector("#bHs tr td.mono", state="attached")
    p.click("[data-preset=anonymous]"); p.get_by_text("Confirmer — anonyme").click()
    p.wait_for_function("document.getElementById('retour-controle').textContent.includes('impossible')")
    assert [a[2] for a in ecritures(appels)] == ["/enable"]
    ctx.close()


def test_service_cache_ajout_et_retrait_avec_confirmation(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/tor/", ROUTES)
    p.wait_for_selector("#bHs tr td.mono", state="attached")
    p.click("#btnAjoutHs"); p.fill("#fHs [name=name]", "monsite"); p.fill("#fHs [name=local_port]", "8080")
    p.click("#fHs button[type=submit]")
    assert not [a for a in appels if a[2] == "/hidden_service/add"]
    p.get_by_text("Confirmer — Créer").click()
    p.wait_for_function("document.getElementById('retour-hs').textContent.includes('créé')")
    corps = json.loads([a for a in appels if a[2] == "/hidden_service/add"][0][3])
    assert corps == {"name": "monsite", "local_port": 8080, "virtual_port": 80}
    p.locator("#bHs tr").first.get_by_text("Retirer").click()
    assert not [a for a in appels if a[2] == "/hidden_service/remove"]
    p.get_by_text("Confirmer — Retirer").click()
    p.wait_for_function("document.getElementById('retour-hs').textContent.includes('retiré')")
    assert json.loads([a for a in appels if a[2] == "/hidden_service/remove"][0][3]) == {"name": "webui"}
    ctx.close()


def test_emancipation_confirmee_affiche_l_adresse(navigateur):
    r = {**ROUTES, "exposure": {"/tor/emancipate_webui": (200, {"success": True, "output": {"onion": "nouveau.onion"}, "tor": {}})}}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/tor/", r)
    p.wait_for_selector("#bHs tr td.mono", state="attached")
    p.click("#btnEmanciper")
    assert not [a for a in appels if a[1] == "exposure"]
    p.get_by_text("Confirmer — Publier").click()
    p.wait_for_selector("#emancipe:not([hidden])")
    assert p.inner_text("#emOnion") == "nouveau.onion"
    assert [a[0] for a in appels if a[1] == "exposure"] == ["POST"]
    ctx.close()


def test_pays_vpn_et_ponts_memes_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/tor/", ROUTES)
    p.wait_for_selector("#bHs tr td.mono", state="attached")
    p.select_option("#selPays", ["CH", "FR"]); p.click("#paysAppliquer"); p.get_by_text("Confirmer — Appliquer").click()
    p.wait_for_function("document.getElementById('retour-pays').textContent.includes('appliquée')")
    assert json.loads([a for a in appels if a[2] == "/exit_country" and a[0] == "POST"][0][3]) == {"countries": ["FR", "CH"]}
    p.fill("#vpnSel", "192.0.2.99"); p.click("#vpnAjout")
    p.wait_for_function("document.getElementById('retour-vpn').textContent.includes('ajouté')")
    assert json.loads([a for a in appels if a[2] == "/vpn/client" and a[0] == "POST"][0][3]) == {"kind": "ip", "selector": "192.0.2.99"}
    p.fill("#vpnSel", "2001:db8::5"); p.click("#vpnAjout")
    assert "IPv6" in p.inner_text("#retour-vpn") and len([a for a in appels if a[2] == "/vpn/client" and a[0] == "POST"]) == 1
    p.locator("#bPonts tr").first.get_by_text("Retirer").click(); p.get_by_text("Confirmer — Retirer").click()
    p.wait_for_function("document.getElementById('retour-ponts').textContent.includes('retiré')")
    d = [a for a in appels if a[2] == "/tor/bridge" and a[0] == "DELETE"][0]
    assert json.loads(d[3]) == {"line": PONT}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {m: {k: (401, {"detail": "jeton requis"}) for k in v} for m, v in ROUTES.items()}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/tor/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tBoot", "#tCirc", "#tRecu", "#tEmis", "#tSortie")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/tor/?demo=1", {})
    p.wait_for_selector("#bHs tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#btnDesactiver"); p.get_by_text("Confirmer — Désactiver").click()
    p.wait_for_function("document.getElementById('retour-controle').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/tor/?demo=1&embed=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bHs tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
