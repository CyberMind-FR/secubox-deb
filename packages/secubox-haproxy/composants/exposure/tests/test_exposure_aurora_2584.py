# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2584 — /exposure/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "www" / "exposure" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
API_SRC = (ROOT / "api" / "main.py").read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "crt-engine" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "outerHTML", "insertAdjacentHTML", "onclick=", "onsubmit="):
        assert interdit not in SRC, interdit
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'exposure'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC


def test_routes_d_ecriture_identiques_a_l_ancienne_page():
    for route in ("/tor/add", "/tor/remove", "/emancipate", "/revoke"):
        assert f"API + '{route}'" in SRC
        assert f'@app.post("{route}"' in API_SRC
    assert "'/api/v1/exposure/exposure/'" in SRC and '@app.post("/exposure/{vhost}")' in API_SRC
    # corps de révocation inchangé : les trois canaux sont toujours demandés
    assert "{ service: nom, tor: true, dns: true, mesh: true }" in SRC
    # aucune action nouvelle : ni SSL, ni webhook, ni historique, ni webui, ni contournement du WAF
    for absent in ("/ssl/add", "/ssl/remove", "/webhooks", "emancipate_webui", "/history", "waf_bypass", "bypass"):
        assert absent not in SRC, absent


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


ONION = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
STATUS = {"services": {"total": 3, "external": 1}, "tor": {"count": 1, "services": []},
          "ssl": {"count": 1, "backends": [{"service": "blog.conf", "domain": "blog.example.com", "backend": "nginx"}]}}
SCAN = {"services": [{"port": 22, "address": "192.0.2.1", "process": "sshd", "name": "SSH", "external": False},
                     {"port": 80, "address": "0.0.0.0", "process": "haproxy", "name": "HAProxy", "external": True},
                     {"port": 9050, "address": "127.0.0.1", "process": "tor", "name": "Tor", "external": False}]}
TOR = {"services": [{"service": "monapp", "onion": ONION, "port": "80", "backend": "127.0.0.1:8080"}]}
EMANC = {"services": [{"name": "monapp", "port": 8080, "domain": None, "tor": True, "dns": False, "mesh": True, "onion": ONION},
                      {"name": "webui", "local_port": 9080, "onion_port": 80, "active": True}]}
API = {"/status": (200, STATUS), "/scan": (200, SCAN), "/tor_list": (200, TOR), "/emancipated": (200, EMANC)}


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
        elif chemin.rstrip("/") == "exposure":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/exposure", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        defaut = (404, {}) if r.request.method == "GET" else (200, {"success": True})
        statut, corps = routes.get(chemin, defaut)
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/exposure/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels, dialogues


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/exposure/", API)
    p.wait_for_selector("#bTor tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tTotal", "#tExt", "#tTor", "#tSsl", "#tEm")] == ["3", "1", "1", "1", "2"]
    assert p.inner_text("#etat") == "EN LIGNE"
    assert ONION in p.inner_text("#bTor") and "monapp" in p.inner_text("#bTor")
    scan = p.inner_text("#bScan")
    assert "HAProxy" in scan and "TOUTES INTERFACES" in scan and "ADRESSE PRÉCISE" in scan
    em = p.inner_text("#bEm")
    assert "8080" in em and "9080" in em and "TOR" in em and "MAILLAGE" in em   # port repris de local_port pour webui
    assert "blog.example.com" in p.inner_text("#bSsl")
    assert err == []
    ctx.close()


def test_jeton_envoye(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/exposure/", API)
    p.evaluate("localStorage.setItem('sbx_token','abc')")
    p.reload(); p.wait_for_selector("#bTor tr td.mono", state="attached")
    assert any(a[3] == "Bearer abc" for a in appels)
    ctx.close()


def test_retirer_service_cache_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels, dial = ouvre(navigateur, "http://sbx.test/exposure/", API)
    p.wait_for_selector("#bTor tr td.act")
    p.locator("#bTor tr").first.get_by_text("Retirer").click()
    assert not [a for a in appels if a[0] == "POST"]
    p.locator("#bTor tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rTor').textContent.includes('retiré')")
    post = [a for a in appels if a[1] == "/tor/remove"][0]
    assert json.loads(post[2]) == {"service": "monapp"} and dial == []
    ctx.close()


def test_revoquer_envoie_les_trois_canaux(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/exposure/", API)
    p.wait_for_selector("#bEm tr td.act")
    p.locator("#bEm tr").first.get_by_text("Révoquer").click()
    assert not [a for a in appels if a[1] == "/revoke"]
    p.locator("#bEm tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rEm').textContent.includes('révoqué')")
    assert json.loads([a for a in appels if a[1] == "/revoke"][0][2]) == {"service": "monapp", "tor": True, "dns": True, "mesh": True}
    ctx.close()


def test_emanciper_confirme_puis_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/exposure/", {**API, "/emancipate": (200, {"success": True, "output": {"onion": ONION, "mesh_error": "annuaire absent"}})})
    p.click("#ouvrirEm")
    p.fill("#fEm [name=service]", "web"); p.fill("#fEm [name=port]", "8081")
    p.check("#fEm [name=tor]"); p.check("#fEm [name=mesh]")
    p.click("#fEm button[type=submit]")
    assert p.is_visible("#cEm") and "web" in p.inner_text("#cEm")
    assert not [a for a in appels if a[1] == "/emancipate"]
    p.click("#cEm >> text=Confirmer")
    p.wait_for_function("document.getElementById('rEm').textContent.includes('émancipé')")
    assert json.loads([a for a in appels if a[1] == "/emancipate"][0][2]) == {"service": "web", "port": 8081, "domain": None, "tor": True, "dns": False, "mesh": True}
    assert "annuaire absent" in p.inner_text("#rEm")
    ctx.close()


def test_ajout_tor_et_erreur_affichee(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/exposure/", {**API, "/tor/add": (400, {"detail": "Hidden service already exists"})})
    p.click("#ouvrirTor")
    p.fill("#fTor [name=service]", "monapp")
    p.click("#fTor button[type=submit]"); p.click("#cTor >> text=Confirmer")
    p.wait_for_function("document.getElementById('rTor').textContent.includes('already exists')")
    assert json.loads([a for a in appels if a[1] == "/tor/add"][0][2]) == {"service": "monapp", "local_port": 9180, "onion_port": 80}   # frontal onion-in (#3112)
    ctx.close()


def test_exposition_par_vhost(navigateur):
    ctx, p, _, appels, _ = ouvre(navigateur, "http://sbx.test/exposure/", {**API, "/exposure/zigbee.example.com": (200, {"vhost": "zigbee.example.com", "reach": "wan", "mesh": False, "tor": False})})
    p.fill("#expVhost", "a/b"); p.click("#fExp button[type=submit]")
    assert "invalide" in p.inner_text("#rExp") and not [a for a in appels if a[0] == "POST"]
    p.fill("#expVhost", "zigbee.example.com"); p.select_option("#fExp [name=reach]", "wan")
    p.click("#fExp button[type=submit]")
    assert "public" in p.inner_text("#cExp")
    assert not [a for a in appels if a[0] == "POST"]
    p.click("#cExp >> text=Confirmer")
    p.wait_for_function("document.getElementById('rExp').textContent.includes('Appliqué')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/exposure/zigbee.example.com" and json.loads(post[2]) == {"reach": "wan", "mesh": False, "tor": False}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/exposure/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tTotal", "#tExt", "#tTor", "#tSsl", "#tEm")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/exposure/?demo=1", {})
    p.wait_for_selector("#bTor tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bTor tr").first.get_by_text("Retirer").click(); p.locator("#bTor tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rTor').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/exposure/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bTor tr td.mono", state="attached")
    p.click("#ouvrirEm")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
