# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2612 — /jitsi/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[2] / "www" / "jitsi" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-light" not in SRC and "crt-engine" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onsubmit=\"save"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'jitsi'" in SRC and "demo" in SRC and "embed" in SRC


def test_routes_et_corps_d_ecriture_identiques():
    # les trois seules écritures de l'ancienne page, mêmes routes, mêmes corps
    assert "ecrire('POST', '/control', { action })" in SRC
    assert "ecrire('POST', '/service/restart', { unit })" in SRC
    assert "ecrire('POST', '/public-ip', { address })" in SRC
    assert len(re.findall(r"ecrire\('", SRC)) == 3
    for lecture in ("'/status'", "'/stats'", "'/logs?unit='"):
        assert lecture in SRC
    # routes volontairement non reprises par l'API (docker) : jamais appelées
    for absente in ("/rooms", "/recordings", "/jibri", "/config"):
        assert absente not in SRC
    assert "sbx_token" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"module": "jitsi", "version": "2.2.0", "installed": True, "container": "running", "domain": "meet.example.org", "lxc_ip": "192.0.2.50",
          "web_reachable": True, "services": {"prosody": "active", "jicofo": "active", "videobridge": "failed", "web": "active"},
          "media": {"udp_port": 10000, "public_address": "198.51.100.7", "public_address_set": True}}
STATS = {"conferences": 0, "participants": 4, "largest_conference": 3}
API = {"/status": (200, STATUS), "/stats": (200, STATS), "/logs": (200, {"unit": "jicofo", "lines": ["ligne un", "<b>ligne deux</b>"]})}


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
        elif chemin.rstrip("/") == "jitsi":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/jitsi", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (200, {"success": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/jitsi/**", api)
    p.goto(url)
    p.dialogues = dialogues
    return ctx, p, erreurs, appels


def test_tuiles_et_services_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/jitsi/", API)
    p.wait_for_function("document.getElementById('tConf').textContent !== '—'")
    assert [p.inner_text(i) for i in ("#tConf", "#tPart", "#tGrande")] == ["0", "4", "3"]   # 0 est une mesure
    assert p.inner_text("#tEtat") == "EN MARCHE" and p.inner_text("#etat") == "EN MARCHE"
    assert p.inner_text("#tMedia") == "198.51.100.7" and p.inner_text("#tWeb") == "JOIGNABLE"
    assert "FAILED" in p.inner_text("#lServ") and p.locator("#lServ .svc").count() == 4
    assert p.get_attribute("#iUrl a", "href") == "https://meet.example.org/"
    p.fill("#salle", "equipe a")
    assert p.get_attribute("#rejoindre", "href") == "https://meet.example.org/equipe%20a"
    assert err == []
    ctx.close()


def test_stats_indisponibles_donnent_des_tirets(navigateur):
    routes = {**API, "/stats": (200, {"available": False, "conferences": 0, "participants": 0})}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/jitsi/", routes)
    p.wait_for_function("document.getElementById('tEtat').textContent !== '—'")
    assert [p.inner_text(i) for i in ("#tConf", "#tPart", "#tGrande")] == ["—"] * 3 and err == []
    ctx.close()


def test_arreter_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/jitsi/", API)
    p.wait_for_function("document.getElementById('bascule').textContent === 'Arrêter'")
    p.click("#bascule")
    assert p.is_visible("#conf") and "coupées" in p.inner_text("#confTexte")
    assert not [a for a in appels if a[0] == "POST"]
    p.click("#confNon")
    assert not p.is_visible("#conf") and not [a for a in appels if a[0] == "POST"]
    p.click("#bascule"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('arrêté')")
    assert [json.loads(a[2]) for a in appels if a[1] == "/control"] == [{"action": "stop"}]
    assert p.dialogues == []
    ctx.close()


def test_redemarrer_un_service_et_adresse_publique(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/jitsi/", API)
    p.wait_for_selector("#lServ .svc button")
    p.locator("#lServ .svc").nth(2).get_by_text("Redémarrer").click()
    assert not [a for a in appels if a[1] == "/service/restart"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('redémarré')")
    assert json.loads([a for a in appels if a[1] == "/service/restart"][0][2]) == {"unit": "jitsi-videobridge2"}
    p.click("#o-media"); p.fill("#cfgIp", "203.0.113.10"); p.click("#fIp button[type=submit]")
    assert not [a for a in appels if a[1] == "/public-ip"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rIp').textContent.includes('enregistrée')")
    assert json.loads([a for a in appels if a[1] == "/public-ip"][0][2]) == {"address": "203.0.113.10"}
    ctx.close()


def test_operation_en_cours_est_annoncee(navigateur):
    routes = {**API, "/control": (200, {"success": True, "pending": True, "message": "in progress"})}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/jitsi/", routes)
    p.wait_for_function("document.getElementById('bascule').textContent === 'Arrêter'")
    p.click("#bascule"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('En cours')")
    ctx.close()


def test_journaux_en_texte_brut(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/jitsi/", API)
    p.click("#o-journaux")
    p.wait_for_function("document.getElementById('journal').textContent.includes('ligne un')")
    assert "<b>ligne deux</b>" in p.inner_text("#journal") and p.locator("#journal b").count() == 0
    assert any(a[1] == "/logs" for a in appels) and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/jitsi/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE" and "session requise" in p.inner_text("#session")
    assert [p.inner_text(i) for i in ("#tEtat", "#tConf", "#tPart", "#tMedia", "#tWeb")] == ["—"] * 5
    assert p.url.endswith("/jitsi/") and err == []     # plus de redirection vers login.html
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/jitsi/?demo=1", {})
    p.wait_for_function("document.getElementById('tConf').textContent === '2'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#bascule"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/jitsi/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tConf').textContent !== '—'")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
