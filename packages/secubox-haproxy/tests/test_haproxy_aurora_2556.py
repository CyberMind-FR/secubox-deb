# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2556 — /haproxy/ au profil Aurora : pages statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "haproxy" / "index.html"
MAIN = Path(__file__).resolve().parents[1] / "api" / "main.py"
SRC = PAGE.read_text(encoding="utf-8")
API_SRC = MAIN.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "/shared/crt-engine.js" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "outerHTML", "insertAdjacentHTML", "onclick="):
        assert interdit not in SRC, interdit
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'haproxy'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC


def test_routes_d_ecriture_existent_cote_api():
    """Chaque route d'écriture de la page existe vraiment dans l'API (l'ancienne page en appelait trois qui n'existaient pas)."""
    attendu = {
        "'POST', '/waf/toggle'": '@router.post("/waf/toggle"',
        "'POST', '/waf/sync-routes'": '@router.post("/waf/sync-routes"',
        "'POST', '/generate'": '@router.post("/generate"',
        "'POST', '/reload'": '@router.post("/reload"',
        "'POST', '/restart'": '@router.post("/restart"',
        "'/vhost/' + encodeURIComponent": '@router.put("/vhost/{name}"',
        "'DELETE', '/vhost/'": '@router.delete("/vhost/{name}"',
        "'POST', '/backend'": '@router.post("/backend"',
        "'DELETE', '/backend/'": '@router.delete("/backend/{name}"',
        "'POST', '/certificates/acme'": '@router.post("/certificates/acme"',
        "'DELETE', '/certificates/'": '@router.delete("/certificates/{name}"',
    }
    for page, api in attendu.items():
        assert page in SRC, page
        assert api in API_SRC, api
    # routes fantômes de l'ancienne page : jamais existé côté API
    for fantome in ("/certificate/request", "'/certificate/'", "/server", "PUT', '/backend"):
        assert fantome not in SRC, fantome
    # champs obligatoires de VHostCreate / BackendCreate envoyés
    assert "name: EDIT_VHOST || domaine" in SRC and "servers, mode" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"running": True, "http_port": 80, "https_port": 443, "stats_port": 8404, "waf_enabled": True, "waf_available": True, "vhost_count": 2, "backend_count": 1}
COMPOSANTS = {"components": [{"name": "HAProxy Service", "description": "Load balancer", "running": True, "config_path": "/etc/haproxy/haproxy.cfg"},
                             {"name": "WAF Inspector", "description": "sbxwaf", "enabled": True, "available": False, "port": 8085}]}
ACCES = {"access": [{"name": "HTTPS Frontend", "type": "frontend", "port": 443, "url": "https://{{hostname}}:443"},
                    {"name": "x.exemple.org", "type": "vhost", "url": "javascript:alert(1)", "waf_protected": True}]}
VHOSTS = {"vhosts": [{"name": "a.exemple.org", "domain": "a.exemple.org", "backend": "web", "ssl": True, "ssl_redirect": True, "acme": True, "waf_bypass": False, "enabled": True},
                     {"name": "b.exemple.org", "domain": "b.exemple.org", "backend": "web", "ssl": False, "waf_bypass": True, "enabled": False}]}
BACKENDS = {"backends": [{"name": "web", "servers": ["192.0.2.10:8080", "192.0.2.11:8080"], "mode": "http", "balance": "roundrobin"},
                         {"name": "waf_inspector", "type": "waf", "mode": "http", "port": 8085}]}
STATS = {"stats": [{"pxname": "http-in", "svname": "FRONTEND", "type": "0", "status": "OPEN", "scur": "3", "stot": "1000", "bin": "2048", "bout": "1048576"},
                   {"pxname": "web", "svname": "BACKEND", "type": "1", "status": "UP", "scur": "3", "stot": "1000", "bin": "2048", "bout": "1048576"},
                   {"pxname": "web", "svname": "srv0", "type": "2", "status": "DOWN", "scur": "0", "stot": "1000", "bin": "0", "bout": "0"}]}
CERTS = {"certificates": [{"name": "a_exemple_org", "path": "/etc/haproxy/certs/a_exemple_org.pem", "domains": ["a.exemple.org"], "issuer": "LE",
                           "expires_at": "2026-12-01T10:00:00", "days_until_expiry": 49, "expired": False},
                          {"name": "old_exemple_org", "path": "/etc/haproxy/certs/old_exemple_org.pem", "domains": ["old.exemple.org"], "issuer": "LE",
                           "expires_at": "2026-09-30T10:00:00", "days_until_expiry": -13, "expired": True}],
         "total": 2, "expiring_soon": 0, "expired": 1}
API = {"/status": (200, STATUS), "/components": (200, COMPOSANTS), "/access": (200, ACCES), "/vhosts": (200, VHOSTS),
       "/backends": (200, BACKENDS), "/stats": (200, STATS), "/certificates": (200, CERTS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "haproxy":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/haproxy", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(r.request.method + " " + chemin, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/haproxy/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def ecritures(appels):
    return [a for a in appels if a[0] != "GET"]


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/haproxy/", API)
    p.wait_for_selector("#bComp tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tService", "#tWaf", "#tVhosts", "#tBackends", "#tCerts")] == ["En marche", "Actif", "2", "1", "2"]
    # Requêtes = frontends seulement : 1 000 (l'ancienne page additionnait frontend + backend + serveur = 3 000)
    assert re.sub(r"\s", "", p.inner_text("#tReq")) == "1000"
    assert p.inner_text("#etat") == "EN MARCHE" and "1 expiré" in p.inner_text("#sCerts")
    assert "INDISPONIBLE" in p.inner_text("#bComp")
    p.click("#o-vhosts")
    assert "a.exemple.org" in p.inner_text("#bVhosts") and "CONTOURNÉ" in p.inner_text("#bVhosts")
    p.click("#o-backends")
    assert "192.0.2.10:8080" in p.inner_text("#bBack") and "INSPECTEUR WAF" in p.inner_text("#bBack")
    p.click("#o-stats")
    assert "http-in/FRONTEND" in p.inner_text("#bStats") and "DOWN" in p.inner_text("#bStats") and "1,0 Mo" in p.inner_text("#bStats")
    p.fill("#fStats", "srv0")
    assert p.locator("#bStats tr").count() == 1
    p.click("#o-certs")
    assert "EXPIRÉ" in p.inner_text("#bCerts") and "VALIDE" in p.inner_text("#bCerts") and "dans 49 j" in p.inner_text("#bCerts")
    p.click("#o-acces")
    # une URL non http(s) venue de l'API n'est jamais un lien
    assert p.locator("#bAcces a").count() == 1 and p.get_attribute("#bAcces a", "href").startswith("https://")
    assert err == []
    ctx.close()


def test_actions_demandent_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/haproxy/", API)
    p.click("#o-actions")
    p.wait_for_selector("#aReload")
    p.click("#aReload")
    assert p.is_visible("#conf") and not ecritures(appels)
    p.click("#confNon")
    assert not p.is_visible("#conf") and not ecritures(appels)
    p.click("#aReload")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('rechargé')")
    assert ("POST", "/reload", None) in appels
    p.click("#aGen")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('Configuration générée')")
    assert ("POST", "/generate", None) in appels
    ctx.close()


def test_echec_de_generation_est_affiche(navigateur):
    routes = {**API, "POST /generate": (200, {"success": False, "validation": "erreur de syntaxe ligne 4"})}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/haproxy/", routes)
    p.click("#o-actions")
    p.click("#aGen")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('syntaxe')")
    assert "ko" in p.get_attribute("#resultat", "class")
    ctx.close()


def test_bascule_waf_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/haproxy/", API)
    p.click("#o-actions")
    p.wait_for_selector("#aToggle")
    assert p.inner_text("#aToggle") == "Désactiver le WAF"
    p.click("#aToggle")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('envoyée')")
    post = [a for a in appels if a[1] == "/waf/toggle"][0]
    assert json.loads(post[2]) == {"enabled": False}
    p.click("#aSync")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('route')")
    assert ("POST", "/waf/sync-routes", None) in appels
    ctx.close()


def test_ajouter_un_vhost_envoie_nom_et_champs(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/haproxy/", API)
    p.click("#o-vhosts")
    p.click("#addVhost")
    p.fill("#fVhost [name=domain]", "c.exemple.org")
    p.select_option("#fVhost [name=backend]", "web")
    p.click("#fVhost button[type=submit]")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('ajouté')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/vhost"][0]
    assert json.loads(post[2]) == {"name": "c.exemple.org", "domain": "c.exemple.org", "backend": "web", "ssl": True, "ssl_redirect": True,
                                   "acme": True, "waf_bypass": False, "enabled": True}
    ctx.close()


def test_modifier_et_supprimer_un_vhost(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/haproxy/", API)
    p.click("#o-vhosts")
    p.wait_for_selector("#bVhosts td.act")
    p.locator("#bVhosts tr").first.get_by_text("Modifier").click()
    p.uncheck("#fVhost [name=acme]")
    p.click("#fVhost button[type=submit]")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('mis à jour')")
    put = [a for a in appels if a[0] == "PUT"][0]
    assert put[1] == "/vhost/a.exemple.org" and json.loads(put[2])["acme"] is False and json.loads(put[2])["name"] == "a.exemple.org"
    p.locator("#bVhosts tr").nth(1).get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('supprimé')")
    assert ("DELETE", "/vhost/b.exemple.org", None) in appels
    ctx.close()


def test_backend_et_certificat_sur_les_vraies_routes(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/haproxy/", API)
    p.click("#o-backends")
    p.click("#addBackend")
    p.fill("#fBackend [name=name]", "api")
    p.fill("#fBackend [name=servers]", "192.0.2.20:9000, 192.0.2.21:9000")
    p.click("#fBackend button[type=submit]")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('Backend ajouté')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/backend"][0]
    assert json.loads(post[2])["servers"] == ["192.0.2.20:9000", "192.0.2.21:9000"] and json.loads(post[2])["name"] == "api"
    p.locator("#bBack tr").first.get_by_text("Supprimer").click()
    p.click("#confOui")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('Backend « web » supprimé')")
    assert ("DELETE", "/backend/web", None) in appels
    p.click("#o-certs")
    p.click("#addCert")
    p.fill("#fCert [name=domain]", "d.exemple.org")
    p.check("#fCert [name=staging]")
    p.click("#fCert button[type=submit]")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('Certificat demandé')")
    acme = [a for a in appels if a[1] == "/certificates/acme"][0]
    assert json.loads(acme[2]) == {"domain": "d.exemple.org", "staging": True}
    p.locator("#bCerts tr").first.get_by_text("Supprimer").click()
    p.click("#confOui")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('Certificat « a_exemple_org » supprimé')")
    assert ("DELETE", "/certificates/a_exemple_org", None) in appels
    ctx.close()


def test_succes_false_est_un_echec(navigateur):
    routes = {**API, "POST /certificates/acme": (200, {"success": False, "error": "Challenge échoué"})}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/haproxy/", routes)
    p.click("#o-certs")
    p.click("#addCert")
    p.fill("#fCert [name=domain]", "d.exemple.org")
    p.click("#fCert button[type=submit]")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('Challenge')")
    assert "ko" in p.get_attribute("#resultat", "class")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/haproxy/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tService", "#tWaf", "#tVhosts", "#tBackends", "#tReq", "#tCerts")] == ["—"] * 6 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/haproxy/?demo=1", {})
    p.wait_for_selector("#bComp tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.inner_text("#tVhosts") == "3"
    p.click("#o-actions")
    p.click("#aReload")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('resultat').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/haproxy/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bComp tr td.mono", state="attached")
    for t in ("composants", "acces", "vhosts", "backends", "stats", "certs", "actions"):
        p.click("#o-" + t)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
