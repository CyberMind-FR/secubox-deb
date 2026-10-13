# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2556 — /vhost/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "vhost" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "hybrid-dark" not in SRC and "hybrid-skin" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'vhost'" in SRC and "demo" in SRC and "embed" in SRC
    assert "sbx_token" in SRC


def test_routes_d_ecriture_a_l_identique():
    # mêmes routes, méthodes et corps que l'ancienne page
    for attendu in (
        "ecrire('POST', '/vhost', { domain, backend, tls_mode: f.tls_mode.value, websocket: f.websocket.value === 'true' })",
        "ecrire('PUT', '/vhost/' + encodeURIComponent(domaine), { enabled: activer })",
        "ecrire('DELETE', '/vhost/' + encodeURIComponent(domaine))",
        "ecrire('POST', '/vhost/' + encodeURIComponent(domaine) + '/anti-robots', { enabled: voulu })",
        "ecrire('POST', '/certificate/issue', { domain: domaine, email })",
        "ecrire('POST', '/reload')",
    ):
        assert attendu in SRC, attendu
    for lecture in ("'/status'", "'/vhosts'", "'/certificates'", "'/access'"):
        assert lecture in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _fin(jours):
    return (datetime.now(timezone.utc) + timedelta(days=jours)).strftime("%b %d %H:%M:%S %Y GMT")


STATUS = {"running": True, "vhost_count": 3, "enabled_count": 2, "cert_count": 3,
          "components": {"nginx": {"running": True, "version": "1.22.1"}, "acme": {"installed": True}}}
VHOSTS = {"count": 3, "vhosts": [
    {"domain": "wiki.example.net", "backend": "http://192.0.2.10:3000", "tls_mode": "haproxy", "ssl": True, "enabled": True,
     "nginx_enabled": True, "haproxy_routed": True, "url": "https://wiki.example.net", "source": "nginx",
     "exposure": {"reach": "wan", "mesh": False}, "anti_robots": True, "module": {"id": "wiki", "certain": True, "runtime": "lxc"}},
    {"domain": "nas.example.net", "backend": "http://192.0.2.20:5000", "tls_mode": "off", "ssl": False, "enabled": False,
     "nginx_enabled": False, "haproxy_routed": False, "url": None, "source": "nginx",
     "exposure": {"reach": "lan", "mesh": True}, "anti_robots": False, "module": None},
    {"domain": "chess.example.net", "backend": "192.0.2.30:8081", "tls_mode": "haproxy", "ssl": True, "enabled": True,
     "nginx_enabled": False, "haproxy_routed": True, "url": "https://chess.example.net", "source": "haproxy",
     "exposure": {"reach": "wan", "mesh": False}, "anti_robots": False, "module": None}]}
CERTS = {"count": 3, "certificates": [
    {"domain": "wiki.example.net", "expires": _fin(60), "issuer": "CN=R11,O=Let's Encrypt,C=US"},
    {"domain": "nas.example.net", "expires": _fin(9), "issuer": "CN=R11,O=Let's Encrypt,C=US"},
    {"domain": "*.example.net", "expires": _fin(-3), "issuer": ""}]}
ACCESS = {"vhosts": [{"domain": "wiki.example.net", "url": "https://wiki.example.net", "backend": "http://192.0.2.10:3000", "ssl": True, "enabled": True}]}
API = {"/status": (200, STATUS), "/vhosts": (200, VHOSTS), "/certificates": (200, CERTS), "/access": (200, ACCESS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "vhost":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/vhost", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get((r.request.method, chemin), (200, {"success": True, "reload_required": False}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/vhost/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/vhost/", API)
    p.wait_for_selector("#bVhosts tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tVhosts", "#tFichiers", "#tNginx", "#tCerts", "#tBientot", "#tExpires")] == ["3", "3", "Actif", "3", "1", "1"]
    assert p.inner_text("#etat") == "NGINX ACTIF" and "activés : 2" in p.inner_text("#sFichiers")
    t = p.inner_text("#bVhosts")
    assert "wiki.example.net" in t and "HAPROXY" in t and "DÉSACTIVÉ" in t and "route HAProxy sans fichier nginx" in t
    assert p.locator("#bVhosts input[type=checkbox]").first.is_checked()
    p.click("#o-certs")
    c = p.inner_text("#bCerts")
    assert "EXPIRÉ" in c and "CRITIQUE" in c and "VALIDE" in c and "R11" in c
    p.click("#o-acces")
    assert "https://wiki.example.net" in p.inner_text("#bAcces")
    assert err == []
    ctx.close()


def test_supprimer_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/vhost/", {**API, ("DELETE", "/vhost/wiki.example.net"): (200, {"success": True, "reload_required": True})})
    p.click("#o-vhosts"); p.wait_for_selector("#bVhosts tr td.act")
    p.locator("#bVhosts tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    assert p.is_visible("#conf") and "Supprimer le vhost wiki.example.net" in p.inner_text("#conf")
    p.locator("#conf").get_by_text("Annuler").click()
    assert not p.is_visible("#conf") and not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bVhosts tr").first.get_by_text("Supprimer").click()
    p.locator("#conf").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('supprimé')")
    assert ("DELETE", "/vhost/wiki.example.net", None) in appels
    assert ("POST", "/reload", None) in appels          # reload_required honoré comme avant
    assert err == []
    ctx.close()


def test_creation_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/vhost/", API)
    p.click("#o-vhosts"); p.click("#addVhost")
    p.fill("#fVhost [name=domain]", "neuf.example.net"); p.fill("#fVhost [name=backend]", "http://192.0.2.50:3000")
    p.select_option("#fVhost [name=tls_mode]", "acme"); p.select_option("#fVhost [name=websocket]", "true")
    p.click("#fVhost button[type=submit]")
    p.wait_for_function("document.getElementById('retour').textContent.includes('créé')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/vhost"][0]
    assert json.loads(post[2]) == {"domain": "neuf.example.net", "backend": "http://192.0.2.50:3000", "tls_mode": "acme", "websocket": True}
    ctx.close()


def test_bascule_anti_robots_et_certificat(navigateur):
    routes = {**API, ("POST", "/vhost/nas.example.net/anti-robots"): (200, {"anti_robots": True})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/vhost/", routes)
    p.click("#o-vhosts"); p.wait_for_selector("#bVhosts tr td.act")
    p.locator("#bVhosts tr").nth(1).locator("input[type=checkbox]").check()
    p.wait_for_function("document.getElementById('retour').textContent.includes('Anti-robots activé')")
    assert json.loads([a for a in appels if a[1].endswith("/anti-robots")][0][2]) == {"enabled": True}
    p.locator("#bVhosts tr").nth(1).get_by_text("Activer").click()
    p.locator("#conf").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('activé')")
    assert json.loads([a for a in appels if a[0] == "PUT"][0][2]) == {"enabled": True}
    p.click("#o-certs"); p.locator("#bCerts tr").first.get_by_text("Renouveler").click()
    assert p.input_value("#confChamp") == "admin@example.net"       # le générique *. n'entre pas dans l'adresse
    p.locator("#conf").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('Renouvellement')")
    assert json.loads([a for a in appels if a[1] == "/certificate/issue"][0][2]) == {"domain": "*.example.net", "email": "admin@example.net"}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/vhost/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tVhosts", "#tFichiers", "#tNginx", "#tCerts", "#tBientot", "#tExpires")] == ["—"] * 6 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/vhost/?demo=1", {})
    p.wait_for_selector("#bVhosts tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#o-vhosts"); p.locator("#bVhosts tr").first.get_by_text("Supprimer").click()
    p.locator("#conf").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    p.locator("#bVhosts tr").first.locator("input[type=checkbox]").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('Anti-robots non appliqué')")
    assert p.locator("#bVhosts tr").first.locator("input[type=checkbox]").is_checked()   # revient à l'état réel
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/vhost/?embed=1&demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bVhosts tr td.mono", state="attached")
    for onglet in ("o-vhosts", "o-acces", "o-certs"):
        p.click("#" + onglet)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
