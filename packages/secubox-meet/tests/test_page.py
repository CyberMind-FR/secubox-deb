# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Page /meet/ au profil Aurora (#3154) : tests statiques, puis vrai navigateur avec API simulée."""
import json
import re
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
PAGE = RACINE / "www" / "meet" / "index.html"
APPARMOR = RACINE / "apparmor" / "secubox-meet"
MENU = RACINE / "menu.d" / "625-meet.json"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "https://", "http://"):
        assert interdit not in SRC
    assert "sbxVue" in SRC and "onglet:'meet'" in SRC and "sbx_token" in SRC and "demo" in SRC and "embed" in SRC


def test_ecritures_portent_la_confirmation():
    assert '"confirmer":"meet"' in SRC.replace(" ", "")
    for route in ("'/media-expose'", "'/control'", "'/oidc'", "'/oidc/enregistrer'", "'/status'"):
        assert route in SRC


def test_profil_apparmor_refuse_les_secrets():
    p = APPARMOR.read_text()
    assert "deny /etc/secubox/secrets/** r," in p and "/run/secubox/meet.sock" in p and "profile secubox-meet-api" in p
    assert "complain" not in p and "/usr/bin/sudo Ux," in p


def test_menu_exact():
    assert json.loads(MENU.read_text()) == {
        "id": "meet", "domain": "visio.gk2.secubox.in", "name": "Visio (Meet)", "icon": "🎥", "path": "/meet/",
        # #3313 : « communication » hors des six catégories de la charte (test_menu_categories du hub) : mesh, comme jitsi
        "category": "mesh", "order": 625, "description": "Visioconférence La Suite Meet", "theme": "correspondance"}


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"module": "meet", "version": "0.1.0", "installed": True, "container": "running", "domain": "visio.example.org",
          "livekit_domain": "livekit.example.org", "lxc_ip": "10.100.0.195", "web_reachable": True,
          "services": {"postgresql": "active", "redis": "active", "livekit": "active", "meet-backend": "failed", "nginx": "active"},
          "media": {"tcp_port": 7881, "udp_port": 7882, "exposed": False}, "oidc": {"client_registered": True}}
OIDC = {"issuer": "https://hall.example.org/oidc", "discovery": True, "jwks": True, "keys": 1, "redirect_registered": True, "hint": ""}
API = {"/status": (200, STATUS), "/media-expose": (200, {"exposed": False}), "/oidc": (200, OIDC),
       "/logs": (200, {"unit": "meet-backend", "lines": ["ligne un", "<b>ligne deux</b>"]})}


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
        elif chemin.rstrip("/") == "meet":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/meet", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (200, {"success": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/meet/**", api)
    p.goto(url)
    p.dialogues = dialogues
    return ctx, p, erreurs, appels


def test_tuiles_et_services_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/meet/", API)
    p.wait_for_function("document.getElementById('tEtat').textContent !== '—'")
    assert p.inner_text("#tEtat") == "EN MARCHE" and p.inner_text("#tMedia") == "NON"
    assert p.inner_text("#tServ") == "4/5" and p.inner_text("#tOidc") == "ENREGISTRÉ"
    assert p.locator("#lServ .svc").count() == 5 and "FAILED" in p.inner_text("#lServ")
    assert err == []
    ctx.close()


def test_sans_session_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/meet/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert [p.inner_text(i) for i in ("#tEtat", "#tServ", "#tMedia", "#tOidc")] == ["—"] * 4 and err == []
    ctx.close()


def test_ports_media_exigent_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/meet/", API)
    p.wait_for_function("document.getElementById('tEtat').textContent !== '—'")
    p.click("#o-media")
    p.click("#mediaAction")
    assert p.is_visible("#conf") and "7881" in p.inner_text("#confTexte")
    assert not [a for a in appels if a[0] == "POST"]
    p.click("#confNon")
    assert not p.is_visible("#conf") and not [a for a in appels if a[0] == "POST"]
    p.click("#mediaAction"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rMedia').textContent.includes('ouverts')")
    posts = [(a[1], json.loads(a[2])) for a in appels if a[0] == "POST"]
    assert posts == [("/media-expose", {"action": "apply", "confirmer": "meet"})]
    assert p.dialogues == []
    ctx.close()


def test_arreter_demande_une_confirmation(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/meet/", API)
    p.wait_for_function("document.getElementById('bascule').textContent === 'Arrêter'")
    p.click("#bascule")
    assert p.is_visible("#conf") and not [a for a in appels if a[0] == "POST"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('arrêté')")
    assert [json.loads(a[2]) for a in appels if a[1] == "/control"] == [{"action": "stop"}]
    ctx.close()


def test_operation_en_cours_est_annoncee(navigateur):
    routes = {**API, "/control": (200, {"success": True, "pending": True})}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/meet/", routes)
    p.wait_for_function("document.getElementById('bascule').textContent === 'Arrêter'")
    p.click("#bascule"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('En cours')")
    ctx.close()


def test_identite_et_journaux_en_texte_brut(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/meet/", API)
    p.click("#o-identite"); p.click("#oidcVerif")
    p.wait_for_function("document.getElementById('oidcRes').textContent.includes('hall.example.org')")
    p.click("#o-journaux")
    p.wait_for_function("document.getElementById('journal').textContent.includes('ligne un')")
    assert "<b>ligne deux</b>" in p.inner_text("#journal") and p.locator("#journal b").count() == 0
    assert any(a[1] == "/oidc" for a in appels) and any(a[1] == "/logs" for a in appels) and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/meet/?demo=1", {})
    p.wait_for_function("document.getElementById('tServ').textContent === '5/5'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#bascule"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('inerte')")
    assert appels == [] and err == [] and "Échec" not in p.inner_text("#rServ")
    assert "ko" not in (p.get_attribute("#rServ", "class") or "").split()
    ctx.close()


def test_largeur_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/meet/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tEtat').textContent !== '—'")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


def test_enregistrement_oidc_non_applique_est_annonce(navigateur):
    """I2 : meetctl dit quand le nouveau secret n'a pas atteint le conteneur ; la page le montre (sans « ok »)."""
    indication = "conteneur à l'arrêt : démarrez-le puis relancez l'enregistrement pour appliquer le secret"
    routes = {**API, "/oidc/enregistrer": (200, {"success": True, "applique": False, "hint": indication})}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/meet/", routes)
    p.click("#o-identite")
    p.click("#oidcEnreg")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rOidc').textContent.includes('relancez')")
    assert "pas encore appliqué" in p.inner_text("#rOidc")
    assert "ok" not in (p.get_attribute("#rOidc", "class") or "").split() and err == []
    ctx.close()
    routes = {**API, "/oidc/enregistrer": (200, {"success": True, "applique": True})}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/meet/", routes)
    p.click("#o-identite")
    p.click("#oidcEnreg")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rOidc').textContent.includes('enregistré')")
    assert p.inner_text("#rOidc") == "Client OIDC enregistré." and "ok" in p.get_attribute("#rOidc", "class").split()
    ctx.close()
