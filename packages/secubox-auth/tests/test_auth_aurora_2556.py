# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2556 — /auth/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "auth" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif_ni_secret():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "hybrid-dark" not in SRC and "crt-engine" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'auth'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    # aucun nouveau stockage : seulement la lecture du jeton existant
    assert "localStorage.setItem" not in SRC and "sessionStorage" not in SRC and "document.cookie" not in SRC


def test_routes_lues_et_ecriture_de_revocation_inchangee():
    for r in ("'/status'", "'/sessions'", "'/oauth_providers'", "/revoke_session?session_id="):
        assert r in SRC
    assert SRC.count("ecrire('") == 1 and "ecrire('POST', '/revoke_session" in SRC
    # routes et champs inexistants de l'ancienne page
    assert "'/providers'" not in SRC and "logins_today" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
STATUS = {"sessions": {"active": 2, "total": 3}, "vouchers": {"total": 12, "unused": 9, "used": 3}, "oauth_providers": ["github"], "timestamp": "2026-10-13T10:00:00"}
SESSIONS = {"count": 2, "sessions": [
    {"id": "aaaabbbbccccdddd", "type": "jwt", "username": "admin", "ip": "192.0.2.10", "user_agent": "Firefox", "created": "2026-10-13T09:00:00", "expires": NOW + 7200, "remaining_seconds": 7200},
    {"id": "1122334455667788", "type": "voucher", "voucher_code": "SBX-SECRETCODE", "client_ip": "203.0.113.5", "created": NOW - 60, "expires": NOW + 3600, "remaining_seconds": 3600}]}
PROVIDERS = {"providers": [{"id": "github", "configured": True, "enabled": True}, {"id": "google", "configured": False, "enabled": False}]}
API = {"/status": (200, STATUS), "/sessions": (200, SESSIONS), "/oauth_providers": (200, PROVIDERS),
       "/revoke_session": (200, {"success": True, "revoked": "aaaabbbbccccdddd"})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "auth":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/auth", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.url.split("?", 1)[1] if "?" in r.request.url else ""))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/auth/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/auth/", API)
    p.wait_for_selector("#bSess tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tActives", "#tTotal", "#tBons", "#tFourn")] == ["2", "3", "9", "2"]
    assert p.inner_text("#etat") == "EN SERVICE"
    t = p.inner_text("#bSess")
    assert "admin" in t and "192.0.2.10" in t and "203.0.113.5" in t and "dans 2 h" in t
    assert "1970" not in t and "aaaabbbb…" in t
    # jamais le code de bon complet ni l'identifiant entier
    assert "SECRETCODE" not in p.content() and "ccccdddd" not in t
    assert "github" in p.inner_text("#bFourn") and "DÉSACTIVÉ" in p.inner_text("#bFourn")
    assert err == []
    ctx.close()


def test_revocation_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/auth/", API)
    p.wait_for_selector("#bSess tr td.act button")
    p.locator("#bSess tr").first.get_by_text("Révoquer").click()
    assert p.is_visible("#confSess") and not [a for a in appels if a[0] == "POST"]
    p.click("#confNon")
    assert not p.is_visible("#confSess") and not [a for a in appels if a[0] == "POST"]
    p.locator("#bSess tr").first.get_by_text("Révoquer").click()
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rSess').textContent.includes('révoquée')")
    assert ("POST", "/revoke_session", "session_id=aaaabbbbccccdddd") in appels
    assert err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/auth/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tActives", "#tTotal", "#tBons", "#tFourn")] == ["—"] * 4 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/auth/?demo=1", {})
    p.wait_for_selector("#bSess tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bSess tr").first.get_by_text("Révoquer").click()
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rSess').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/auth/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bSess tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
