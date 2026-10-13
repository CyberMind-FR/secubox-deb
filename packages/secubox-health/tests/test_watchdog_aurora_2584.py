# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2584 — /watchdog/ au profil Aurora : tests statique + vrai navigateur, API simulée."""
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "composants" / "watchdog" / "www" / "watchdog" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "crt-engine" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'watchdog'" in SRC and "demo" in SRC and "embed" in SRC and "sbx_token" in SRC


def test_routes_d_ecriture_a_l_identique():
    # mêmes routes et mêmes corps que l'ancienne page ; aucune écriture nouvelle
    for r in ("'/container/restart'", "'/service/restart'", "'/check'", "'/logs/clear'"):
        assert r in SRC
    assert "{ name: nom }" in SRC
    ecritures = re.findall(r"ecrire\('(POST|DELETE|PUT)', ([^,)]+)", SRC)
    assert sorted(c for _, c in ecritures) == ["'/check'", "'/logs/clear'", "route"]
    for interdit in ("/webhooks", "/config'", "method: 'POST'"):
        assert not re.search(r"ecrire\([^)]*" + re.escape(interdit), SRC)


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def iso(s):
    return (datetime.now(timezone.utc) - timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


STATUS = {"health": "degraded", "timestamp": iso(3), "cached": False,
          "containers": [{"name": "mailserver", "state": "running", "pid": 4121, "critical": True},
                         {"name": "gitea", "state": "stopped", "pid": 0, "critical": False}],
          "services": [{"name": "nginx", "process": "nginx", "state": "running", "pid": 812, "critical": True}],
          "endpoints": [{"name": "Portail", "host": "localhost", "path": "/portal/", "code": 200, "healthy": True},
                        {"name": "API", "host": "localhost", "path": "/api/v1/hub/status", "code": 0, "healthy": False}]}
CONF = {"enabled": True, "interval": 60, "alert_cooldown": 300, "auto_recovery": True}
HIST = {"events": [{"id": "a", "type": "recovery_failed", "target": "gitea", "details": {"error": "<b>x</b>"}, "timestamp": iso(120)},
                   {"id": "b", "type": "recovery_success", "target": "nginx", "details": {}, "timestamp": iso(3 * 86400)}], "total": 2}
LOGS = {"lines": ["[2026-10-13 06:02:11] [WARNING] recovery_failed: gitea", "", "<img src=x onerror=window.__xss=1>"], "total": 3}
API = {"/status": (200, STATUS), "/config": (200, CONF), "/history": (200, HIST), "/logs": (200, LOGS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "watchdog":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/watchdog", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (200, {"success": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/watchdog/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/watchdog/", API)
    p.wait_for_selector("#bCont tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tConteneurs", "#tServices", "#tPoints", "#tProblemes", "#tSurv", "#tEvt")] == ["1/2", "1/1", "1/2", "2", "Active", "1"]
    # la santé globale vient de /status.health (l'ancienne page lisait enabled/running, absents)
    assert p.inner_text("#etat") == "DÉGRADÉ"
    assert "mailserver" in p.inner_text("#bCont") and "4121" in p.inner_text("#bCont") and "ARRÊTÉ" in p.inner_text("#bCont")
    # code 0 = injoignable : jamais « ✗ 0 »
    assert "INJOIGNABLE" in p.inner_text("#bPts") and "localhost/portal/" in p.inner_text("#bPts")
    assert "Relance échouée" in p.inner_text("#evts")
    # fichier de journal vide : la ligne vide n'est pas affichée ; contenu d'API jamais interprété en HTML
    assert p.inner_text("#nLog") == "2 ligne(s)" and "<img src=x" in p.inner_text("#logs")
    assert p.evaluate("window.__xss") is None and p.locator("#logs img, #evts b").count() == 0
    assert err == []
    ctx.close()


def test_redemarrer_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/watchdog/", API)
    p.wait_for_selector("#bCont tr td.act")
    p.locator("#bCont tr").first.get_by_text("Redémarrer").click()
    assert not [a for a in appels if a[0] == "POST"]          # pas encore : il faut confirmer
    assert "Redémarrer mailserver ?" in p.inner_text("#bCont")
    p.locator("#bCont").get_by_text("Annuler").click()
    assert not [a for a in appels if a[0] == "POST"]
    p.locator("#bCont tr").first.get_by_text("Redémarrer").click()
    p.locator("#bCont").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rCont').textContent.includes('redémarré')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/container/restart" and json.loads(post[2]) == {"name": "mailserver"}
    # service
    p.locator("#bServ tr").first.get_by_text("Redémarrer").click()
    p.locator("#bServ").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rServ').textContent.includes('redémarré')")
    assert ("POST", "/service/restart", json.dumps({"name": "nginx"}, separators=(",", ":"))) in appels
    ctx.close()


def test_echec_de_redemarrage_affiche_l_erreur(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/watchdog/", {**API, "/container/restart": (200, {"success": False, "error": "Container failed to start"})})
    p.wait_for_selector("#bCont tr td.act")
    p.locator("#bCont tr").first.get_by_text("Redémarrer").click()
    p.locator("#bCont").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rCont').textContent.includes('impossible')")
    assert "Container failed to start" in p.inner_text("#rCont")
    ctx.close()


def test_verification_et_vidage_du_journal(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/watchdog/", {**API, "/check": (200, {"success": True, "issues": ["Container gitea is stopped"]})})
    p.wait_for_selector("#bCont tr td.act")
    p.click("#verifier")
    p.wait_for_function("document.getElementById('rGlobal').textContent.includes('1 problème')")
    assert ("POST", "/check", None) in appels
    p.click("#viderLogs")
    assert not [a for a in appels if a[1] == "/logs/clear"] and "irréversible" in p.inner_text("#confLogs")
    p.click("#okLogs")
    p.wait_for_function("document.getElementById('rLogs').textContent.includes('vidé')")
    assert ("POST", "/logs/clear", None) in appels
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/watchdog/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tConteneurs", "#tServices", "#tPoints", "#tProblemes", "#tSurv", "#tEvt")] == ["—"] * 6
    assert "/login" not in p.url      # plus de redirection forcée
    assert err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/watchdog/?demo=1", {})
    p.wait_for_selector("#bCont tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bCont tr").first.get_by_text("Redémarrer").click()
    p.locator("#bCont").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rCont').textContent.includes('inerte')")
    p.click("#verifier")
    p.wait_for_function("document.getElementById('rGlobal').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/watchdog/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bCont tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
