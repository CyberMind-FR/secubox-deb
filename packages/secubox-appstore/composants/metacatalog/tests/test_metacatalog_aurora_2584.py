# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2584 — /metacatalog/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "metacatalog" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "/shared/crt-engine.js" not in SRC and "hybrid-dark" not in SRC and "crt-light" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onchange=", "onkeyup="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'metacatalog'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC


def test_routes_lues_et_ecriture_a_l_identique():
    for r in ("'/status'", "'/services'", "'/dependencies'", "'/service/'", "'/dependencies/'", "'/endpoints/'"):
        assert r in SRC
    # la seule écriture de l'ancienne page : POST /refresh, sans corps
    assert len(re.findall(r"ecrire\('(?:POST|PUT|DELETE|PATCH)'", SRC)) == 1
    assert "ecrire('POST', '/refresh')" in SRC
    assert "body:" not in SRC.split("async function ecrire", 1)[1].split("function toast", 1)[0]


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def svc(nom, statut, cat="system", deps=(), dependents=(), **kw):
    base = {"name": nom, "version": "1.0.0", "description": "Service " + nom, "status": statut, "category": cat, "dependencies": list(deps),
            "dependents": list(dependents), "installed": statut != "not_installed", "enabled": statut == "running",
            "socket": None if statut == "not_installed" else "/run/secubox/" + nom[8:] + ".sock", "systemd_unit": nom + ".service",
            "active_since": None, "memory_usage": None}
    base.update(kw)
    return base


LISTE = [svc("secubox-core", "running", dependents=["secubox-dpi", "secubox-qos"], active_since="Mon 2026-10-12 06:12:03 CEST", memory_usage="42.1 MB"),
         svc("secubox-dpi", "running", "security", deps=["secubox-core"]),
         svc("secubox-qos", "failed", "network", deps=["secubox-core"]),
         svc("secubox-turn", "stopped", "network", deps=["secubox-core"]),
         svc("secubox-glances", "not_installed", "monitoring", deps=["secubox-core"]),
         svc("secubox-xss", "running", "<img src=x onerror=window.__xss=1>")]
GRAPHE = {"nodes": [{"id": s["name"], "label": s["name"][8:], "status": s["status"], "category": s["category"], "installed": s["installed"]} for s in LISTE],
          "edges": [{"from": "secubox-core", "to": "secubox-dpi"}, {"from": "secubox-core", "to": "secubox-qos"}]}
API = {("GET", "/status"): (200, {"module": "metacatalog", "status": "running", "total_services": 6, "last_refresh": "2026-10-13T08:30:00"}),
       ("GET", "/services"): (200, {"services": LISTE, "count": 6}),
       ("GET", "/dependencies"): (200, GRAPHE),
       ("GET", "/service/secubox-core"): (200, LISTE[0]),
       ("GET", "/dependencies/secubox-core"): (200, {"service": "secubox-core", "direct_dependencies": [], "all_dependencies": [], "dependents": ["secubox-dpi", "secubox-qos"]}),
       ("GET", "/endpoints/secubox-dpi"): (200, {"service": "secubox-dpi", "base_path": "/api/v1/dpi", "socket": "/run/secubox/dpi.sock",
                                                  "endpoints": [{"method": "GET", "path": "/health", "description": "Sonde", "auth": False},
                                                                {"method": "GET", "path": "/status", "description": "État", "auth": True}]}),
       ("POST", "/refresh"): (200, {"success": True, "message": "Catalogue refreshed", "stats": {}})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "metacatalog":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/metacatalog", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get((r.request.method, chemin), (404, {"detail": "absent"}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/metacatalog/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableau_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/metacatalog/", API)
    p.wait_for_selector("#bServ tr td b", state="attached")
    assert [p.inner_text(i) for i in ("#tTotal", "#tMarche", "#tArret", "#tEchec", "#tInst", "#tNon")] == ["6", "3", "1", "1", "5", "1"]
    assert p.inner_text("#etat") == "CATALOGUE EN LIGNE" and "08:30:00" in p.inner_text("#maj")
    tab = p.inner_text("#bServ")
    assert "EN ÉCHEC" in tab and "NON INSTALLÉ" in tab and "ARRÊTÉ" in tab
    # catégories dérivées des données (plus de liste en dur), y compris une catégorie inattendue
    assert "monitoring" in p.inner_text("#fCat")
    # aucune donnée d'API n'est interprétée comme du HTML
    assert p.evaluate("window.__xss") is None and p.locator("#bServ img").count() == 0
    assert err == []
    ctx.close()


def test_filtres_cote_client(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/metacatalog/", API)
    p.wait_for_selector("#bServ tr td b", state="attached")
    p.select_option("#fEtat", "failed")
    assert p.locator("#bServ tr").count() == 1 and "qos" in p.inner_text("#bServ")
    p.select_option("#fEtat", ""); p.check("#fInst")
    assert p.locator("#bServ tr").count() == 5
    p.fill("#fRech", "dpi")
    assert p.locator("#bServ tr").count() == 1
    ctx.close()


def test_detail_dans_la_page_avec_dependances(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/metacatalog/", API)
    p.wait_for_selector("#bServ tr td b", state="attached")
    p.locator("#bServ tr").first.get_by_text("Détail").click()
    p.wait_for_selector("#detail:not([hidden])")
    assert p.inner_text("#dNom") == "secubox-core" and p.inner_text("#dMem") == "42.1 MB"
    assert "dpi" in p.inner_text("#dUtil") and p.inner_text("#dDeps") == "—"
    assert ("GET", "/service/secubox-core") in [(a[0], a[1]) for a in appels]
    p.keyboard.press("Escape")
    assert not p.is_visible("#detail") and err == []
    ctx.close()


def test_graphe_et_routes_d_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/metacatalog/", API)
    p.wait_for_selector("#bServ tr td b", state="attached")
    p.click("#o-dependances")
    assert p.locator("#carte g.noeud").count() == 6 and p.locator("#carte line").count() == 2 and "2 liens" in p.inner_text("#nGraphe")
    p.click("#o-endpoints")
    assert p.locator("#eSel option").count() == 1 + 3          # seuls les services en marche, plus le choix vide
    p.select_option("#eSel", "secubox-dpi")
    p.wait_for_selector("#eListe .ep")
    assert p.locator("#eListe .ep").count() == 2 and "JETON" in p.inner_text("#eListe") and "/api/v1/dpi" in p.inner_text("#eBase")
    assert not p.is_hidden("#eNote")      # liste standard : annoncée comme telle
    assert err == []
    ctx.close()


def test_actualiser_poste_refresh_sans_corps_avec_jeton(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/metacatalog/", API)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.wait_for_selector("#bServ tr td b", state="attached")
    p.click("#rafraichir")
    p.wait_for_function("document.getElementById('toast').textContent.includes('recalculé')")
    posts = [a for a in appels if a[0] == "POST"]
    assert [(a[1], a[2]) for a in posts] == [("/refresh", None)] and posts[0][3] == "Bearer jeton-test"
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/metacatalog/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tTotal", "#tMarche", "#tArret", "#tEchec", "#tInst", "#tNon")] == ["—"] * 6 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/metacatalog/?demo=1", {})
    p.wait_for_selector("#bServ tr td b", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and p.inner_text("#tTotal") == "10"
    p.click("#rafraichir")
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    p.locator("#bServ tr").first.get_by_text("Détail").click()
    p.click("#o-endpoints"); p.select_option("#eSel", "secubox-dpi")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/metacatalog/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bServ tr td b", state="attached")
    for o in ("#o-dependances", "#o-endpoints", "#o-services"):
        p.click(o)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
