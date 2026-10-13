# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2571 — /routes/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "routes" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "/shared/crt-engine.js" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'routes'" in SRC and "demo" in SRC and "embed" in SRC and "sbx_token" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("ecrire('DELETE', '/routes', corps)", "ecrire('DELETE', '/rules/'", "ecrire('POST', '/rules', corps)",
              "ecrire('POST', '/routes', corps)", "ecrire('POST', '/flush')"):
        assert r in SRC
    for lecture in ("'/status'", "'/routes'", "'/rules'", "'/tables'", "'/neighbors'"):
        assert lecture in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"module": "routes", "status": "running", "ipv4_routes": 2, "ipv6_routes": 1, "rules": 2, "neighbors": 3}
ROUTES = {"ipv4": [{"destination": "default", "gateway": "192.0.2.1", "interface": "eth0", "metric": 100, "protocol": "dhcp"},
                   {"destination": "198.51.100.0/24", "gateway": None, "interface": "wg0", "metric": 0, "protocol": "kernel"}],
          "ipv6": [{"destination": "2001:db8::/64", "gateway": None, "interface": "eth0", "metric": 256, "protocol": "kernel"}], "total": 3}
RULES = {"ipv4": [{"priority": 0, "selector": "all", "action": "lookup", "table": "local"},
                  {"priority": 100, "selector": "from 192.0.2.0/24", "action": "lookup", "table": "wan2"}],
         "ipv6": [{"priority": 0, "selector": "all", "action": "lookup", "table": "local"}], "total": 3}
TABLES = {"tables": [{"id": 254, "name": "main"}, {"id": 100, "name": "wan2"}]}
NEIGH = {"arp": [{"ip": "192.0.2.1", "mac": "02:00:5e:00:53:01", "interface": "eth0", "state": "REACHABLE", "family": "inet"},
                 {"ip": "192.0.2.9", "mac": None, "interface": "eth0", "state": "FAILED", "family": "inet"}],
         "ndp": [{"ip": "2001:db8::1", "mac": "02:00:5e:00:53:02", "interface": "eth0", "state": "STALE", "family": "inet6"}], "total": 3}
OK = (200, {"success": True, "message": "Operation completed"})
API = {"/status": (200, STATUS), "/routes": (200, ROUTES), "/rules": (200, RULES), "/tables": (200, TABLES), "/neighbors": (200, NEIGH)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "routes":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/routes", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get((r.request.method, chemin), routes.get(chemin, (404, {}))) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/routes/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/routes/", API)
    p.wait_for_selector("#bRoutes tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tV4", "#tV6", "#tRegles", "#tVoisins")] == ["2", "1", "2", "3"]
    assert p.inner_text("#etat") == "EN SERVICE"
    t = p.inner_text("#bRoutes")
    assert "198.51.100.0/24" in t and "2001:db8::/64" in t and "IPv6" in t
    # métrique 0 est une mesure ; passerelle absente = tiret
    assert p.locator("#bRoutes tr").nth(1).locator("td").nth(4).inner_text() == "0"
    assert p.locator("#bRoutes tr").nth(1).locator("td").nth(2).inner_text() == "—"
    p.click("#o-regles")
    assert p.get_attribute("#o-regles", "aria-selected") == "true" and p.is_visible("#t-regles") and not p.is_visible("#t-routes")
    assert "wan2" in p.inner_text("#bRegles") and "main" in p.inner_text("#bTables")
    p.click("#o-voisins")
    assert "REACHABLE" in p.inner_text("#bArp") and "FAILED" in p.inner_text("#bArp") and "2001:db8::1" in p.inner_text("#bNdp")
    assert err == []
    ctx.close()


def test_filtre_famille_et_texte(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/routes/", API)
    p.wait_for_selector("#bRoutes tr td.mono", state="attached")
    p.select_option("#famRoutes", "ipv6")
    assert p.locator("#bRoutes tr").count() == 1
    p.select_option("#famRoutes", "all"); p.fill("#filtreRoutes", "wg0")
    assert p.locator("#bRoutes tr").count() == 1 and "198.51.100.0/24" in p.inner_text("#bRoutes")
    ctx.close()


def test_supprimer_une_route_confirme_dans_la_page_et_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/routes/", {**API, ("DELETE", "/routes"): OK})
    p.wait_for_selector("#bRoutes tr td.act")
    p.locator("#bRoutes tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bRoutes tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rRoutes').textContent.includes('supprimée')")
    assert json.loads([a for a in appels if a[0] == "DELETE"][0][2]) == {"destination": "default", "gateway": "192.0.2.1", "interface": "eth0"}
    ctx.close()


def test_ajouter_une_route_et_erreur_success_false(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/routes/", {**API, ("POST", "/routes"): (200, {"success": False, "error": "RTNETLINK answers: File exists"})})
    p.click("#addRoute")
    p.fill("#fRoute [name=destination]", "203.0.113.0/24"); p.fill("#fRoute [name=gateway]", "192.0.2.1"); p.fill("#fRoute [name=metric]", "50")
    p.click("#fRoute button[type=submit]")
    p.wait_for_function("document.getElementById('rRoutes').textContent.includes('File exists')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/routes"][0]
    assert json.loads(post[2]) == {"destination": "203.0.113.0/24", "gateway": "192.0.2.1", "metric": 50}
    ctx.close()


def test_regles_ajout_suppression_et_ipv6_en_lecture_seule(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/routes/", {**API, ("POST", "/rules"): OK, ("DELETE", "/rules/100"): OK})
    p.click("#o-regles"); p.wait_for_selector("#bRegles tr td.act")
    assert p.locator("#bRegles tr").filter(has_text="IPv6").get_by_text("Supprimer").count() == 0
    p.locator("#bRegles tr").filter(has_text="wan2").get_by_text("Supprimer").click()
    p.locator("#bRegles tr").filter(has_text="wan2").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rRegles').textContent.includes('supprimée')")
    assert ("DELETE", "/rules/100", None) in appels
    p.click("#addRegle"); p.fill("#fRegle [name=priority]", "200"); p.fill("#fRegle [name=from]", "192.0.2.0/24"); p.fill("#fRegle [name=table]", "wan2")
    p.click("#fRegle button[type=submit]")
    p.wait_for_function("document.getElementById('rRegles').textContent.includes('ajoutée')")
    assert json.loads([a for a in appels if a[0] == "POST" and a[1] == "/rules"][0][2]) == {"priority": 200, "from": "192.0.2.0/24", "table": "wan2"}
    ctx.close()


def test_vider_le_cache_demande_confirmation(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/routes/", {**API, ("POST", "/flush"): OK})
    p.wait_for_selector("#bRoutes tr td.act")
    p.get_by_role("button", name="Vider le cache").click()
    assert not [a for a in appels if a[1] == "/flush"]
    p.locator("#zVidage").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rRoutes').textContent.includes('vidé')")
    assert ("POST", "/flush", None) in appels
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/routes/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tV4", "#tV6", "#tRegles", "#tVoisins")] == ["—"] * 4 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/routes/?demo=1", {})
    p.wait_for_selector("#bRoutes tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bRoutes tr").first.get_by_text("Supprimer").click()
    p.locator("#bRoutes tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rRoutes').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/routes/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bRoutes tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    p.click("#o-regles"); p.click("#addRegle")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
