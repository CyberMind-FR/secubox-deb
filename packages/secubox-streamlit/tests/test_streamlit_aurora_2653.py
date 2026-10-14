# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2653 — /streamlit/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices).

Zéro appli en ligne n'est pas une panne (#982) : l'état vide doit le dire."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "streamlit" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
NOW = int(time.time())


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert not re.findall(r"<script src=", SRC)          # le menu commun est injecté hors embed/démo
    assert "/shared/sidebar.js" in SRC and "!EMBED && !DEMO" in SRC
    assert "hybrid-" not in SRC and "crt-" not in SRC and "fonts.googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "<iframe"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'streamlit'" in SRC and "DEMO" in SRC and "embed" in SRC


def test_routes_et_ecritures_a_l_identique():
    for r in ("'/apps/audit'", "'/status'", "'/health'", "'/components'", "'/access'", "'/apps'", "'/instances'",
              "'/wake', { method: 'POST' }", "'/recapture', { method: 'POST' }", "'/screenshot?t='",
              "'/start?port='", "'/stop', { method: 'POST' }", "{ method: 'DELETE' }",
              "'/instance/'", "'/container/start'", "'/container/stop'", "'/container/install'",
              "'/gitea/clone/'", "JSON.stringify({ repo })", "API + '/deploy'", "form.append('file'"):
        assert r in SRC, r
    assert "localStorage.getItem('sbx_token')" in SRC and "Bearer" in SRC
    assert "pollWakeUntilRunning" in SRC and "r.status === 'running'" in SRC


def test_onglets_accessibles_et_pas_de_secret():
    assert 'role="tablist"' in SRC and SRC.count('role="tab"') == 5 and SRC.count('role="tabpanel"') == 5
    assert "aria-selected" in SRC and "focus-visible" in SRC
    assert "setItem(WAKE" in SRC or "setItem(WAKE_DURATIONS_KEY" in SRC
    assert "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def app(nom, etat, **kw):
    return {"name": nom, "state": etat, "shape": "app.py", "domain": "", "last_active": NOW - 60, "sleep_after_seconds": 900, **kw}


AUDIT_ZERO = {"available": True, "cache_age_seconds": 30, "apps": [app("alpha", "sleeping"), app("beta", "sleeping", domain="beta.example.org"), app("gamma", "archived")]}
AUDIT_UN = {"available": True, "cache_age_seconds": 30, "apps": [app("alpha", "running", port=8501, domain="a.example.org", issues=["stale-port"]), app("beta", "sleeping", domain="beta.example.org")]}
STATUS = {"app_count": 2, "running_apps": 0, "instance_count": 1, "container_status": "running"}
BASE = {
    "/apps/audit": (200, AUDIT_ZERO), "/status": (200, STATUS),
    "/health": (200, {"checks": {"api": "ok", "container": "running"}}),
    "/components": (200, {"components": [{"name": "streamlitctl", "description": "ctl", "installed": True}]}),
    "/access": (200, {"access": []}),
    "/apps": (200, {"apps": [{"name": "alpha", "main": "app.py", "port": 8501, "running": True}, {"name": "beta", "main": "main.py", "running": False}]}),
    "/instances": (200, {"instances": [{"id": "i1", "app": "alpha", "port": 8511, "running": False}]}),
}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "streamlit":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/streamlit", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        defaut = (404, {}) if r.request.method == "GET" else (200, {"success": True})
        statut, corps = routes.get(chemin, defaut)
        if callable(corps):
            corps = corps()
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/streamlit/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def ecritures(appels):
    return [a for a in appels if a[0] != "GET"]


def test_zero_appli_en_ligne_est_dit_normal(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/streamlit/", BASE)
    p.wait_for_function("document.getElementById('fTotal').textContent === '3'")
    assert [p.inner_text(i) for i in ("#fTotal", "#fEnLigne", "#fDort", "#fArch", "#fAnom")] == ["3", "0", "2", "1", "0"]
    assert p.is_visible("#veilleNote") and "pas une panne" in p.inner_text("#veilleNote")
    assert p.inner_text("#etat") == "EN VEILLE"
    assert p.get_attribute("#fEnLigne >> xpath=..", "title") and "Zéro est normal" in p.get_attribute("#fEnLigne >> xpath=..", "title")
    p.click("#t-acces")
    p.wait_for_function("document.getElementById('acces').textContent.includes('normal')")
    assert err == []
    ctx.close()


def test_onglets_aria_selected_et_clavier(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/streamlit/", BASE)
    p.wait_for_selector("#sante .ligne")
    assert p.get_attribute("#t-etat", "aria-selected") == "true" and p.get_attribute("#t-mosaic", "aria-selected") == "false"
    p.focus("#t-etat"); p.keyboard.press("ArrowRight")
    assert p.get_attribute("#t-acces", "aria-selected") == "true" and p.is_hidden("#v-etat") and p.is_visible("#v-acces")
    p.click("#t-instances")
    p.wait_for_selector("#bInst td strong")
    assert "i1" in p.inner_text("#bInst")
    assert err == []
    ctx.close()


def test_mosaique_reveil_poll_et_ouverture(navigateur):
    reveil = {"/apps/beta/wake": (200, {"status": "running"})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamlit/?onglet=mosaic", {**BASE, **reveil})
    p.wait_for_selector("button[data-wake]")
    assert "réveiller et ouvrir" in p.inner_text("#mur")
    assert p.locator("#mur img").count() == 0
    p.evaluate("window.__ouvert = []; window.open = (u, ...r) => { if (u) window.__ouvert.push(u); return null; }")
    p.locator("button[data-wake='beta']").click()
    p.wait_for_function("window.__ouvert.length === 1")
    assert p.evaluate("window.__ouvert[0]") == "https://beta.example.org/"
    assert any(a[:2] == ("POST", "/apps/beta/wake") for a in appels)
    assert err == []
    ctx.close()


def test_mosaique_appli_en_ligne_recapture_et_lien(navigateur):
    routes = {**BASE, "/apps/audit": (200, AUDIT_UN), "/apps/alpha/recapture": (200, {"triggered": True})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamlit/?onglet=mosaic", routes)
    p.wait_for_selector("button[data-recapture]")
    assert p.get_attribute("#mur a", "href") == "https://a.example.org/"
    assert "port périmé" in p.inner_text("#mur")
    p.click("button[data-recapture]")
    p.wait_for_function("document.getElementById('toast').textContent.includes('capture')")
    assert any(a[:2] == ("POST", "/apps/alpha/recapture") for a in appels)
    assert p.inner_text("#fAnom") == "1"
    assert err == []
    ctx.close()


def test_demarrer_arreter_supprimer_avec_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamlit/?onglet=applis", BASE)
    p.wait_for_selector("#bApps tr td.act")
    ligne = p.locator("#bApps tr")
    ligne.nth(1).get_by_text("Démarrer").click()
    p.fill("#portDemarre", "8555")
    ligne.nth(1).get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rApps').textContent.includes('Démarrage')")
    assert any(a[:2] == ("POST", "/app/beta/start") for a in appels)
    ligne.nth(0).get_by_text("Arrêter").click()
    p.wait_for_function("document.getElementById('rApps').textContent.includes('arrêtée')")
    assert any(a[:2] == ("POST", "/app/alpha/stop") for a in appels)
    p.locator("#bApps tr").nth(0).get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]           # il faut confirmer
    p.locator("#bApps tr").nth(0).get_by_text("Annuler").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#bApps tr").nth(0).get_by_text("Supprimer").click()
    p.locator("#bApps tr").nth(0).get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rApps').textContent.includes('supprimée')")
    assert any(a[:2] == ("DELETE", "/app/alpha") for a in appels)
    assert err == []
    ctx.close()


def test_demarrage_envoie_le_port_en_requete(navigateur):
    vus = []
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/streamlit/?onglet=applis", BASE)
    p.on("request", lambda r: vus.append(r.url))
    p.wait_for_selector("#bApps tr td.act")
    p.locator("#bApps tr").nth(1).get_by_text("Démarrer").click()
    p.fill("#portDemarre", "8555")
    p.locator("#bApps tr").nth(1).get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rApps').textContent.includes('Démarrage')")
    assert any(u.endswith("/api/v1/streamlit/app/beta/start?port=8555") for u in vus)
    ctx.close()


def test_instances_et_conteneur(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamlit/?onglet=instances", BASE)
    p.wait_for_selector("#bInst td.act")
    p.locator("#bInst").get_by_text("Démarrer").click()
    p.wait_for_function("document.getElementById('rInst').textContent.includes('démarrage')")
    assert any(a[:2] == ("POST", "/instance/i1/start") for a in appels)
    p.click("#t-etat")
    p.click("#cInstall")
    assert not [a for a in appels if a[1] == "/container/install"]
    p.click("#cOui")
    p.wait_for_function("document.getElementById('rConteneur').textContent.includes('Installation')")
    assert any(a[:2] == ("POST", "/container/install") for a in appels)
    assert err == []
    ctx.close()


def test_deploiement_multipart_et_gitea(navigateur, tmp_path):
    routes = {**BASE, "/deploy": (200, {"success": True}), "/gitea/clone/neuf": (200, {"success": True})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamlit/?onglet=applis", routes)
    p.wait_for_selector("#bApps tr td.act")
    z = tmp_path / "a.zip"; z.write_bytes(b"PK\x03\x04")
    p.fill("#dNom", "mon-app"); p.fill("#dPort", "8600")
    p.set_input_files("#dFichier", str(z))
    p.wait_for_function("document.getElementById('rDeploy').textContent.includes('Déployée')")
    dep = [a for a in appels if a[1] == "/deploy"][0]
    assert dep[0] == "POST" and "mon-app" in dep[2] and "8600" in dep[2]
    p.fill("#gNom", "neuf"); p.fill("#gDepot", "http://gitea.local/u/r.git")
    p.click("#fGitea button[type=submit]")
    p.wait_for_function("document.getElementById('rGitea').textContent.includes('cloné')")
    g = [a for a in appels if a[1] == "/gitea/clone/neuf"][0]
    assert json.loads(g[2]) == {"repo": "http://gitea.local/u/r.git"}
    assert err == []
    ctx.close()


def test_jeton_sbx_token_en_bearer(navigateur):
    ctx2, p, _, appels = ouvre_avec_jeton(navigateur)
    p.wait_for_function("document.getElementById('fTotal').textContent === '3'")
    assert all(a[3] == "Bearer jeton-test" for a in appels if a[1] == "/apps/audit")
    ctx2.close()


def ouvre_avec_jeton(navigateur):
    ctx = navigateur.new_context(viewport={"width": 1300, "height": 900})
    ctx.add_init_script("localStorage.setItem('sbx_token','jeton-test')")
    p = ctx.new_page(); erreurs, appels = [], []
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, body="", content_type="application/javascript"))
    p.route("http://sbx.test/streamlit/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SRC))

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/streamlit", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = BASE.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/streamlit/**", api)
    p.goto("http://sbx.test/streamlit/")
    return ctx, p, erreurs, appels


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in BASE}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/streamlit/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#fTotal", "#fEnLigne", "#fDort", "#fArch", "#fAnom", "#sApps", "#sCont")] == ["—"] * 7
    assert not p.is_visible("#veilleNote") and err == []
    ctx.close()


def test_demonstration_annoncee_et_aucune_ecriture(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamlit/?demo=1&onglet=mosaic", {})
    p.wait_for_selector("button[data-wake]")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("button[data-wake]").first.click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    p.click("#t-applis")
    p.wait_for_selector("#bApps tr td.act")
    p.locator("#bApps").get_by_text("Démarrer").first.click()
    p.locator("#bApps").get_by_text("Confirmer").first.click()
    p.fill("#gNom", "x"); p.fill("#gDepot", "y"); p.click("#fGitea button[type=submit]")
    p.wait_for_function("document.getElementById('rGitea').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/streamlit/?embed=1", BASE, taille={"width": 420, "height": 800})
    p.wait_for_selector("#sante .ligne")
    for onglet in ("mosaic", "etat", "acces", "applis", "instances"):
        p.click("#t-" + onglet)
        p.wait_for_timeout(150)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), onglet
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
