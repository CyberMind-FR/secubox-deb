# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3247 — page /streamlit/ : nom public au dépôt, publier / renommer / retirer, port automatique.

Page statique + vrai navigateur, API simulée (même banc que test_streamlit_aurora_2653)."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "streamlit" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_depot_porte_le_nom_public_et_le_port_automatique():
    assert 'id="dPublic"' in SRC and "form.append('public_name'" in SRC
    assert 'value="8501"' not in SRC and "p.value = 8501" not in SRC      # plus de port imposé par la page
    assert SRC.count('placeholder="auto"') >= 1


def test_actions_de_publication_et_lecture():
    for r in ("'/publications'", "'/publish'", "'/rename'", "'/unpublish'", "JSON.stringify({ public_name"):
        assert r in SRC, r
    assert "Renommer" in SRC and "Publier" in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML"):
        assert interdit not in SRC


playwright = pytest.importorskip("playwright.sync_api")
NOW = int(time.time())


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


BASE = {
    "/apps/audit": (200, {"available": True, "cache_age_seconds": 30, "apps": []}),
    "/status": (200, {"app_count": 2, "running_apps": 0, "instance_count": 0, "container_status": "stopped"}),
    "/health": (200, {"checks": {"api": "ok"}}),
    "/components": (200, {"components": []}),
    "/access": (200, {"access": []}),
    "/instances": (200, {"instances": []}),
    "/apps": (200, {"apps": [{"name": "alpha", "main": "app.py", "port": 8501, "running": True},
                             {"name": "Beta_App", "main": "main.py", "running": False}]}),
    "/publications": (200, {"auto": False, "domaine": "example.org", "apps": {
        "alpha": [{"nom_public": "a", "domaine": "a.example.org", "port": 8501, "enabled": True}]}}),
}


def ouvre(navigateur, url, routes):
    ctx = navigateur.new_context(viewport={"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="application/javascript", body="")
        elif chemin.rstrip("/") == "streamlit":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/streamlit", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        defaut = (404, {}) if r.request.method == "GET" else (200, {"success": True})
        statut, corps = routes.get(chemin, defaut)
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/streamlit/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_renommer_dans_la_page(navigateur):
    routes = {**BASE, "/app/alpha/rename": (200, {"ok": True, "nom_public": "nouveau",
                                                  "domaine": "nouveau.example.org", "evenement": "renommage"})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamlit/?onglet=applis", routes)
    p.wait_for_selector("#bApps tr td.act")
    ligne = p.locator("#bApps tr").nth(0)
    assert "a.example.org" in ligne.inner_text()
    ligne.get_by_text("Renommer").click()
    p.fill("#nomPublic", "nouveau")
    p.locator("#bApps tr").nth(0).get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rApps').textContent.includes('nouveau.example.org')")
    envoi = next(a for a in appels if a[:2] == ("POST", "/app/alpha/rename"))
    assert json.loads(envoi[2]) == {"public_name": "nouveau"}
    assert err == []
    ctx.close()


def test_publier_propose_un_nom_derive_du_dossier(navigateur):
    routes = {**BASE, "/app/Beta_App/publish": (200, {"ok": True, "nom_public": "beta-app",
                                                      "domaine": "beta-app.example.org"})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamlit/?onglet=applis", routes)
    p.wait_for_selector("#bApps tr td.act")
    ligne = p.locator("#bApps tr").nth(1)
    assert "non publiée" in ligne.inner_text()
    ligne.get_by_text("Publier").click()
    assert p.input_value("#nomPublic") == "beta-app"
    p.locator("#bApps tr").nth(1).get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rApps').textContent.includes('beta-app.example.org')")
    envoi = next(a for a in appels if a[:2] == ("POST", "/app/Beta_App/publish"))
    assert json.loads(envoi[2]) == {"public_name": "beta-app"}
    assert err == []
    ctx.close()


def test_erreur_du_serveur_affichee_telle_quelle(navigateur):
    routes = {**BASE, "/app/Beta_App/start": (503, {"detail": "Conteneur streamlit endormi : réveil impossible"})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamlit/?onglet=applis", routes)
    p.wait_for_selector("#bApps tr td.act")
    p.locator("#bApps tr").nth(1).get_by_text("Démarrer").click()
    assert p.input_value("#portDemarre") == ""
    p.locator("#bApps tr").nth(1).get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rApps').textContent.includes('réveil impossible')")
    assert any(a[:2] == ("POST", "/app/Beta_App/start") for a in appels)
    assert not any(re.search(r"port=", a[1] or "") for a in appels)
    assert err == []
    ctx.close()


def test_depot_envoie_le_nom_public(navigateur):
    routes = {**BASE, "/deploy": (200, {"success": True, "name": "atelier-partage-1", "port": 8507,
                                        "publication": {"publiee": True, "domaine": "atelier.example.org"}})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamlit/?onglet=applis", routes)
    p.wait_for_selector("#bApps tr td.act")
    p.fill("#dNom", "atelier-partage-1")
    p.fill("#dPublic", "atelier")
    p.set_input_files("#dFichier", files=[{"name": "x.zip", "mimeType": "application/zip", "buffer": b"PK\x05\x06"}])
    p.wait_for_function("document.getElementById('rDeploy').textContent.includes('atelier.example.org')")
    envoi = next(a for a in appels if a[:2] == ("POST", "/deploy"))
    assert 'name="public_name"' in envoi[2] and "atelier" in envoi[2]
    assert "8507" in p.inner_text("#rDeploy")
    assert err == []
    ctx.close()
