# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2653 — /streamforge/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "composants" / "streamforge" / "www" / "streamforge" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert not re.findall(r"<script src=", SRC)
    assert "/shared/sidebar.js" in SRC and "!EMBED && !DEMO" in SRC
    assert "hybrid-" not in SRC and "crt-" not in SRC and "fonts.googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "sbxVue" in SRC and "onglet: 'streamforge'" in SRC and "DEMO" in SRC and "embed" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("API = '/api/v1/streamforge'", "'/status'", "'/templates'", "'/apps'",
              "'/app', { method: 'POST', body: JSON.stringify({ name, template }) }",
              "'/start', { method: 'POST' }", "'/stop', { method: 'POST' }", "{ method: 'DELETE' }"):
        assert r in SRC, r
    assert "localStorage.getItem('sbx_token')" in SRC and "Bearer" in SRC and "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


BASE = {
    "/status": (200, {"app_count": 2, "running_count": 1}),
    "/templates": (200, {"templates": [{"name": "basic"}, {"name": "tableau"}]}),
    "/apps": (200, {"apps": [{"name": "alpha", "status": "running", "port": 8601, "entrypoint": "app.py"},
                             {"name": "beta", "status": "stopped", "port": 0, "entrypoint": "main.py"}]}),
}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    if jeton:
        ctx.add_init_script("localStorage.setItem('sbx_token','%s')" % jeton)
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, body="", content_type="application/javascript"))
    p.route("http://sbx.test/streamforge/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SRC))

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/streamforge", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {}) if r.request.method == "GET" else (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/streamforge/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_cartes_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamforge/", BASE, jeton="jt")
    p.wait_for_selector(".carte")
    assert [p.inner_text(i) for i in ("#tApps", "#tMarche", "#tModeles")] == ["2", "1", "2"]
    assert p.inner_text("#etat") == "EN SERVICE"
    t = p.inner_text("#parc")
    assert "alpha" in t and "8601" in t and "main.py" in t
    assert [o for o in p.eval_on_selector_all("#modele option", "o => o.map(x => x.value)")] == ["basic", "tableau"]
    assert all(a[3] == "Bearer jt" for a in appels)
    assert err == []
    ctx.close()


def test_creer_une_appli_envoie_le_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamforge/", BASE)
    p.wait_for_selector(".carte")
    p.fill("#nom", "gamma"); p.select_option("#modele", "tableau"); p.click("#btnCree")
    p.wait_for_function("document.getElementById('rCree').textContent.includes('créée')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/app"][0]
    assert json.loads(post[2]) == {"name": "gamma", "template": "tableau"}
    assert err == []
    ctx.close()


def test_demarrer_arreter_supprimer(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamforge/", BASE)
    p.wait_for_selector(".carte")
    p.locator(".carte").nth(1).get_by_text("Démarrer").click()
    p.wait_for_function("document.getElementById('rParc').textContent.includes('Démarrage')")
    p.locator(".carte").nth(0).get_by_text("Arrêter").click()
    p.wait_for_function("document.getElementById('rParc').textContent.includes('arrêtée')")
    p.locator(".carte").nth(0).get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator(".carte").nth(0).get_by_text("Annuler").click()
    p.locator(".carte").nth(0).get_by_text("Supprimer").click()
    p.locator(".carte").nth(0).get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rParc').textContent.includes('supprimée')")
    vus = [a[:2] for a in appels]
    assert ("POST", "/app/beta/start") in vus and ("POST", "/app/alpha/stop") in vus and ("DELETE", "/app/alpha") in vus
    assert err == []
    ctx.close()


def test_etat_vide_dit_quoi_faire(navigateur):
    vide = {"/status": (200, {"app_count": 0, "running_count": 0}), "/templates": (200, {"templates": []}), "/apps": (200, {"apps": []})}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/streamforge/", vide)
    p.wait_for_function("document.getElementById('parc').textContent.includes('Aucune appli')")
    assert p.inner_text("#tApps") == "0" and p.inner_text("#tModeles") == "0"
    assert err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in BASE}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/streamforge/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tApps", "#tMarche", "#tModeles")] == ["—"] * 3 and err == []
    ctx.close()


def test_demonstration_annoncee_et_aucune_ecriture(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/streamforge/?demo=1", {})
    p.wait_for_selector(".carte")
    assert "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator(".carte").nth(1).get_by_text("Démarrer").click()
    p.fill("#nom", "x"); p.click("#btnCree")
    p.wait_for_function("document.getElementById('rCree').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/streamforge/?embed=1", BASE, taille={"width": 420, "height": 800})
    p.wait_for_selector(".carte")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
