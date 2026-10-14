# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2684 — coque /toolbox/ (index.html) au profil Aurora : contrôles statiques + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www" / "toolbox"
PAGE = WWW / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
ONGLETS = ["overview", "clients", "filtres", "social", "ads", "reseau", "tor", "sentinel", "config"]
PAGES = {"overview": "apercu.html", "clients": "clients.html", "filtres": "filtres.html", "social": "social.html", "ads": "pubs.html",
         "reseau": "/soc/reseau.html", "tor": "tor.html", "sentinel": "sentinelle.html", "config": "config.html"}


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert not re.search(r"<script[^>]+src=", SRC, re.I)                    # le menu est injecté, jamais en dur
    assert "/shared/sidebar.js" in SRC and "!EMBED && !DEMO" in SRC
    assert "fonts.googleapis" not in SRC and "hybrid-dark" not in SRC and "crt-light" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "min-height:100vh"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'toolbox'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_lecture_seule_memes_routes_et_jeton():
    # la coque ne fait que des lectures ; les écritures vivent dans les onglets (tests *_2373 / routes_pages_1778)
    assert not re.search(r"method\s*:", SRC) and "POST" not in SRC.replace("(POST)", "")
    for r in ("'/health'", "'/admin/config'", "'/admin/metrics'", "var API = '/api/v1/toolbox'"):
        assert r in SRC, r
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer ' + t" in SRC
    assert "setItem" not in SRC


def test_neuf_onglets_a_l_identique_et_toutes_les_pages_existent():
    for nom, page in PAGES.items():
        assert f"{nom}: '{page}'" in SRC, nom
        if not page.startswith("/"):
            assert (WWW / page).exists(), page
    assert re.findall(r"\['(\w+)', '", SRC.split("var ONGLETS")[1].split("];")[0]) == ONGLETS
    assert "role', 'tab'" in SRC and "role=\"tablist\"" in SRC and "aria-selected" in SRC and "focus-visible" in SRC
    assert "'ArrowRight'" in SRC and "'Home'" in SRC


def test_aucun_mac_ni_secret_en_clair():
    low = SRC.lower()
    assert "mac_hash" not in low and not re.search(r"\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b", low)
    assert "key.pem" not in low and not re.search(r"(password|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]", low)


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


HEALTH = {"status": "ok", "module": "toolbox", "version": "2.99.1"}
CONFIG = {"r2": {"enabled": True, "mitm_listen": "10.99.0.1:8080"}}
METRICS = {"clients_active": 12, "events_24h_total": 3456}
API = {"/health": (200, HEALTH), "/admin/config": (200, CONFIG), "/admin/metrics": (200, METRICS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels, cadres = [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "toolbox":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        elif chemin.startswith("toolbox/") and (WWW / chemin[8:]).exists():
            cadres.append(r.request.url)
            r.fulfill(status=200, content_type="text/html", body=(WWW / chemin[8:]).read_text(encoding="utf-8"))
        elif chemin.startswith("soc/"):
            cadres.append(r.request.url)
            r.fulfill(status=200, content_type="text/html", body="<!doctype html><title>soc</title><p>Réseau en direct (simulé)")
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/toolbox", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {})) if r.request.method == "GET" else (200, {})
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/toolbox/**", api)
    p.route("http://sbx.test/api/v1/hub/**", lambda r, *_: r.fulfill(status=404, body=""))
    p.goto(url)
    return ctx, p, erreurs, appels, cadres


def test_tuiles_viennent_de_l_api_et_lecture_seule(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/toolbox/", API)
    p.wait_for_function("document.getElementById('etat').textContent === 'EN LIGNE'")
    assert [p.inner_text(i) for i in ("#tVersion", "#tMode", "#tClients", "#tEvents")] == ["v2.99.1", "R2", "12", "3 456"]
    assert p.is_visible("#r2") and not p.is_visible("#demo") and not p.is_visible("#session")
    assert all(a[0] == "GET" for a in appels) and {a[1] for a in appels} >= {"/health", "/admin/config", "/admin/metrics"}
    assert all(p.get_attribute(s, "title") for s in (".tuile:nth-of-type(1)", ".tuile:nth-of-type(2)"))
    assert err == []
    ctx.close()


def test_jeton_en_bearer(navigateur):
    ctx = navigateur.new_context()
    ctx.add_init_script("localStorage.setItem('sbx_token','jeton-de-test')")
    p = ctx.new_page()
    appels = []
    p.route("http://sbx.test/toolbox/", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SRC))
    p.route("http://sbx.test/toolbox/*.html*", lambda r, *_: r.fulfill(status=200, content_type="text/html", body="<p>x"))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))

    def api(r, *_):
        appels.append(r.request.headers.get("authorization"))
        r.fulfill(status=200, content_type="application/json", body=json.dumps({}))
    p.route("http://sbx.test/api/v1/toolbox/**", api)
    p.goto("http://sbx.test/toolbox/")
    p.wait_for_function("document.getElementById('etat').textContent !== 'Chargement…'")
    assert appels and set(appels) == {"Bearer jeton-de-test"}
    ctx.close()


def test_onglets_aria_clavier_et_cadre(navigateur):
    ctx, p, err, _, cadres = ouvre(navigateur, "http://sbx.test/toolbox/", API)
    p.wait_for_selector("#tab-overview[aria-selected=true]")
    assert p.locator("[role=tab]").count() == 9 and p.get_attribute("#onglets", "role") == "tablist"
    assert p.get_attribute("#cadreVue", "src") == "apercu.html?embed=1"
    for nom in ONGLETS:
        p.click(f"#tab-{nom}")
        assert p.get_attribute(f"#tab-{nom}", "aria-selected") == "true"
        assert p.locator("[role=tab][aria-selected=true]").count() == 1
        attendu = PAGES[nom] + "?embed=1"
        assert p.get_attribute("#cadreVue", "src") == attendu
        assert p.get_attribute("#vue", "aria-labelledby") == f"tab-{nom}"
    assert p.evaluate("location.hash") == "#config"
    # flèches : onglet suivant, avec retour au premier ; Home / End
    p.focus("#tab-config"); p.keyboard.press("ArrowRight")
    assert p.get_attribute("#tab-overview", "aria-selected") == "true" and p.evaluate("document.activeElement.id") == "tab-overview"
    p.keyboard.press("End")
    assert p.get_attribute("#tab-config", "aria-selected") == "true"
    p.keyboard.press("Home")
    assert p.get_attribute("#tab-overview", "aria-selected") == "true"
    assert err == []
    ctx.close()


def test_lien_profond_par_ancre_et_hauteur_du_cadre(navigateur):
    ctx, p, err, _, cadres = ouvre(navigateur, "http://sbx.test/toolbox/#tor", API)
    p.wait_for_selector("#tab-tor[aria-selected=true]")
    assert p.get_attribute("#cadreVue", "src") == "tor.html?embed=1"
    # la page encadrée annonce sa hauteur (clé sbxToolboxVue) : la coque l'applique, bornée à 300-4000 px
    p.wait_for_function("parseInt(document.getElementById('cadreVue').style.height) !== 1200")
    h = int(p.evaluate("document.getElementById('cadreVue').style.height")[:-2])
    assert 300 <= h <= 4000
    p.click("#tab-reseau")
    assert p.get_attribute("#cadreVue", "src") == "/soc/reseau.html?embed=1"
    assert err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/toolbox/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tVersion", "#tMode", "#tClients", "#tEvents")] == ["—"] * 4 and err == []
    ctx.close()


def test_module_hors_ligne_zero_est_une_mesure(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/toolbox/", {k: (500, {}) for k in API})
    p.wait_for_function("document.getElementById('etat').textContent === 'HORS LIGNE'")
    assert p.inner_text("#tClients") == "—"
    ctx.close()
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/toolbox/",
                              {**API, "/admin/metrics": (200, {"clients_active": 0, "events_24h_total": 0}), "/admin/config": (200, {"r2": {"enabled": False}})})
    p.wait_for_function("document.getElementById('etat').textContent === 'EN LIGNE'")
    assert p.inner_text("#tClients") == "0" and p.inner_text("#tMode") == "R1" and not p.is_visible("#r2")
    ctx.close()


def test_demonstration_annoncee_menu_absent_et_demo_transmis(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, "http://sbx.test/toolbox/?demo=1", {})
    p.wait_for_selector("#demo:not([hidden])")
    assert "DÉMONSTRATION" in p.inner_text("#demo") and p.inner_text("#etat") == "DÉMO"
    assert p.inner_text("#tClients") == "7"
    assert p.get_attribute("#cadreVue", "src") == "apercu.html?demo=1&embed=1"
    p.click("#tab-reseau")
    assert p.get_attribute("#cadreVue", "src") == "/soc/reseau.html?demo=1&embed=1"
    assert p.evaluate("!document.querySelector('script[src*=\"sidebar.js\"]')")   # menu commun absent en démonstration
    assert [a for a in appels if a[1] in ("/health", "/admin/config", "/admin/metrics")] == [] and err == []
    ctx.close()


def test_menu_commun_hors_embed_et_telephone_sans_debordement(navigateur):
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/toolbox/", API)
    assert p.evaluate("!!document.querySelector('script[src=\"/shared/sidebar.js\"]')")
    ctx.close()
    ctx, p, err, _, _ = ouvre(navigateur, "http://sbx.test/toolbox/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('etat').textContent === 'EN LIGNE'")
    assert p.evaluate("!document.querySelector('script[src*=\"sidebar.js\"]')")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
