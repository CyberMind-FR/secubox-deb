# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2675 — /soc.html et /soc/ au profil Aurora : tests statiques puis vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www"
PAGES = {"soc": WWW / "soc.html", "index": WWW / "soc" / "index.html"}
URLS = {"soc": "http://sbx.test/soc.html", "index": "http://sbx.test/soc/"}
SRC = {k: p.read_text(encoding="utf-8") for k, p in PAGES.items()}
PAGES_IDS = list(PAGES)

# Routes lues par les deux anciennes pages (relevées avant la refonte) : elles doivent rester citées à l'identique.
ROUTES_COMMUNES = ["/api/v1/hub", "/api/v1/waf", "/api/v1/metrics", "/health", "/stats", "/alerts?limit=100&aggregate=true",
                   "/public/firewall_summary", "/overview", "/dashboard", "/connections", "/network_summary"]


@pytest.mark.parametrize("k", PAGES_IDS)
def test_page_autonome_lecture_seule_sans_dialogue_natif(k):
    s = SRC[k]
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in s
    attendu = ["/shared/sidebar.js"] + (["/shared/health-banner.js"] if k == "index" else [])
    assert re.findall(r'<script src="([^"]+)"', s) == attendu
    assert "fonts.googleapis" not in s and "design-tokens.css" not in s and "hybrid" not in s
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "Math.random", "document.write"):
        assert interdit not in s
    assert "lorem" not in s.lower()
    assert "sbxVue" in s and "onglet: ONGLET" in s and "DEMO" in s and "embed" in s
    # lecture seule : uniquement des GET
    assert "method: 'GET'" in s and "'POST'" not in s and "'PUT'" not in s and "'DELETE'" not in s and "JSON.stringify" not in s
    # jeton : sbx_token en Bearer, lecture protégée par try/catch, jamais écrit ni affiché
    assert "localStorage.getItem('sbx_token')" in s and "'Bearer ' + t" in s and "setItem" not in s
    assert re.search(r"try \{ return localStorage\.getItem\('sbx_token'\)", s)
    # onglets Aurora
    assert 'role="tablist"' in s and s.count('role="tab"') == 3 and 'aria-selected="true"' in s and "focus-visible" in s


@pytest.mark.parametrize("k", PAGES_IDS)
def test_routes_identiques_a_l_ancienne_page(k):
    s = SRC[k]
    for r in ROUTES_COMMUNES:
        assert r in s, r
    assert ("/module-health/summary" in s) == (k == "index")   # seul /soc/ lisait la santé des modules
    assert "/portal/login.html?redirect=" in s                 # même cible de connexion que l'ancienne redirection


# --------------------------------------------------------------------------- navigateur
playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


ALERTES = {"aggregated": True, "alerts": [
    {"client_ip": "203.0.113.57", "country": "NL", "count": 40, "latest_alert": {"host": "www.exemple.test"}},
    {"client_ip": "198.51.100.23", "country": "US", "count": 10, "latest_alert": {"host": "git.exemple.test"}},
    {"client_ip": "192.0.2.14", "country": "FR", "count": 5, "latest_alert": None}]}
WAF = {"running": True, "version": "1.2.0", "rules_loaded": 412, "blocked_24h": 1284, "blocked_today": 342,
       "top_countries": [{"country": "NL", "count": 312}, {"country": "DE", "count": 201}],
       "categories_list": [{"name": "scanner", "count": 420}, {"name": "sqli", "count": 91}],
       "top_vhosts": [{"vhost": "www.exemple.test", "count": 540}, {"vhost": "git.exemple.test", "count": 222}],
       "last_threat": {"ip": "203.0.113.57", "type": "scanner", "vhost": "www.exemple.test", "time_ago": "4m ago"}}
API = {
    "hub/health": (200, {"status": "ok", "module": "hub", "modules": {"waf": {"status": "ok"}, "dns": {"status": "ok"}, "mail": {"status": "degraded"}, "nac": {"status": "ok"}}}),
    "hub/module-health/summary": (200, {"healthy": 10, "degraded": 1, "down": 1, "total": 12, "health_percent": 83.3}),
    "waf/stats": (200, WAF), "waf/alerts": (200, ALERTES),
    "hub/public/firewall_summary": (200, {"status": "active", "tables": 6, "chains": 24, "rules": 187, "processed": 10284, "dropped": 1284, "accepted": 9000, "source": "cache"}),
    "metrics/overview": (200, {"cpu_percent": 20, "mem_pct": 50, "mem_used_kb": 2048000, "mem_total_kb": 4096000, "load_avg": [0.4, 0.5, 0.4], "uptime": 172800}),
    "hub/dashboard": (200, {"cpu_percent": 23, "memory_percent": 61, "disk_percent": 48, "load_avg": [0.42, 0.5, 0.4], "uptime": 259200}),
    "metrics/connections": (200, {"total_tcp": 214, "http": 38, "https": 161, "ssh": 3}),
    "hub/network_summary": (200, {"interfaces": 7, "interfaces_up": 5, "wan_status": "connected"}),
}


def ouvre(navigateur, k, routes, token="tok-factice", suffixe="", taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    if token:
        ctx.add_init_script("try{localStorage.setItem('sbx_token','%s')}catch(e){}" % token)
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin in ("soc.html", "soc/", "soc"):
            r.fulfill(status=200, content_type="text/html", body=SRC[k])
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        url = r.request.url.split("/api/v1/", 1)[1]
        chemin = url.split("?")[0]
        appels.append((r.request.method, url, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/**", api)
    p.goto(URLS[k] + suffixe)
    return ctx, p, erreurs, appels


def txt(p, i):
    return re.sub(r"\s", " ", p.inner_text(i)).strip()


def attend_charge(p):
    p.wait_for_function("document.getElementById('maj').textContent.startsWith('Relevé')")


@pytest.mark.parametrize("k", PAGES_IDS)
def test_tuiles_et_panneaux_viennent_de_l_api(navigateur, k):
    ctx, p, err, appels = ouvre(navigateur, k, API)
    attend_charge(p)
    p.wait_for_function("document.querySelector('#activite li .tx code')")
    assert re.sub(r"\s", "", p.inner_text("#cMenaces .v")) == "1284"
    assert txt(p, "#cConns .v") == "214" and "38 HTTP · 161 HTTPS" in txt(p, "#cConns .s")
    if k == "index":
        assert txt(p, "#cServ .v") == "10" and "sur 12" in txt(p, "#cServ .s") and "83 % sains" in txt(p, "#cServ .s")
    else:
        assert txt(p, "#cServ .v") == "3" and "sur 4" in txt(p, "#cServ .s")
    assert txt(p, "#cFw .v") == "187" and "6 tables" in txt(p, "#cFw .s")
    assert re.sub(r"\s", "", p.inner_text("#cDrop .v")) == "1284"
    assert txt(p, "#cUp .v") == "3 j 0 h"                       # uptime du dashboard (259200 s), prioritaire sur metrics
    assert txt(p, "#etat") == "DÉGRADÉ"
    assert txt(p, "#wVer") == "v1.2.0" and txt(p, "#wReg") == "412" and "scanner" in txt(p, "#wDern") and "203.0.113.57" in txt(p, "#wDern")
    assert "NL" in txt(p, "#wPays") and "DE" in txt(p, "#wPays") and "scanner" in txt(p, "#wCats")
    assert txt(p, "#fEtat") == "ACTIF" and txt(p, "#fRg") == "187"
    assert txt(p, "#jCpuV") == "23 %" and txt(p, "#jMemV") == "61 %" and txt(p, "#jDskV") == "48 %" and txt(p, "#jNetV") == "71 %"
    assert "Charge 0,42" in txt(p, "#jCpuI") and "connected" in txt(p, "#jNetI")
    assert err == []
    ctx.close()


@pytest.mark.parametrize("k", PAGES_IDS)
def test_memes_appels_memes_en_tetes(navigateur, k):
    ctx, p, _, appels = ouvre(navigateur, k, API)
    attend_charge(p)
    p.wait_for_function("document.querySelector('#activite li .tx code')")
    urls = sorted(u for m, u, _h in appels)
    attendu = ["hub/dashboard", "hub/health", "hub/network_summary", "hub/public/firewall_summary", "metrics/connections", "metrics/overview",
               "waf/alerts?limit=100&aggregate=true", "waf/stats"] + (["hub/module-health/summary"] if k == "index" else [])
    assert urls == sorted(attendu)
    assert {m for m, _u, _h in appels} == {"GET"}
    assert all(h == "Bearer tok-factice" for _m, _u, h in appels)
    ctx.close()


def test_soc_index_lit_sans_jeton_les_routes_publiques(navigateur):
    """L'ancienne /soc/ n'exigeait pas de jeton pour health, stats, pare-feu, overview, connections (session portée par cookie)."""
    ctx, p, err, appels = ouvre(navigateur, "index", API, token=None)
    attend_charge(p)
    lues = sorted(u.split("?")[0] for _m, u, _h in appels)
    assert lues == ["hub/health", "hub/public/firewall_summary", "metrics/connections", "metrics/overview", "waf/stats"]
    assert "hub/dashboard" not in lues and "hub/network_summary" not in lues and "waf/alerts" not in lues
    assert all(h is None for _m, _u, h in appels)
    assert txt(p, "#session") .startswith("Aucune mesure : session requise") and p.is_visible("#session")
    assert err == []
    ctx.close()


def test_soc_html_sans_jeton_n_appelle_rien(navigateur):
    """L'ancienne /soc.html redirigeait vers la connexion sans rien appeler : elle affiche maintenant un bandeau, sans requête."""
    ctx, p, err, appels = ouvre(navigateur, "soc", API, token=None)
    p.wait_for_selector("#session:not([hidden])")
    assert appels == []
    assert "session requise" in txt(p, "#session") and txt(p, "#etat") == "SESSION REQUISE"
    assert p.get_attribute("#connexion", "href") == "/portal/login.html?redirect=%2Fsoc.html"
    assert [txt(p, "#" + i + " .v") for i in ("cMenaces", "cConns", "cServ", "cFw", "cDrop", "cUp")] == ["—"] * 6
    assert [txt(p, "#" + i) for i in ("jCpuV", "jMemV", "jDskV", "jNetV")] == ["—"] * 4 and err == []
    ctx.close()


@pytest.mark.parametrize("k", PAGES_IDS)
def test_session_refusee_bandeau_et_tirets(navigateur, k):
    refus = {c: (401, {"detail": "jeton requis"}) for c in API}
    ctx, p, err, _ = ouvre(navigateur, k, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert txt(p, "#etat") == "SESSION REQUISE"
    assert [txt(p, "#" + i + " .v") for i in ("cMenaces", "cConns", "cServ", "cFw", "cDrop")] == ["—"] * 5
    assert txt(p, "#wVer") == "—" and txt(p, "#fTab") == "—" and err == []
    ctx.close()


@pytest.mark.parametrize("k", PAGES_IDS)
def test_service_arrete_hors_ligne_sans_erreur_js(navigateur, k):
    ctx, p, err, _ = ouvre(navigateur, k, {})
    p.wait_for_function("document.getElementById('etat').textContent === 'HORS LIGNE'")
    assert not p.is_visible("#session") and txt(p, "#cMenaces .v") == "—" and err == []
    ctx.close()


@pytest.mark.parametrize("k", PAGES_IDS)
def test_mesure_nulle_reste_un_zero_et_absente_un_tiret(navigateur, k):
    routes = {**API, "metrics/connections": (200, {"total_tcp": 0, "http": 0, "https": 0, "ssh": 0}),
              "hub/dashboard": (200, {"cpu_percent": 0, "memory_percent": 61, "load_avg": [0, 0, 0]})}
    ctx, p, _, _ = ouvre(navigateur, k, routes)
    attend_charge(p)
    assert txt(p, "#cConns .v") == "0" and txt(p, "#jCpuV") == "0 %" and txt(p, "#jDskV") == "—"   # disk_percent absent
    ctx.close()


@pytest.mark.parametrize("k", PAGES_IDS)
def test_pas_de_serie_horaire_pas_de_courbe_inventee(navigateur, k):
    ctx, p, _, _ = ouvre(navigateur, k, API)
    attend_charge(p)
    assert "n’indique pas" in txt(p, "#mNote") or "ne fournit pas de série horaire" in txt(p, "#mNote")
    assert p.locator("#mCourbe rect").count() == 0
    ctx.close()


@pytest.mark.parametrize("k", PAGES_IDS)
def test_serie_horaire_fournie_dessinee_en_svg(navigateur, k):
    routes = {**API, "waf/stats": (200, {**WAF, "hourly_blocks": list(range(24))})}
    ctx, p, _, _ = ouvre(navigateur, k, routes)
    attend_charge(p)
    p.wait_for_selector("#mCourbe rect")
    assert p.locator("#mCourbe rect").count() == 24 and p.locator("#mCourbe svg").count() == 1
    ctx.close()


@pytest.mark.parametrize("k", PAGES_IDS)
def test_onglets_activite_clavier_et_filtre(navigateur, k):
    routes = {**API, "hub/dashboard": (200, {"cpu_percent": 1})}
    ctx, p, _, _ = ouvre(navigateur, k, routes)
    attend_charge(p)
    p.wait_for_function("document.querySelector('#activite li .tx code')")
    assert p.get_attribute("#tAll", "aria-selected") == "true" and p.locator("#activite li").count() >= 2
    p.focus("#tAll"); p.keyboard.press("ArrowRight")
    assert p.get_attribute("#tThreats", "aria-selected") == "true" and p.get_attribute("#tAll", "aria-selected") == "false"
    assert p.evaluate("document.activeElement.id") == "tThreats" and p.locator("#activite li code").count() >= 2
    p.keyboard.press("ArrowRight")
    assert p.get_attribute("#tSystem", "aria-selected") == "true"
    assert "ne sont pas sains" in txt(p, "#activite")
    p.keyboard.press("End"); assert p.evaluate("document.activeElement.id") == "tSystem"
    p.keyboard.press("Home"); assert p.evaluate("document.activeElement.id") == "tAll"
    ctx.close()


def test_activite_sans_doublon_au_rafraichissement(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "index", API)
    attend_charge(p)
    p.wait_for_function("document.querySelector('#activite li .tx code')")
    n = p.locator("#activite li").count()
    p.click("#rafraichir")
    p.wait_for_timeout(400)
    assert p.locator("#activite li").count() == n
    ctx.close()


def test_capteurs_par_continent_et_sites_vises(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "index", API)
    attend_charge(p)
    p.wait_for_selector("#eOrigL .lg")
    o = txt(p, "#eOrigL")
    assert "Europe" in o and "Amériques" in o and "45" in o and "10" in o
    assert p.text_content("#eVisD text") == "3" and "Europe" in txt(p, "#eVisL")
    v = txt(p, "#eVhL")
    assert "www.exemple.test" in v and "git.exemple.test" in v and p.text_content("#eVhD text") == "762"
    assert p.locator("#eOrigD circle").count() >= 2 and err == []
    ctx.close()


def test_soc_html_courbes_des_paquets_apres_deux_releves(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "soc", API)
    attend_charge(p)
    assert "Courbe en cours" in txt(p, "#fCd") and txt(p, "#fRej") == "—"
    assert re.sub(r"\s", "", p.inner_text("#fAcc")) == "9000"
    p.click("#rafraichir")
    p.wait_for_selector("#fCd svg polyline", state="attached")
    assert p.locator("#fCa svg polyline").count() == 1
    ctx.close()


@pytest.mark.parametrize("k", PAGES_IDS)
def test_demonstration_annoncee_sans_aucune_requete(navigateur, k):
    ctx, p, err, appels = ouvre(navigateur, k, {}, token=None, suffixe="?demo=1")
    attend_charge(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and not p.is_visible("#session")
    assert appels == [] and err == []
    assert txt(p, "#cMenaces .v") != "—" and txt(p, "#etat") in ("EN LIGNE", "DÉGRADÉ")
    p.wait_for_selector("#mCourbe rect")                       # série horaire fictive annoncée par le bandeau
    assert "exemple.test" in txt(p, "#activite")
    ctx.close()


@pytest.mark.parametrize("k", PAGES_IDS)
def test_telephone_sans_debordement_embarque_et_hauteur_annoncee(navigateur, k):
    ctx, p, err, _ = ouvre(navigateur, k, API, taille={"width": 420, "height": 800}, suffixe="?embed=1")
    attend_charge(p)
    p.wait_for_function("document.querySelector('#activite li .tx code')")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()


@pytest.mark.parametrize("k", PAGES_IDS)
def test_demonstration_a_420_px_sans_debordement(navigateur, k):
    ctx, p, err, _ = ouvre(navigateur, k, {}, token=None, suffixe="?demo=1&embed=1", taille={"width": 420, "height": 800})
    attend_charge(p)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and err == []
    ctx.close()


@pytest.mark.parametrize("k", PAGES_IDS)
def test_hauteur_annoncee_a_l_hote(navigateur, k):
    ctx, p, _, _ = ouvre(navigateur, k, API, suffixe="?embed=1")
    p.evaluate("window.__m = []; addEventListener('message', e => window.__m.push(e.data))")
    attend_charge(p)
    p.evaluate("annoncer()")          # hors iframe, parent === window : le message revient à la page elle-même
    p.wait_for_function("window.__m.length > 0")
    m = p.evaluate("window.__m[0]")
    assert m["onglet"] == ("soc" if k == "index" else "soc-hub") and m["sbxVue"] > 100
    ctx.close()
