# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2341 : la page Guardian du SOC affiche les mesures réelles (WAF, DPI, appareils), le mode du WAF sans le supposer, « — » sans mesure, échappe tout, n'appelle rien d'externe ; l'onglet par défaut de /soc/ l'encadre."""
import json
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
WWW = Path(__file__).resolve().parents[1] / "www" / "soc"
PAGE = WWW / "guardian.html"
STATS = {"total_threats": 15933, "observed_threats": 1796, "by_severity": {"critical": 25, "high": 139, "medium": 194, "info": 15000}, "top_countries": {"US": 9, "FR": 1},
         "by_category": {"robots": 15500, "lfi": 25}, "leurres_touches": {"telnet": 7221, "vnc": 4475}}
ALERTES = {"alerts": [{"timestamp": "2026-10-11T07:13:51", "client_ip": "1.2.3.4", "country": "US", "category": "<img src=x onerror=window.xss=1>", "host": "h", "path": "/p", "severity": "high", "action": "banned"}]}


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, reponses, url="http://g.test/soc/guardian.html"):
    p = nav.new_context().new_page()
    externes, erreurs = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("request", lambda r: externes.append(r.url) if not r.url.startswith(("http://g.test", "data:")) else None)

    def api(r):
        corps = reponses.get(r.request.url.split("?")[0].split("g.test")[1])
        r.fulfill(status=200 if corps is not None else 401, content_type="application/json", body=json.dumps(corps if corps is not None else {}))
    p.route("http://g.test/api/**", api)
    p.route("http://g.test/soc/guardian.html*", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.goto(url)
    p.wait_for_timeout(600)
    return p, externes, erreurs


def test_les_mesures_sont_affichees_le_mode_est_celui_du_waf_et_les_noms_echappes(nav):
    p, externes, erreurs = ouvre(nav, {"/api/v1/waf/stats": STATS, "/api/v1/waf/alerts": ALERTES, "/api/v1/waf/enforcement/mode": {"mode": "ACTIVE", "detail": {"campagnes": "ACTIVE", "acteurs": "ACTIVE"}}})
    t = p.inner_text("body").replace(" ", " ")
    assert "15 933" in t and "1 796 observées" in t and "164" in t                    # critiques = critique + haute
    assert "Mode actif" in t and p.locator(".mode.on").count() == 3                    # OBSERVE, MITIGATE, BLOCK
    assert p.evaluate("window.xss") is None and "<img" in t
    assert not externes and not erreurs
    p.context.close()


def test_sans_mode_du_waf_aucun_mode_n_est_suppose(nav):
    p, _, _ = ouvre(nav, {"/api/v1/waf/stats": STATS})
    assert "Mode —" in p.inner_text("#modeTitre") and p.locator(".mode.on").count() == 0
    p.context.close()


def test_sans_session_les_tuiles_sont_des_tirets_et_on_invite_a_se_connecter(nav):
    p, _, _ = ouvre(nav, {})
    assert p.locator(".tuile .v").first.inner_text() == "—" and p.locator("#session").is_visible()
    p.context.close()


def test_le_mode_demo_est_annonce(nav):
    p, _, _ = ouvre(nav, {}, "http://g.test/soc/guardian.html?demo=1")
    assert p.locator("#demo").is_visible() and not p.locator("#session").is_visible()
    p.context.close()


def test_aucune_ressource_externe_dans_la_source():
    assert not re.search(r"(src|href)=[\"']https?://|url\(\s*[\"']?https?://|@import", PAGE.read_text(encoding="utf-8"))


def test_l_onglet_par_defaut_de_soc_est_guardian_et_l_encadre():
    h = (WWW / "index.html").read_text(encoding="utf-8")
    assert re.search(r'id="t0"[^>]*>.*?Guardian', h) and 'aria-selected="true" aria-controls="e0"' in h and 'src="guardian.html"' in h
    assert re.search(r'id="e1" role="tabpanel" aria-labelledby="t1" hidden', h)       # Vigie (l'ancienne page) reste, masquée par défaut


def test_la_hauteur_envoyee_ne_depend_pas_de_la_hauteur_de_l_iframe():
    """documentElement.scrollHeight >= hauteur de l'iframe : la page ne pouvait que grandir (vide de 3000 px)."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1] / "www/soc/guardian.html").read_text()
    assert "sbxSocVue:document.documentElement.scrollHeight" not in src
    assert "querySelector('.cadre').getBoundingClientRect()" in src


def _navigateur(page, interroger):
    """Exécute `interroger(page)` dans un thread propre : Playwright (API synchrone) refuse de tourner
    sous une boucle asyncio, et un test asynchrone voisin peut en laisser une active (#2423)."""
    import concurrent.futures
    import pytest
    sync_api = pytest.importorskip("playwright.sync_api")

    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", f"chromium indisponible : {e}")
            pg = nav.new_page()
            erreurs = []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.goto("file://" + str(page) + "?demo=1")
            pg.wait_for_timeout(500)
            r = interroger(pg)
            nav.close()
            return ("ok", r, erreurs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1], res[2]


def test_appareils_principaux_empiles_par_usage_et_regroupes_2423():
    """#2423 : barres empilées par type d'usage ; les identités de même adresse de tunnel sont regroupées (déduit) ; aucune erreur JavaScript."""
    import pathlib
    page = pathlib.Path(__file__).resolve().parents[1] / "www" / "soc" / "guardian.html"
    (noms, segments), erreurs = _navigateur(page, lambda pg: (
        pg.evaluate("[...document.querySelectorAll('#appareils .ligne .n')].map(e => e.textContent.trim())"),
        pg.evaluate("document.querySelectorAll('#appareils .ligne i').length")))
    assert erreurs == [], erreurs
    assert any(n.startswith("Appareil · .204") and "×2" in n for n in noms)   # deux identités sur .204 regroupées
    assert segments >= 4                                                          # barres empilées : plusieurs types d'usage


def test_panneau_filtrage_web_2430():
    """#2430 : Guardian lit /api/v1/webfilter/etat : barres bloqué/observé par catégorie, mode dit ; sans session « Session requise »."""
    import pathlib
    page = pathlib.Path(__file__).resolve().parents[1] / "www" / "soc" / "guardian.html"
    (note, lignes, texte), erreurs = _navigateur(page, lambda pg: (
        pg.evaluate("document.getElementById('wfNote').textContent"),
        pg.evaluate("document.querySelectorAll('#wf .ligne').length"),
        pg.evaluate("document.getElementById('wf').textContent")))
    assert erreurs == [], erreurs
    assert "blocage actif" in note and lignes == 4
    assert "980 / 1 240" in texte.replace(" ", " ").replace(" ", " ") and "aurait bloqué" in texte
    src = page.read_text(encoding="utf-8")
    assert "/api/v1/webfilter/etat" in src and "Session requise" in src
