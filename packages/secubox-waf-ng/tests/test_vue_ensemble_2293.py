# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2293 : la vue d'ensemble SBXWAF affiche les mesures du WAF, dit « — » sans mesure, échappe tout, n'appelle rien d'externe ; /waf/ l'ouvre par défaut et la racine du vhost la sert."""
import json
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
RACINE = Path(__file__).resolve().parents[1] / "composants" / "waf"
WWW = RACINE / "www" / "waf"
VUE = WWW / "vue.html"
STATS = {"par_origine": {"waf": 1282856}, "blocked_24h": 136638, "by_severity": {"critical": 5, "high": 10, "medium": 20, "info": 900},
         "by_category": {"robots": 383, "sqli": 30, "lfi": 5}, "par_type": {"http": 100, "ssh": 3}, "top_countries": [{"country": "US", "count": 9}],
         "top_vhosts": [{"vhost": "app.test", "count": 4}]}
ALERTES = {"alerts": [{"timestamp": "2026-10-11T06:40:46+02:00", "client_ip": "1.2.3.4", "country": "US", "category": "<img src=x onerror=window.xss=1>", "host": "h", "path": "/p", "severity": "high", "action": "banned"}]}


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, reponses, url="http://w.test/waf/vue.html"):
    p = nav.new_context().new_page()
    externes, erreurs = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("request", lambda r: externes.append(r.url) if not r.url.startswith(("http://w.test", "data:")) else None)

    def api(r):
        corps = reponses.get(r.request.url.split("?")[0].split("w.test")[1])
        r.fulfill(status=200 if corps is not None else 401, content_type="application/json", body=json.dumps(corps if corps is not None else {}))
    p.route("http://w.test/api/**", api)
    p.route("http://w.test/waf/vue.html*", lambda r: r.fulfill(status=200, content_type="text/html", body=VUE.read_text(encoding="utf-8")))
    p.goto(url)
    p.wait_for_timeout(600)
    return p, externes, erreurs


def test_les_mesures_du_waf_sont_affichees_et_les_noms_echappes(nav):
    p, externes, erreurs = ouvre(nav, {"/api/v1/waf/stats": STATS, "/api/v1/waf/status": {"enabled": True, "total_rules": 158, "autoban_enabled": True}, "/api/v1/waf/alerts": ALERTES})
    t = p.inner_text("body").replace(" ", " ")
    assert "1 282 856" in t and "136 638" in t and "ACTIF · 158 RÈGLES" in t and "35" in t   # menaces = critique + haute + moyenne
    assert p.evaluate("window.xss") is None and "<img" in t
    assert not externes and not erreurs
    p.context.close()


def test_sans_session_les_mesures_sont_des_tirets_et_on_invite_a_se_connecter(nav):
    p, _, _ = ouvre(nav, {})
    assert p.locator(".tuile .v").first.inner_text() == "—"
    assert p.locator("#session").is_visible() and "Se connecter" in p.inner_text("#session")
    p.context.close()


def test_le_mode_demo_est_annonce(nav):
    p, _, _ = ouvre(nav, {}, "http://w.test/waf/vue.html?demo=1")
    assert p.locator("#demo").is_visible() and not p.locator("#session").is_visible()
    p.context.close()


def test_aucune_ressource_externe_dans_la_source():
    assert not re.search(r"(src|href)=[\"']https?://|url\(\s*[\"']?https?://|@import", VUE.read_text(encoding="utf-8"))


def test_la_page_waf_ouvre_la_vue_d_ensemble_par_defaut():
    h = (WWW / "index.html").read_text(encoding="utf-8")
    assert 'data-tab="vue"' in h and 'src="vue.html"' in h and 'switchTab("vue")' in h


def test_la_racine_du_vhost_sert_la_vue_et_garde_l_ancien_tableau():
    c = (RACINE / "nginx" / "waf-vhost.conf").read_text(encoding="utf-8")
    assert "location = / { try_files /vue.html =404; }" in c and "location = /tableau { try_files /tableau.html =404; }" in c
