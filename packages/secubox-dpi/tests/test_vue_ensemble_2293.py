# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2293 : la vue d'ensemble DPI affiche les mesures de sbxdpi, dit « — » sans mesure, échappe tout, n'appelle rien d'externe, et la page admin l'encadre."""
import json
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
WWW = Path(__file__).resolve().parents[1] / "www" / "dpi"
VUE = WWW / "vue.html"
STATS = {"connected": True, "total_flows": 1551979, "total_bytes": 11041112469, "updated_at": 1791694262, "protocols": [{"name": "TLS", "pct": 87.7}, {"name": "DNS", "pct": 9.5}]}
CLIENTS = [{"device": "d1", "name": "<img src=x onerror=window.xss=1>", "bytes": 1000, "usages": [{"name": "ai", "bytes": 600}], "top_dst": [{"host": "h.test", "bytes": 5}]}]
PAYS = [{"cc": "FR", "bytes": 5158589430}, {"cc": "ZZ", "bytes": 5}]


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, reponses, url="http://d.test/dpi/vue.html"):
    p = nav.new_context().new_page()
    externes, erreurs = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("request", lambda r: externes.append(r.url) if not r.url.startswith(("http://d.test", "data:")) else None)

    def api(r):
        corps = reponses.get(r.request.url.split("?")[0].split("d.test")[1])
        r.fulfill(status=200 if corps is not None else 401, content_type="application/json", body=json.dumps(corps if corps is not None else {}))
    p.route("http://d.test/api/**", api)
    p.route("http://d.test/dpi/vue.html*", lambda r: r.fulfill(status=200, content_type="text/html", body=VUE.read_text(encoding="utf-8")))
    p.goto(url)
    p.wait_for_timeout(600)
    return p, externes, erreurs


def test_les_mesures_de_sbxdpi_sont_affichees_et_les_noms_echappes(nav):
    p, externes, erreurs = ouvre(nav, {"/api/v1/dpi/stats": STATS, "/api/v1/dpi/clients": CLIENTS, "/api/v1/dpi/countries": PAYS})
    t = p.inner_text("body").replace(" ", " ")
    assert "1 551 979" in t and "10.3 Go" in t and "DPI ACTIF" in t
    assert p.evaluate("window.xss") is None and "<img" in t
    assert not externes and not erreurs
    p.context.close()


def test_sans_session_les_mesures_sont_des_tirets_et_on_invite_a_se_connecter(nav):
    p, _, _ = ouvre(nav, {})
    assert p.locator(".tuile .v").first.inner_text() == "—"
    assert p.locator("#session").is_visible() and "Se connecter" in p.inner_text("#session")
    p.context.close()


def test_le_mode_demo_est_annonce(nav):
    p, _, _ = ouvre(nav, {}, "http://d.test/dpi/vue.html?demo=1")
    assert p.locator("#demo").is_visible()
    p.context.close()


def test_aucune_ressource_externe_dans_la_source():
    assert not re.search(r"(src|href)=[\"']https?://|url\(\s*[\"']?https?://|@import", VUE.read_text(encoding="utf-8"))


def test_la_page_admin_encadre_la_vue():
    assert 'src="vue.html"' in (WWW / "index.html").read_text(encoding="utf-8")
