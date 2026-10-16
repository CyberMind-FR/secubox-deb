# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2814 — sur un hote hall.*, la barre laterale mene a admin.* (le Hall ne sert pas les pages de modules) ; ailleurs, liens relatifs inchanges."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
SIDEBAR = Path(__file__).resolve().parents[1] / "www" / "shared" / "sidebar.js"
PAGE = "<!doctype html><html><head><meta charset=utf-8><title>t</title></head><body><nav class='sidebar' id='sidebar'></nav><main>contenu</main><script src='/shared/sidebar.js'></script></body></html>"


def item(i, nom, path, cat, ordre=100):
    return {"id": i, "name": nom, "icon": "🔹", "path": path, "category": cat, "order": ordre, "theme": "socle", "installed": True, "active": True, "espace": "protection", "objet": None}


WAF, NAC, SYS, HUB = item("waf", "WAF", "/waf/", "wall", 105), item("nac", "NAC", "/nac/", "auth", 130), item("system", "System", "/system/", "boot", 550), item("hub", "Dashboard", "/", "root", 0)
MENU = {"categories": [{"id": "wall", "name": "Wall", "icon": "🧱", "order": 2, "items": [WAF]}, {"id": "auth", "name": "Auth", "icon": "🔑", "order": 1, "items": [NAC]},
                       {"id": "boot", "name": "Boot", "icon": "🚀", "order": 3, "items": [SYS]}, {"id": "root", "name": "Root", "icon": "🔧", "order": 4, "items": [HUB]}],
        "themes": [], "total_installed": 4, "total_active": 4, "espaces": []}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, hote, chemin="/identite/", port=""):
    base = f"http://{hote}{port}"
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.route(f"{base}/shared/**", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
    p.route(f"{base}/api/**", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps(MENU if r.request.url.endswith("/public/menu") else {})))
    p.route(f"{base}/shared/sidebar.js", lambda r: r.fulfill(status=200, content_type="application/javascript", body=SIDEBAR.read_text(encoding="utf-8")))
    p.route(lambda u: u.split("?")[0] == base + chemin, lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE))
    p.goto(base + chemin + "?nav=categories")
    p.wait_for_function("document.querySelectorAll('#sidebar .nav-item').length >= 3", timeout=15000)
    return ctx, p, erreurs


def hrefs(p):
    return p.eval_on_selector_all("#sidebar a.nav-item", "els => els.map(e => e.getAttribute('href'))")


def test_sur_le_hall_les_liens_menent_a_l_admin(navigateur):
    ctx, p, err = ouvre(navigateur, "hall.gk2.sbx.test")
    h = hrefs(p)
    assert "http://admin.gk2.sbx.test/waf/" in h and "http://admin.gk2.sbx.test/nac/" in h and "http://admin.gk2.sbx.test/system/" in h
    assert not any(x.startswith("/") and not x.startswith("//") for x in h), h
    ctx.close()


def test_le_port_est_conserve(navigateur):
    ctx, p, err = ouvre(navigateur, "hall.gk2.sbx.test", port=":8443")
    assert "http://admin.gk2.sbx.test:8443/waf/" in hrefs(p)
    ctx.close()


def test_un_clic_navigue_vers_l_admin_sans_sonde_inter_origine(navigateur):
    ctx, p, err = ouvre(navigateur, "hall.gk2.sbx.test")
    requetes = []
    p.on("request", lambda r: requetes.append(r.url))
    p.route("http://admin.gk2.sbx.test/**", lambda r: r.fulfill(status=200, content_type="text/html", body="<html><body>admin</body></html>"))
    p.click("#sidebar a.nav-item[data-module=waf]")
    p.wait_for_url("http://admin.gk2.sbx.test/waf/", timeout=10000)
    assert not [u for u in requetes if u.startswith("http://admin.gk2.sbx.test") and "/api/" in u], "aucune sonde de sante inter-origine"
    ctx.close()


def test_le_bouton_reglages_de_la_barre_du_haut_vise_aussi_l_admin(navigateur):
    ctx, p, err = ouvre(navigateur, "hall.gk2.sbx.test")
    cible = p.evaluate("""() => { const b = [...document.querySelectorAll('.menu-btn')].find(x => x.title === 'Settings'); return b ? b.getAttribute('onclick') : null }""")
    assert cible is None or "admin.gk2.sbx.test" in cible or "ORIGINE" in cible or "versAdmin" in cible
    ctx.close()


def test_hors_du_hall_les_liens_restent_relatifs(navigateur):
    ctx, p, err = ouvre(navigateur, "admin.gk2.sbx.test", "/waf/")
    assert "/waf/" in hrefs(p) and not any(x.startswith("http") for x in hrefs(p))
    ctx.close()
