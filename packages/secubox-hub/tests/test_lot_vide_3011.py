# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3011 — la barre latérale n'applique qu'un lot de santé REMPLI : un lot vide ou `warming` laisse les
LED sur le dernier état connu au lieu de les passer toutes à « unknown »."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
SIDEBAR = Path(__file__).resolve().parents[1] / "www" / "shared" / "sidebar.js"
PAGE = "<!doctype html><html><head><meta charset=utf-8><title>t</title></head><body><nav class='sidebar' id='sidebar'></nav><main>contenu</main><script src='/shared/sidebar.js'></script></body></html>"


def item(i, nom, path, cat, ordre=100):
    return {"id": i, "name": nom, "icon": "🔹", "path": path, "category": cat, "order": ordre, "theme": "socle", "installed": True, "active": True}


MENU = {"categories": [{"id": "wall", "name": "Wall", "icon": "🧱", "order": 2, "items": [item("waf", "WAF", "/waf/", "wall")]},
                       {"id": "auth", "name": "Auth", "icon": "🔑", "order": 1, "items": [item("nac", "NAC", "/nac/", "auth")]}],
        "themes": [], "espaces": [], "total_installed": 2, "total_active": 2}
PLEIN = {"modules": {"waf": {"status": "ok", "msg": "Running"}, "nac": {"status": "error", "msg": "Failed"}}, "count": 2}
VIDE = {"modules": {}, "count": 0, "warming": True}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, reponses):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(route):
        u = route.request.url
        if u.endswith("/public/menu"):
            corps = MENU
        elif u.endswith("/public/health-batch"):
            corps = reponses["lot"]
        else:
            corps = {}
        route.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/shared/**", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
    p.route("http://sbx.test/api/**", api)
    p.route("http://sbx.test/shared/sidebar.js", lambda r: r.fulfill(status=200, content_type="application/javascript", body=SIDEBAR.read_text(encoding="utf-8")))
    p.route(lambda u: u.split("?")[0] == "http://sbx.test/waf/", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE))
    p.goto("http://sbx.test/waf/")
    p.wait_for_selector("#sidebar .nav-item[data-module='waf'] .status-led", timeout=15000)
    return ctx, p, erreurs


def led(p, mod):
    return p.get_attribute(f"#sidebar .nav-item[data-module='{mod}'] .status-led", "title")


def _relance(p):
    with p.expect_response(lambda r: r.url.endswith("/public/health-batch")):
        p.evaluate("window.SecuBoxSidebar.checkHealth(true)")
    p.wait_for_timeout(200)


def test_un_lot_vide_laisse_les_led_sur_le_dernier_etat(navigateur):
    reponses = {"lot": PLEIN}
    ctx, p, erreurs = ouvre(navigateur, reponses)
    _relance(p)
    assert led(p, "waf") == "Running" and led(p, "nac") == "Failed"
    reponses["lot"] = VIDE
    _relance(p)
    assert led(p, "waf") == "Running"
    assert led(p, "nac") == "Failed"
    assert erreurs == []
    ctx.close()


def test_un_lot_plein_suivant_s_applique(navigateur):
    reponses = {"lot": PLEIN}
    ctx, p, erreurs = ouvre(navigateur, reponses)
    _relance(p)
    assert led(p, "waf") == "Running"
    reponses["lot"] = {"modules": {"waf": {"status": "warn", "msg": "Active (exited)"}, "nac": {"status": "ok", "msg": "Running"}}, "count": 2}
    _relance(p)
    assert led(p, "waf") == "Active (exited)"
    assert led(p, "nac") == "Running"
    assert erreurs == []
    ctx.close()
