# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3969 — page Attaquants du WAF : frise fine bornée, classement compact + un détail, répartitions regroupées,
adresses masquées hors du détail replié. Vrai navigateur, API simulée (g.test), CSP du vhost."""
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

W = Path(__file__).resolve().parents[1] / "composants" / "waf" / "www" / "waf"
HTML = (W / "attaquants.html").read_text(encoding="utf-8")
CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'"
NOW = time.time()


def iso(h):
    return datetime.fromtimestamp(NOW - h * 3600, timezone.utc).isoformat()


def test_bas_sans_innerhtml_lisible_et_sans_donut():
    bloc = HTML[HTML.index("// ---- Bas de page (#3969)"):HTML.index("// ---- Fin du bas de page")]
    assert "innerHTML" not in bloc and "donut" not in HTML
    css = HTML[HTML.index("/* bas (#3969)"):HTML.index("/* fin du bas */")]
    assert min(float(x) for x in re.findall(r"font-size:([0-9.]+)rem", css)) >= .85 and "prefers-reduced-motion" in css


def suivis(n):
    return [{"ip": f"198.51.100.{i + 1}", "count": 500 - i, "first_seen": iso(20 - i * .5), "last_seen": iso(i * .3), "severity_max": "high" if i % 2 else "critical",
             "currently_banned": i % 3 == 0, "top_categories": [{"category": "sqli", "count": 10}], "sample_path": "/p"} for i in range(n)]


@pytest.fixture(scope="module")
def nav():
    api = pytest.importorskip("playwright.sync_api")
    with api.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as e:
            pytest.skip(f"chromium indisponible : {e}")
        yield b
        b.close()


def ouvre(nav, tracked, suffixe="", largeur=1280):
    p = nav.new_context(viewport={"width": largeur, "height": 900}, locale="fr-FR", timezone_id="Europe/Paris").new_page()
    p.erreurs = []
    p.on("pageerror", lambda e: p.erreurs.append(str(e)))

    def servir(r):
        u = r.request.url.split("?")[0].split("g.test")[1]
        if u == "/api/v1/waf/bans/history" and tracked is not None:
            return r.fulfill(status=200, content_type="application/json", body=json.dumps({"window_hours": 24, "tracked": tracked}))
        if u.startswith("/api/"):
            return r.fulfill(status=401, content_type="application/json", body="{}")
        f = W / u[len("/waf/"):]
        if u.startswith("/waf/") and f.is_file():
            return r.fulfill(status=200, content_type="text/html", body=f.read_text(encoding="utf-8"), headers={"Content-Security-Policy": CSP})
        return r.fulfill(status=404, body="")
    p.route("http://g.test/**", servir)
    p.goto("http://g.test/waf/attaquants.html" + suffixe)
    p.wait_for_timeout(600)
    return p


def test_frise_bornee_tableau_plus_et_detail(nav):
    p = ouvre(nav, suivis(25))
    assert p.locator("#frise .fr-r").count() == 12 and "+ 13 adresses" in p.inner_text("#frise")
    assert all(p.locator("#frise .fr-r").nth(i).bounding_box()["height"] <= 30 for i in range(12))
    assert p.locator("#rang .cl").count() == 10 and p.inner_text("#plus") == "Afficher 10 de plus (15 restantes)"
    p.click("#plus")
    assert p.locator("#rang .cl").count() == 20
    # aucune adresse en clair hors du détail replié
    texte = p.inner_text("#bas")
    assert "198.51.•.•" in texte and not re.search(r"198\.51\.100\.\d", texte)
    p.locator("#detail details summary").click()
    assert "198.51.100.1" in p.inner_text("#detail details")
    p.locator("#frise .fr-r").nth(11).click()
    assert p.locator("#rang .cl").nth(11).get_attribute("aria-current") == "true" and p.evaluate("document.activeElement.id") == "detail"
    p.locator("#rang .cl").first.focus()
    p.keyboard.press("ArrowDown")
    p.keyboard.press("Enter")
    assert p.locator("#rang .cl").nth(1).get_attribute("aria-current") == "true"
    p.locator("#legG [data-g=critical]").click()
    assert p.locator("#rang .cl").count() == 10 and p.input_value("#fg") == "critical" and "13 sur 25" in p.inner_text("#nbAff")
    assert not p.erreurs
    p.context.close()


def test_aucune_injection(nav):
    x = "<img src=x onerror=window.xss=1>"
    t = suivis(1)
    t[0].update(ip=x, top_categories=[{"category": x, "count": 3}], sample_path=x)
    p = ouvre(nav, t)
    p.locator("#detail details summary").click()
    assert x in p.inner_text("#detail") and p.evaluate("window.xss") is None and p.locator("#bas img").count() == 0 and not p.erreurs
    p.context.close()


def test_session_requise(nav):
    p = ouvre(nav, None)
    assert "Session requise" in p.inner_text("#rang") and p.locator("#session").is_visible() and not p.erreurs
    p.context.close()


@pytest.mark.parametrize("suffixe", ["?demo=1", "?demo=1&embed=1"])
def test_demo_400_px(nav, suffixe):
    p = ouvre(nav, None, suffixe, 400)
    p.evaluate("document.querySelectorAll('#bas details').forEach(function(d){d.open=true;})")
    assert p.locator("#rang .cl").count() == 9 and p.evaluate("document.documentElement.scrollWidth") <= 400
    assert p.evaluate("[...document.querySelectorAll('#bas button, #bas summary, #bas input, #bas select')].filter(function(e){return e.offsetParent&&e.getBoundingClientRect().height<40;}).length") == 0
    assert not p.erreurs
    p.context.close()
