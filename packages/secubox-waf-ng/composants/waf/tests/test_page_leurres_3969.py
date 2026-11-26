# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3969 — page Leurres : classement compact 10 + « Afficher plus », un seul détail (fiche à la demande, gestes), frise
bornée, ce que tentent les robots regroupé, agrégats repris (modes, population). Vrai navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

W = Path(__file__).resolve().parents[1] / "www" / "waf"
HTML = (W / "leurres.html").read_text(encoding="utf-8")
CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'"
N = int(time.time())


def test_statique():
    assert "innerHTML" not in HTML and len(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", HTML)) == 1
    css = HTML[HTML.index("<style>"):HTML.index("</style>")]
    assert min(float(x) for x in re.findall(r"font-size:([0-9.]+)rem", css)) >= .85
    assert 'href="/waf/#sites"' in HTML and "famille:acces_distant" in HTML and "/leurres-service/modes" in HTML


def attaquants(n):
    return [{"ip": f"198.51.100.{i + 1}", "services": ["telnet"], "profil": "force-brute", "client": "", "visites": 3, "premiere": N - 86400 * (1 + i % 5),
             "derniere": N - 600 * (i + 1), "nb_essais": 1, "essais": [{"compte": "root", "mot_de_passe": "toor"}], "rejeu": False,
             "ban": {"actif": i % 2 == 0, "expire_dans": 3600}} for i in range(n)]


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


def ouvre(nav, rep, suffixe="", largeur=1280):
    p = nav.new_context(viewport={"width": largeur, "height": 900}, locale="fr-FR").new_page()
    p.erreurs, p.appels = [], []
    p.on("pageerror", lambda e: p.erreurs.append(str(e)))

    def servir(r):
        u = r.request.url.split("?")[0].split("g.test")[1]
        p.appels.append(u)
        if u.startswith("/api/"):
            c = rep.get(u)
            return r.fulfill(status=200 if c is not None else 401, content_type="application/json", body=json.dumps(c if c is not None else {}))
        f = W / u[len("/waf/"):]
        if u.startswith("/waf/") and f.is_file():
            return r.fulfill(status=200, content_type="text/html", body=f.read_text(encoding="utf-8"), headers={"Content-Security-Policy": CSP})
        return r.fulfill(status=404, body="")
    p.route("http://g.test/**", servir)
    p.goto("http://g.test/waf/leurres.html" + suffixe)
    p.wait_for_timeout(600)
    return p


B = "/api/v1/waf/leurres/"


def api(n, x=None):
    a = attaquants(n)
    if x:
        a[0].update(client=x, essais=[{"compte": x, "mot_de_passe": x}])
    return {B + "resume": {"attaquants": n, "couples": 1, "rejeux": 0, "touches": 3 * n, "bans_actifs": 1, "par_leurre": {"telnet": 3 * n}, "premiere": N - 86400},
            B + "attaquants": {"attaquants": a, "total": n}, B + "dictionnaire": {"couples": 1, "mots_de_passe": [], "comptes": []}, B + "rejeux": {},
            B + "attaquant/198.51.100.1": {"ip": "198.51.100.1", "visites": [{"ts": N - 60, "service": "telnet", "profil": "force-brute", "action": "warning", "client": "", "essais": []}]},
            "/api/v1/waf/leurres-service/modes": {"leurres": [{"service": "telnet", "mode": "bannir"}]},
            "/api/v1/waf/populations": {"disponible": True, "genere_le": N, "populations": [{"id": "famille:acces_distant", "adresses": 40, "etat": "bannie", "serie": [1, 2, 3, 4, 5, 6, 7]}]}}


def test_liste_bornee_detail_fiche_a_la_demande(nav):
    p = ouvre(nav, api(25))
    assert p.locator("#att .cl").count() == 10 and p.inner_text("#plus") == "Afficher 10 de plus (15 restantes)"
    p.click("#plus")
    assert p.locator("#att .cl").count() == 20
    assert p.locator("#frise .fr-r").count() == 12 and "+ 13 attaquants" in p.inner_text("#frise")
    assert not re.search(r"198\.51\.100\.\d", p.inner_text("#att") + p.inner_text("#frise"))       # masquées hors du détail
    assert "198.51.100.1" in p.inner_text("#detail h3") and "Prolonger" in p.inner_text("#detail")
    assert B + "attaquant/198.51.100.1" not in p.appels                                            # fiche lue à la demande
    p.locator("#detail details summary").click()
    p.wait_for_timeout(300)
    assert "telnet · force brute" in p.inner_text("#detail details")
    assert "bannit" in p.inner_text("#leurres") and p.inner_text("#tP") == "40" and p.locator("#tPm rect").count() == 7
    p.locator("#att .cl").first.focus()
    p.keyboard.press("ArrowDown")
    p.keyboard.press("Enter")
    assert "198.51.100.2" in p.inner_text("#detail h3") and not p.erreurs
    p.context.close()


def test_aucune_injection(nav):
    x = "<img src=x onerror=window.xss=1>"
    p = ouvre(nav, api(1, x))
    assert x in p.inner_text("#detail") and p.evaluate("window.xss") is None and p.locator("img").count() == 0 and not p.erreurs
    p.context.close()


@pytest.mark.parametrize("suffixe", ["?demo=1", "?demo=1&embed=1"])
def test_demo_400_px(nav, suffixe):
    p = ouvre(nav, {}, suffixe, 400)
    assert p.locator("#demo").is_visible() and p.locator("#att .cl").count() == 10 and not [u for u in p.appels if u.startswith("/api/")]
    p.evaluate("document.querySelectorAll('details').forEach(function(d){d.open=true;})")
    p.wait_for_timeout(200)
    assert p.evaluate("document.documentElement.scrollWidth") <= 400
    assert p.evaluate("[...document.querySelectorAll('#cadre button, #cadre summary, #cadre select, #cadre input')].filter(function(e){return e.offsetParent&&e.getBoundingClientRect().height<40;}).length") == 0
    assert not p.erreurs
    p.context.close()
