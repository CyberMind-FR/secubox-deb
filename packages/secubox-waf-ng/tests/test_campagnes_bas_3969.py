# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3969 — bas de la page Campagnes du WAF : frise bornée, tableau compact + un détail, « Ce qui est visé ».
Vrai navigateur, API simulée (g.test), CSP du vhost."""
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

W = Path(__file__).resolve().parents[1] / "composants" / "waf" / "www" / "waf"
HTML = (W / "campagnes.html").read_text(encoding="utf-8")
CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'"
NOW = time.time()
H = 3600


def iso(age_h):
    return datetime.fromtimestamp(NOW - age_h * H, timezone.utc).isoformat()


def test_un_seul_script_en_ligne_sans_innerhtml_dans_le_bas():
    assert len(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", HTML)) == 1
    bloc = HTML[HTML.index("// ---- Bas de page (#3969)"):HTML.index("// ---- Fin du bas de page")]
    for interdit in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert interdit not in bloc, interdit
    assert "donut" not in HTML and 'id="cartes"' not in HTML


def test_texte_du_bas_lisible_et_mouvement_reduit():
    css = HTML[HTML.index("/* bas (#3969)"):HTML.index("/* fin du bas */")]
    tailles = [float(x) for x in re.findall(r"font-size:([0-9.]+)rem", css)]
    assert tailles and min(tailles) >= .85
    assert "prefers-reduced-motion" in css and "min-height:40px" in css


def campagnes(n, alertes_par=4, age0=0.5):
    """n campagnes datées : la i-ème a son dernier signe à age0 + i heures, trois adresses de documentation."""
    camps, al = [], []
    for i in range(n):
        ips = [f"198.51.{i}.{k}" for k in range(1, 4)]
        camps.append({"signature": f"{i:04x}deadbeef{i:04x}", "outil": f"outil-{i:02d}", "attaquants": ips, "nb_attaquants": 3,
                      "sondes": 100 + i, "haute_valeur": 0, "exemple_sequence": ["GET /", f"GET /p{i}"]})
        for k in range(alertes_par):
            al.append({"timestamp": iso(age0 + i + k * 20), "client_ip": ips[k % 3], "host": f"h{i}.example.test", "category": "scanners",
                       "severity": "high", "country": "FR", "action": "banned" if k == 1 else "warning"})
    return camps, al


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


def ouvre(nav, reponses, suffixe="", largeur=1280):
    p = nav.new_context(viewport={"width": largeur, "height": 900}, locale="fr-FR", timezone_id="Europe/Paris").new_page()
    p.erreurs = []
    p.on("pageerror", lambda e: p.erreurs.append(str(e)))

    def servir(r):
        u = r.request.url.split("?")[0].split("g.test")[1]
        if u.startswith("/api/"):
            c = reponses.get(u)
            return r.fulfill(status=200 if c is not None else 401, content_type="application/json", body=json.dumps(c if c is not None else {}))
        f = W / u[len("/waf/"):]
        if u.startswith("/waf/") and f.is_file():
            return r.fulfill(status=200, content_type="text/javascript" if u.endswith(".js") else "text/html",
                             body=f.read_text(encoding="utf-8"), headers={"Content-Security-Policy": CSP})
        return r.fulfill(status=404, body="")
    p.route("http://g.test/**", servir)
    p.goto("http://g.test/waf/campagnes.html" + suffixe)
    p.wait_for_timeout(600)
    return p


def api(camps, al, bans=(), pops=None):
    r = {"/api/v1/waf/campaigns": {"available": True, "attaquants": sum(len(c["attaquants"]) for c in camps), "campagnes": camps},
         "/api/v1/waf/alerts": {"alerts": al}, "/api/v1/waf/bans": {"bans": [{"ip": ip} for ip in bans]}}
    if pops is not None:
        r["/api/v1/waf/populations"] = pops
    return r


def test_frise_bornee_triee_et_non_lu_dit(nav):
    camps, al = campagnes(25)
    p = ouvre(nav, api(camps, al))
    lignes = p.locator("#frise .fr-r")
    assert lignes.count() == 12
    noms = [lignes.nth(i).locator("b").inner_text() for i in range(12)]
    assert noms == [f"outil-{i:02d}" for i in range(12)]                       # du dernier signe le plus récent
    assert "+ 13 campagnes datées" in p.inner_text("#frise")
    assert all(lignes.nth(i).bounding_box()["height"] <= 30 for i in range(12))  # ligne fine au bureau
    # la plus ancienne alerte lue date d'environ 84 h : avant, hachuré et dit, jamais un zéro
    assert lignes.first.locator(".nl").count() == 1 and "non lu" in p.inner_text("#frBas")
    assert "alertes lues remontent au" in p.inner_text("#frBas")
    assert lignes.first.locator(".mk.ban").count() == 1 and lignes.first.locator(".mk.der").count() == 1
    t = lignes.first.locator(".tr").first
    assert re.search(r"outil-00 · .+ : \d+ alertes?", t.get_attribute("title"))
    t.hover()
    assert "outil-00" in p.inner_text("#frLecture")
    assert not p.erreurs
    p.context.close()


def test_tableau_afficher_plus_et_detail(nav):
    camps, al = campagnes(25)
    p = ouvre(nav, api(camps, al, bans=["198.51.0.1"]))
    assert p.locator("#liste .cl").count() == 10
    assert p.inner_text("#plus") == "Afficher 10 de plus (15 restantes)"
    p.click("#plus")
    assert p.locator("#liste .cl").count() == 20
    assert p.evaluate("document.activeElement.getAttribute('data-sig')") == camps[10]["signature"]
    p.click("#plus")
    assert p.locator("#liste .cl").count() == 25 and not p.locator("#plus").is_visible()
    # un seul détail : la première campagne, adresses repliées
    d = p.inner_text("#detail")
    assert "outil-00" in d and "h0.example.test" in d and "GET /p0" in d and "bannie 1/3" in d
    assert p.locator("#detail details").count() == 1 and not p.locator("#detail .adr").is_visible()
    p.locator("#detail details summary").click()
    assert "198.51.0.1 (bannie)" in p.inner_text("#detail .adr")
    p.click("#rafraichir")                                                       # un nouveau relevé garde ce qui est ouvert
    p.wait_for_timeout(400)
    assert p.locator("#liste .cl").count() == 25 and p.locator("#detail .adr").is_visible()
    assert not p.erreurs
    p.context.close()


def test_clavier_et_choix_depuis_la_frise(nav):
    camps, al = campagnes(14)
    p = ouvre(nav, api(camps, al))
    p.locator("#liste .cl").first.focus()
    p.keyboard.press("ArrowDown")
    assert p.evaluate("document.activeElement.getAttribute('data-sig')") == camps[1]["signature"]
    p.keyboard.press("End")
    assert p.evaluate("document.activeElement.getAttribute('data-sig')") == camps[9]["signature"]
    p.keyboard.press("Enter")
    assert p.locator("#detail h4").inner_text() == "outil-09"
    assert p.locator(f'#liste [data-sig="{camps[9]["signature"]}"]').get_attribute("aria-current") == "true"
    # depuis la frise, une campagne au-delà des 10 lignes : le tableau s'ouvre jusqu'à elle, le détail prend le focus
    p.locator("#frise .fr-r").nth(11).click()
    assert p.locator("#detail h4").inner_text() == "outil-11"
    assert p.locator("#liste .cl").count() == 14 and p.evaluate("document.activeElement.id") == "detail"
    assert p.locator("#frise .fr-r").nth(11).get_attribute("aria-current") == "true"
    p.locator("#frise .fr-r").first.focus()
    p.keyboard.press("ArrowDown")
    assert p.evaluate("document.activeElement.getAttribute('data-sig')") == camps[1]["signature"]
    assert not p.erreurs
    p.context.close()


def test_aucune_injection(nav):
    x = "<img src=x onerror=window.xss=1>"
    camps = [{"signature": "<img src=x onerror=window.xss=2>", "outil": x, "attaquants": ["203.0.113.9", x], "nb_attaquants": 2, "sondes": 3,
              "haute_valeur": 1, "exemple_sequence": [x]}]
    al = [{"timestamp": iso(1), "client_ip": "203.0.113.9", "host": x, "category": x, "severity": "critical", "country": "<b>", "action": "banned"}]
    p = ouvre(nav, api(camps, al, bans=[x]))
    p.locator("#detail details summary").click()
    t = p.inner_text("#bas")
    assert x in t and p.evaluate("window.xss") is None
    assert p.locator("#bas img").count() == 0 and p.locator("#bas b b").count() == 0 and not p.erreurs
    p.context.close()


def test_rien_d_invente(nav):
    """Alertes illisibles : rien n'est daté ni dessiné, et c'est dit ; une campagne sans alerte reste repliée."""
    camps, _ = campagnes(3)
    p = ouvre(nav, {"/api/v1/waf/campaigns": {"available": True, "attaquants": 9, "campagnes": camps}, "/api/v1/waf/bans": {"bans": []}})
    assert p.locator("#frise .fr-r").count() == 0 and "Alertes illisibles" in p.inner_text("#frise")
    assert p.locator("#liste .cl").count() == 0 and "Campagnes sans alerte récente (3)" in p.inner_text("#sans")
    assert p.locator("#frise .tr").count() == 0 and not p.erreurs
    p.context.close()


def test_mini_serie_du_releve_des_populations(nav):
    camps, al = campagnes(2)
    pops = {"disponible": True, "complet": True, "genere_le": int(NOW) - 60, "age_s": 60, "populations": [
        {"id": "profileur:" + camps[0]["signature"], "famille": "collecte", "cibles": ["h0.example.test"], "adresses": 12, "serie": [5, 0, 3, 9, 1, 4, 7],
         "etat": "observee"}]}
    p = ouvre(nav, api(camps, al, pops=pops))
    p.wait_for_timeout(300)
    l0, l1 = p.locator("#liste .cl").nth(0), p.locator("#liste .cl").nth(1)
    assert "relevé des populations" in l0.locator(".c-m").get_attribute("title") and l0.locator(".mini rect").count() == 7
    assert "alertes lues par jour" in l1.locator(".c-m").get_attribute("title")
    assert not p.erreurs
    p.context.close()


@pytest.mark.parametrize("suffixe", ["?demo=1", "?demo=1&embed=1"])
def test_demo_400_px_sans_debordement_cibles_40(nav, suffixe):
    p = ouvre(nav, {}, suffixe, 400)
    assert p.locator("#frise .fr-r").count() == 12 and "+ 2 campagnes" in p.inner_text("#frise")
    assert p.locator("#liste .cl").count() == 10 and p.locator("#plus").is_visible()
    p.locator("#detail details summary").click()
    p.evaluate("document.querySelectorAll('#bas details').forEach(function(d){d.open=true;})")
    assert p.evaluate("document.documentElement.scrollWidth") <= 400
    assert p.evaluate("[...document.querySelectorAll('#bas *')].filter(function(e){return e.getBoundingClientRect().right>401;}).length") == 0
    assert p.evaluate("[...document.querySelectorAll('#bas button, #bas summary')].filter(function(e){return e.offsetParent&&e.getBoundingClientRect().height<40;}).length") == 0
    assert p.evaluate("Math.min(...[...document.querySelectorAll('#bas *')].filter(function(e){return e.offsetParent&&e.childNodes.length&&[...e.childNodes].some(function(n){return n.nodeType===3&&n.textContent.trim();});}).map(function(e){return parseFloat(getComputedStyle(e).fontSize);}))") >= 13.5
    assert not p.erreurs
    p.context.close()
