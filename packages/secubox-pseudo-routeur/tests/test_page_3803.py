# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3803 — page d'administration : coque Aurora, CSP par hachage, textContent, routes
existantes, aucun chiffre inventé, pas de débordement à 420/1400."""
import base64
import concurrent.futures
import hashlib
import json
import os
import pathlib
import re

import pytest

RACINE = pathlib.Path(__file__).resolve().parents[1]
SRC = (RACINE / "www" / "pseudo-routeur" / "index.html").read_text(encoding="utf-8")
CODE = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", SRC, flags=re.S))
CAPTURE = os.environ.get("SECUBOX_PR_CAPTURE")


def _hash(c):
    return "'sha256-" + base64.b64encode(hashlib.sha256(c.encode()).digest()).decode() + "'"


def test_coque_aurora():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC[:300] and '<html lang="fr" class="sbx-aurora">' in SRC
    assert '<nav class="sidebar" id="sidebar"' in SRC and "sb.src='/shared/sidebar.js'" in CODE
    assert "[hidden]{display:none!important}" in SRC
    assert "localStorage.getItem('sbx_token')" in CODE and "credentials:'same-origin'" in CODE


def test_csp_par_hash_a_jour():
    m = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', SRC)
    csp = {d.split()[0]: d.split()[1:] for d in (x.strip() for x in m.group(1).split(";")) if d}
    scripts = re.findall(r"<script>(.*?)</script>", SRC, flags=re.S)
    assert len(scripts) == 1
    assert csp["script-src"] == ["'self'", _hash(scripts[0])]
    assert csp["script-src-attr"] == ["'unsafe-inline'"] and csp["default-src"] == ["'self'"]
    assert not re.search(r"<[^>]+\son[a-z]+=", SRC) and ' style="' not in SRC and "<script " not in SRC


def test_textcontent_seulement():
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", CODE)
    assert not re.search(r"\b(confirm|alert|prompt)\(", CODE)
    assert "if(DEMO)return Promise.reject" in CODE


def test_routes_citees_existantes():
    from api import main
    existantes = {r.path for r in main.app.routes}
    citees = set(re.findall(r"(?:lire|ecrire)\('(/[a-z-]+)'", CODE))
    assert {"/etat", "/appareils", "/journal", "/apercu", "/activer", "/retour", "/tester-retour"} <= citees
    assert citees <= existantes, citees - existantes


def test_aucun_pourcentage_ipv6_invente():
    assert "part non visible par gk2" in CODE and not re.search(r"IPv6[^']*\d+ ?%", SRC)


# ── Playwright ──
sync_api = pytest.importorskip("playwright.sync_api")
HOSTILE = "<img src=x onerror=window.xss=1>"
ETAT = {"actif": False, "depuis": None, "table_presente": False, "ip_forward": True, "lan_if": "eth2",
        "ip_gk2": "192.0.2.200", "ip_freebox": "192.0.2.254", "passerelle_distribuee": None, "passerelle_lue_a": None,
        "sonde": {"active": False, "echecs_consecutifs": 0, "historique": []}, "compteurs": {"lan": None, "rejete": None}}
APP = {"lan_if": "eth2", "releve": 1, "chaine_chargee": False, "appareils": [
    {"mac": "02:00:5e:00:00:01", "nom": HOSTILE, "ipv4": ["192.0.2.1"], "ipv6_globales": ["2001:db8::1"], "ipv6_actif": True,
     "zone": "blocked", "passe_par_gk2": None}]}


def _page(scenario, largeur=1400, chemin="/pseudo-routeur/"):
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e))
            pg = nav.new_page(viewport={"width": largeur, "height": 900})
            erreurs, posts = [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))

            def api(route):
                u = route.request.url
                if route.request.method == "POST":
                    posts.append(u)
                    corps = {"modifie": False, "pret": True, "etapes": [{"etape": "x", "possible": True, "detail": "y"}]}
                    return route.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
                corps = APP if "/appareils" in u else {"entrees": []} if "/journal" in u else ETAT
                route.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
            pg.route("http://t.test/api/**", api)
            pg.route("http://t.test/shared/**", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
            pg.route("http://t.test/pseudo-routeur/**", lambda r: r.fulfill(status=200, content_type="text/html", body=SRC))
            pg.goto("http://t.test" + chemin)
            pg.wait_for_timeout(500)
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, posts)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=90)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1:]


def test_valeurs_absentes_jamais_inventees():
    def sc(pg):
        return pg.inner_text(".tuiles"), pg.inner_text("#appareils"), pg.evaluate("window.xss")
    (tuiles, app, xss), erreurs, _ = _page(sc)
    assert not erreurs and xss is None
    assert "inconnue" in tuiles and "aucune chaîne chargée" in tuiles and "pas de mesure" in tuiles
    assert HOSTILE in app and "IPv6 actif" in app and "part non visible par gk2" in app and "bloqué" in app
    assert "%" not in app


def test_activer_demande_confirmation_et_tester_retour():
    def sc(pg):
        pg.click("#btn-activer")
        conf = pg.inner_text("#zone-activer .confirm")
        pg.click("#zone-activer >> text=Annuler")
        pg.click("#btn-tester")
        pg.wait_for_timeout(300)
        return conf, pg.inner_text("#etapes")
    (conf, etapes), erreurs, posts = _page(sc)
    assert "Confirmer" in conf and not erreurs
    assert [u.rsplit("/", 1)[1] for u in posts] == ["tester-retour"] and "rien n'a été modifié" in etapes


MESURE = "() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]"


@pytest.mark.parametrize("largeur", [1400, 420])
def test_aucun_debordement_horizontal(largeur):
    for chemin in ("/pseudo-routeur/", "/pseudo-routeur/?demo=1"):
        def sc(pg):
            if CAPTURE and "demo" in pg.url and largeur == 1400:
                pg.screenshot(path=CAPTURE, full_page=True)
            return pg.evaluate(MESURE)
        (sw, cw), erreurs, _ = _page(sc, largeur, chemin)
        assert not erreurs and sw <= cw, (chemin, sw, cw)
