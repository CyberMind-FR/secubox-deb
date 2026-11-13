# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3676 : encart « Pubs bloquées récemment » dans la vue par appareil (onglet Applications) de la page SBX TV Privacy."""
import concurrent.futures
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "tv-privacy" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
CODE = re.findall(r"<script>(.*?)</script>", SRC, flags=re.S)[0]


def test_encart_present_route_existante_et_texte_seulement():
    assert "Pubs bloquées récemment" in SRC and 'id="ap-pubs"' in SRC
    assert "source('/appareils/'+encodeURIComponent(nom)+'/pubs-bloquees')" in CODE
    from api import dnstv_routes as r
    assert "/adblock-tv/appareils/{nom}/pubs-bloquees" in {x.path for x in r.router.routes}
    assert "innerHTML" not in CODE


sync_api = pytest.importorskip("playwright.sync_api")
HOSTILE = "<img src=x onerror=window.xss=1>"


def _ouvrir(url, api=None):
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:                       # noqa: BLE001 — navigateur absent : test sauté
                return ("skip", str(e))
            pg = nav.new_page()
            erreurs, gets = [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            if api:
                def rep(route):
                    gets.append(route.request.url)
                    route.fulfill(status=200, content_type="application/json", body=json.dumps(api(route.request.url)))
                pg.route("http://t.test/api/**", rep)
            pg.route("http://t.test/shared/**", lambda r: r.fulfill(status=200, content_type="text/javascript", body=""))
            pg.route("http://t.test/tv-privacy/**", lambda r: r.fulfill(status=200, content_type="text/html", body=SRC))
            pg.goto(url)
            pg.wait_for_timeout(500)
            pg.click("#t-applications")
            pg.wait_for_timeout(500)
            r = (pg.inner_text(".pubs"), pg.evaluate("() => window.xss === undefined"))
            nav.close()
            return ("ok", r, erreurs, gets)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=90)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1:]


def test_demonstration_regroupe_par_service():
    (texte, sur), erreurs, _ = _ouvrir("http://t.test/tv-privacy/?demo=1")
    assert not erreurs and sur
    assert "Exemple TV — 2 domaines, 12 blocages" in texte
    assert re.search(r"adproxy\.example\.com · \d\d:\d\d · ×8 · liste adblock", texte)
    assert "pub.example.com" in texte and "règle TV Privacy (confirmée)" in texte
    assert "example.net — 1 domaine, 2 blocages" in texte and "indice de gk1" in texte
    assert "illisibles" not in texte                                              # listes lisibles : aucune note


def test_sans_dpi_l_appareil_reste_choisissable_et_les_donnees_sont_du_texte():
    def api(u):
        if "/protection/dpi/etat" in u:
            return {"disponible": False, "raison": "absent", "appareils": []}
        if "/pubs-bloquees" in u:
            return {"maj": 1761955200, "verifie": 1761955800, "fenetre_s": 86400, "listes_lisibles": False, "services": [
                {"service": HOSTILE, "nombre": 3, "dernier_ts": 1761955100,
                 "domaines": [{"domaine": HOSTILE, "dernier_ts": 1761955100, "nombre": 3, "source": "autre", "detail": "autre"}]}]}
        if "/protection/" in u:
            return {}
        return {"appareils": [{"mac": "02:00:5e:00:00:01", "nom": "TV salon", "ips": ["192.0.2.1"], "mode": "auto"}], "profils": []}
    (texte, sur), erreurs, gets = _ouvrir("http://t.test/tv-privacy/", api)
    assert not erreurs and sur
    assert HOSTILE + " — 1 domaine, 3 blocages" in texte and "×3 · autre" in texte
    assert "Listes compilées (adblock, adulte, filtre web) illisibles par le moteur" in texte
    assert any(u.endswith("/api/v1/ad-guard/adblock-tv/appareils/TV%20salon/pubs-bloquees") for u in gets)
