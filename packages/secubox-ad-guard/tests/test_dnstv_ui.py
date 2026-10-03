# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Onglet « DNS AdBlock TV » (POC #1943) dans un vrai navigateur, API simulée : rendu, bascule de mode, ajout de domaine, texte échappé."""
import json
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "ad-guard" / "index.html"


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _page(navigateur, appels, etat):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(route):
        req = route.request
        chemin = re.sub(r"^.*?/api/v1/ad-guard", "", req.url).split("?")[0]
        corps = req.post_data
        appels.append((req.method, chemin, json.loads(corps) if corps else None))
        if chemin == "/adblock-tv/status":
            r = {"actif": etat["actif"], "clients": etat["clients"], "erreur": None, "dropin_present": etat["actif"],
                 "listes": {"domaines": 32, "problemes": [], "par_categorie": {}}, "compteurs": {"requetes": 10, "domaines_uniques": 4, "bloques": 3}}
        elif chemin == "/adblock-tv/stats":
            r = {"requetes": 10, "domaines_uniques": 4, "classes_resolus": {"tracking": 2}, "classes_bloques": {"advertising": 3},
                 "par_decision": {"BLOCKED": 3, "ALLOWED": 7},
                 "top_bloques": [{"domaine": "<img src=x onerror=window.__pwn=1>.example", "categorie": "advertising", "hits": 3}]}
        elif chemin == "/adblock-tv/custom":
            r = {"domaines": ["mon-tracker.example"]}
        elif chemin == "/adblock-tv/sonde":
            r = {"nom": "tabc123.sbx-dnspath.invalid"}
        elif chemin == "/adblock-tv/path-test":
            r = {"recue": True, "lecture": "la box a reçu cette requête", "evenements": [{"client": "192.168.1.50", "decision": "ALLOWED"}]}
        else:
            r = {}
        route.fulfill(status=200, content_type="application/json", body=json.dumps(r))
    # Playwright n'intercepte pas file:// : la page est servie, par interception, sous un nom http fictif.
    p.route("http://sbx.test/api/v1/ad-guard/**", api)
    p.route("http://sbx.test/shared/**", lambda r: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://sbx.test/", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.goto("http://sbx.test/")
    return ctx, p, erreurs


def test_onglet_affiche_statistiques_top_et_appareils_sans_executer_de_html(navigateur):
    appels = []
    etat = {"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "Freebox TV salon", "mode": "block"}]}
    ctx, p, erreurs = _page(navigateur, appels, etat)
    p.click("button[data-tab=adblocktv]")
    p.wait_for_selector("#tv-stats .stat-card")
    assert p.is_checked("#tv-actif") and p.is_checked("input[name=tv-mode][value=block]")
    assert "Requêtes DNS" in p.inner_text("#tv-stats") and "Bloqués" in p.inner_text("#tv-stats")
    assert "Freebox TV salon" in p.inner_text("#tv-clients") and "mon-tracker.example" in p.inner_text("#tv-custom")
    assert p.evaluate("window.__pwn === undefined") and p.evaluate("document.querySelectorAll('#tv-top img').length") == 0     # nom piégé : affiché en texte
    assert "suppression de publicités" in p.inner_text("#adblocktv")                                                        # formulation honnête présente
    assert not erreurs
    ctx.close()


def test_bascule_de_mode_et_ajout_de_domaine_appellent_l_api(navigateur):
    appels = []
    etat = {"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV", "mode": "observe"}]}
    ctx, p, _ = _page(navigateur, appels, etat)
    p.click("button[data-tab=adblocktv]")
    p.wait_for_selector("#tv-stats .stat-card")
    p.check("input[name=tv-mode][value=block]")
    p.fill("#tv-new-domaine", "pub.example.org")
    p.click("text=Ajouter >> nth=-1")
    p.uncheck("#tv-actif")
    p.wait_for_timeout(300)
    assert ("POST", "/adblock-tv/mode", {"mode": "block"}) in appels
    assert ("POST", "/adblock-tv/custom", {"domaine": "pub.example.org"}) in appels
    assert ("POST", "/adblock-tv/etat", {"actif": False}) in appels
    ctx.close()


def test_dns_path_test_depuis_l_interface(navigateur):
    appels = []
    ctx, p, _ = _page(navigateur, appels, {"actif": True, "clients": []})
    p.click("button[data-tab=adblocktv]")
    p.click("text=Nouvelle sonde")
    p.wait_for_function("document.getElementById('tv-sonde-nom').textContent.includes('sbx-dnspath.invalid')")
    p.click("text=La box l'a-t-elle reçue ?")
    p.wait_for_function("document.getElementById('tv-path').textContent.includes('✅')")
    assert "192.168.1.50" in p.inner_text("#tv-path")
    ctx.close()
