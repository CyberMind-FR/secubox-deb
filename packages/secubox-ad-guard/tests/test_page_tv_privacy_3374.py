# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3374 — page SBX TV Privacy : trois vues, routes existantes seulement, données par textContent, confirmations intégrées."""
import concurrent.futures
import json
import pathlib
import re

import pytest

RACINE = pathlib.Path(__file__).resolve().parents[1]
PAGE = RACINE / "www" / "tv-privacy" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
CODE = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", SRC, flags=re.S))


def test_en_tete_spdx_et_titre():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC[:400]
    assert "<title>SBX TV Privacy</title>" in SRC


def test_trois_vues_en_onglets_accessibles():
    for v in ("generale", "equipements", "analyseur"):
        assert f'id="v-{v}" role="tabpanel"' in SRC and f'id="t-{v}" aria-controls="v-{v}"' in SRC
    assert SRC.count('role="tab"') == 3 and "aria-selected" in SRC and 'role="tablist"' in SRC


def test_routes_appelees_existantes_seulement():
    from api import dnstv_routes as r
    existantes = {x.path.replace("/adblock-tv", "", 1) for x in r.router.routes}
    citees = {c for c in re.findall(r"(?:lire|ecrire)\('(/[a-z/-]+)", CODE) if not c.endswith("/")} | {"/appareils/{mac}/profil"}
    assert {"/appareils", "/classification", "/classification/detail", "/live"} <= citees
    assert "'/appareils/'+encodeURIComponent(a.mac)+'/profil'" in CODE
    assert citees <= existantes, citees - existantes
    assert "BASE='/api/v1/ad-guard/adblock-tv'" in CODE


def test_ecritures_a_l_identique_et_confirmees():
    assert CODE.count("method:'POST'") == 1                           # une seule fonction d'écriture
    assert "ecrire('/classification',{domaine:d.domaine,categorie:" in CODE
    assert "{type:sel.value||null}" in CODE
    assert CODE.count("'Confirmer'") == 2 and "Corriger le profil" in CODE
    assert not re.search(r"\b(confirm|alert|prompt)\(", CODE)
    assert "if(DEMO)return Promise.reject" in CODE                   # aucune écriture en démonstration


def test_aucun_innerhtml_ni_ressource_externe():
    assert "innerHTML" not in CODE and "outerHTML" not in CODE and "insertAdjacentHTML" not in CODE and "document.write" not in CODE
    assert "<script src" not in SRC and "http://" not in CODE and "https://" not in CODE
    assert "textContent" in CODE


def test_jeton_sbx_token_et_hauteur_postee():
    assert "localStorage.getItem('sbx_token')" in CODE and "Authorization='Bearer '" in CODE and "credentials:'same-origin'" in CODE
    assert "sbxVue" in CODE and "onglet:'tv-privacy'" in CODE and "min-height:100vh" not in SRC
    assert "@container a" in SRC


def test_menu_et_installation():
    m = json.loads((RACINE / "menu.d" / "161-tv-privacy.json").read_text(encoding="utf-8"))
    assert m["name"] == "SBX TV Privacy" and m["path"] == "/tv-privacy/" and m["category"] == "wall"
    regles = (RACINE / "debian" / "rules").read_text(encoding="utf-8")
    assert "cp -r www/tv-privacy/. debian/secubox-ad-guard/usr/share/secubox/www/tv-privacy/" in regles


sync_api = pytest.importorskip("playwright.sync_api")
HOSTILE = "<img src=x onerror=window.xss=1>"


def _page(scenario, statut=200):
    appareils = {"appareils": [{"mac": "02:00:5e:00:00:01", "nom": HOSTILE, "ips": ["2001:db8::1", "192.0.2.1"], "mode": "auto",
                                "modes_divergents": True, "profil": "LG_WEBOS", "profil_source": "nac", "profil_confiance": 90}],
                 "profils": ["LG_WEBOS", "INCONNU"]}
    classif = {"domaines": [{"domaine": "ads.example.com", "mac": "02:00:5e:00:00:01", "categorie": "PUBLICITE", "source": "liste",
                             "confiance": 90, "requetes": 12, "derniere_observation": 1761955000, "protegee": False},
                            {"domaine": "video.example.org", "mac": "02:00:5e:00:00:01", "categorie": "STREAMING", "source": "liste",
                             "confiance": 95, "requetes": 30, "derniere_observation": 1761955000, "protegee": True}],
               "total": 2, "cache": True, "genere": 1761955200, "categories": ["PUBLICITE", "STREAMING"], "protegees": ["STREAMING"]}
    live = {"evenements": [{"ts": 1761955100, "client": "192.0.2.1", "domaine": HOSTILE, "decision": "BLOCKED"}]}

    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e))
            pg = nav.new_page()
            erreurs, posts = [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))

            def api(route):
                u = route.request.url
                if route.request.method == "POST":
                    posts.append((u, route.request.post_data))
                    return route.fulfill(status=200, content_type="application/json", body="{}")
                corps = appareils if "/appareils" in u else live if "/live" in u else classif
                route.fulfill(status=statut, content_type="application/json", body=json.dumps(corps if statut == 200 else {"detail": "x"}))
            pg.route("http://t.test/api/**", api)
            pg.route("http://t.test/tv-privacy/**", lambda r: r.fulfill(status=200, content_type="text/html", body=SRC))
            pg.goto("http://t.test/tv-privacy/")
            pg.wait_for_timeout(600)
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, posts)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1:]


def test_donnees_affichees_comme_texte_et_correction_confirmee():
    def sc(pg):
        t1 = pg.inner_text("body")
        pg.click("#t-equipements")
        t2 = pg.inner_text("#v-equipements")
        pg.click("text=Corriger le profil")
        pg.select_option("#v-equipements select", "INCONNU")
        pg.click("#v-equipements >> text=Confirmer")
        pg.wait_for_timeout(300)
        pg.click("#t-analyseur")
        t3 = pg.inner_text("#v-analyseur")
        return t1, t2, t3, pg.evaluate("window.xss")
    (t1, t2, t3, xss), erreurs, posts = _page(sc)
    assert xss is None and HOSTILE in t1 and HOSTILE in t2 and not erreurs
    assert "modes divergents" in t2 and "192.0.2.1" in t2 and "IPv6" in t2
    assert "protégé" in t3 and "ads.example.com" in t3
    assert posts and posts[0][0].endswith("/adblock-tv/appareils/02%3A00%3A5e%3A00%3A00%3A01/profil") and json.loads(posts[0][1]) == {"type": "INCONNU"}


def test_sans_session_la_page_le_dit():
    (texte, *_), erreurs, posts = _page(lambda pg: (pg.inner_text("body"),), statut=403)
    assert "session requise" in texte and not erreurs and not posts
