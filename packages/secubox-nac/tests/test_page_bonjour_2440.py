# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2440 — la page NAC affiche le nom annoncé et les services Bonjour ; l'API rend des listes sûres."""
import concurrent.futures
import pathlib

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "nac" / "index.html"


def _navigateur(scenario):
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e), [])
            pg = nav.new_page()
            erreurs = []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.goto("file://" + str(PAGE) + "?demo=1")
            pg.wait_for_selector(".app-c")
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1], res[2]


def test_pastilles_de_services_et_nom_annonce():
    def scenario(pg):
        return pg.evaluate("[...document.querySelectorAll('.app-c')].filter(c => c.textContent.includes('Impression')).map(c => [...c.querySelectorAll('.svc')].map(x => x.textContent))"), \
               pg.evaluate("[...document.querySelectorAll('.app-c b')].map(b => b.textContent).includes('TV du salon')")
    (cartes, nom), erreurs = _navigateur(scenario)
    assert cartes == [["Impression", "Numériseur", "Web"]] and nom and erreurs == []


def test_la_recherche_trouve_par_service():
    def scenario(pg):
        pg.fill("#fq", "chromecast")
        pg.wait_for_timeout(200)
        return pg.locator(".app-c").count()
    n, erreurs = _navigateur(scenario)
    assert n == 1 and erreurs == []


def test_services_illisibles_donnent_une_liste_vide():
    from api.main import _services_json
    assert _services_json('["AirPlay"]') == ["AirPlay"] and _services_json("pas du json") == [] and _services_json(None) == [] and _services_json('{"a":1}') == []
