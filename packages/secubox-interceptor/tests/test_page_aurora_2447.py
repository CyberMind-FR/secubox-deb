# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2447 — page /interceptor/ au profil Aurora : données réelles seulement, aucune action, aucune boîte native, valeurs échappées."""
import concurrent.futures
import pathlib
import re

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "interceptor" / "index.html"


def _navigateur(scenario, query="?demo=1"):
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e), [], [])
            pg = nav.new_page()
            erreurs, natifs = [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
            pg.goto("file://" + str(PAGE) + query)
            pg.wait_for_selector(".mot")
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, natifs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1], res[2], res[3]


def test_page_en_lecture_seule_sans_boite_native():
    src = PAGE.read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", src, flags=re.S))
    code = code.replace("onerror=alert(1)", "")                              # charge de test de la démonstration, affichée comme texte
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])" + f + r"\(", code), f
    assert "method: 'POST'" not in src and "method:'POST'" not in src       # aucune action : supervision seule


def test_demo_tuiles_moteurs_et_serie():
    def scenario(pg):
        return (pg.inner_text("#sMot"), pg.locator(".mot").count(), pg.locator(".mot.ko").count(), pg.locator("#serie rect").count() > 0, pg.is_visible("#demo"), pg.inner_text("#pastille"))
    (mot, n, ko, barres, demo, pastille), erreurs, natifs = _navigateur(scenario)
    assert mot == "4 / 5" and n == 5 and ko == 1 and barres and demo and pastille == "INSPECTION PARTIELLE" and erreurs == [] and natifs == []


def test_hote_hostile_affiche_comme_texte():
    def scenario(pg):
        return pg.evaluate("document.querySelectorAll('#hotes img').length"), pg.evaluate("document.getElementById('hotes').textContent.includes('<img src=x onerror=alert(1)>')")
    (imgs, texte), erreurs, natifs = _navigateur(scenario)
    assert imgs == 0 and texte and erreurs == [] and natifs == []


def test_fenetre_de_temps_change_la_serie():
    def scenario(pg):
        a = pg.evaluate("document.querySelector('#serie svg').textContent")
        pg.click("#win .btn[data-m='15']")
        pg.wait_for_function("document.getElementById('fenetre').textContent.includes('15')")
        return "−60 min" in a, pg.evaluate("document.querySelector('#serie svg').textContent.includes('−15 min')")
    (avant, apres), erreurs, _ = _navigateur(scenario)
    assert avant and apres and erreurs == []


def test_source_illisible_donne_des_tirets_pas_des_zeros():
    """Sans démonstration ni API (fichier local) : tout est « — », rien d'inventé."""
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return None
            pg = nav.new_page(); pg.route("**/api/**", lambda r: r.fulfill(status=500, body="{}"))
            pg.goto("file://" + str(PAGE)); pg.wait_for_timeout(600)
            r = [pg.inner_text(i) for i in ("#sMot", "#sHello", "#sHotes", "#sJa4", "#sPairs")]
            nav.close(); return r
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        r = ex.submit(tache).result(timeout=60)
    if r is None:
        pytest.skip("chromium indisponible")
    assert r == ["—"] * 5
