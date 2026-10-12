# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2467 — page /cdn/ au profil Aurora : mesures réelles, illisible = tiret, valeurs en texte brut, aucune écriture."""
import concurrent.futures
import json
import pathlib
import re

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "cdn" / "index.html"


def _nav(scenario, query="?demo=1", api=None):
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
            if api is not None:
                pg.route("http://t.test/**", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")) if r.request.url.endswith("/page") else api(r))
                pg.goto("http://t.test/page")
            else:
                pg.goto("file://" + str(PAGE) + query)
            pg.wait_for_timeout(500)
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, natifs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1], res[2], res[3]


def test_aucune_boite_native_ni_ecriture():
    src = PAGE.read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", src, flags=re.S)).replace("onerror=alert(1)", "")
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])" + f + r"\(", code), f
    assert "POST" not in src and "DELETE" not in src                              # supervision seule


def test_demo_tuiles_liste_et_fermes_en_tiret():
    def sc(pg):
        return (pg.inner_text("#sNb"), pg.inner_text("#sGros"), pg.inner_text("#sFerm"), pg.locator("#liste .hl").count(),
                pg.evaluate("[...document.querySelectorAll('#liste .hl')].filter(l => l.textContent.includes('fonts')).map(l => l.querySelectorAll('b')[0].textContent)"),
                pg.evaluate("document.getElementById('liste').textContent.includes('<img src=x onerror=alert(1)>')"), pg.locator("#liste img").count(),
                pg.inner_text("#sPolS"), pg.is_visible("#polPan"))
    (nb, gros, ferm, n, fonts, texte, imgs, pols, pan), erreurs, natifs = _nav(sc)
    assert nb == "6" and gros == "metablogizer" and ferm == "2" and n == 6 and fonts == ["—"] and texte and imgs == 0
    assert "non appliquées" in pols and pan and erreurs == [] and natifs == []


def test_source_illisible_donne_des_tirets():
    def api(r):
        r.fulfill(status=500, body="{}")

    def sc(pg):
        return [pg.inner_text(i) for i in ("#sNb", "#sTot", "#sGros", "#sFerm", "#sPol")], pg.inner_text("#pastille")
    (vals, pastille), erreurs, _ = _nav(sc, api=api)
    assert vals == ["—"] * 5 and pastille == "ILLISIBLE" and erreurs == []


def test_session_requise_est_dite():
    def api(r):
        r.fulfill(status=401, body="{}")

    def sc(pg):
        return pg.inner_text("#pastille"), pg.inner_text("#liste")
    (pastille, liste), erreurs, _ = _nav(sc, api=api)
    assert pastille == "SESSION REQUISE" and "Session requise" in liste and erreurs == []
