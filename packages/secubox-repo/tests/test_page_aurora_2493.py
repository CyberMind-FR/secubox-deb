# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2493 — /repo/ au profil Aurora : suites et paquets réels, « — » sans mesure, maintenance confirmée dans la page, valeurs en texte brut, aucune boîte native."""
import concurrent.futures
import json
import pathlib
import re

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "repo" / "index.html"


def _nav(scenario, query="?demo=1", api=None):
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e), [], [], [])
            pg = nav.new_page()
            erreurs, natifs, posts = [], [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
            if api is not None:
                def route(r):
                    u = r.request.url
                    if u.endswith("/page"):
                        return r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8"))
                    if "/api/" in u:
                        if r.request.method == "POST":
                            posts.append(u.split("/api/v1/repo")[-1])
                        return api(r)
                    return r.fulfill(status=200, content_type="text/css" if u.endswith(".css") else "application/javascript", body="")
                pg.route("http://t.test/**", route)
                pg.goto("http://t.test/page")
            else:
                pg.goto("file://" + str(PAGE) + query)
            pg.wait_for_timeout(600)
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, natifs, posts)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1], res[2], res[3], res[4]


def test_aucune_boite_native():
    src = PAGE.read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", src, flags=re.S)).replace("onerror=alert(1)", "")
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])" + f + r"\(", code), f


def test_demo_tuiles_suites_recents_et_journal():
    def sc(pg):
        return ([pg.inner_text(i) for i in ("#tSuites", "#tPaq", "#tDeb", "#tPool")], pg.locator("#suites tr").count(), pg.inner_text("#suites tr:nth-child(2)"), pg.inner_text("#suites tr:nth-child(4)"),
                pg.locator("#recents .rec").count(), pg.locator("#histo .rec").count(), pg.inner_text("#pastille"),
                pg.evaluate("document.getElementById('suites').textContent.includes('<img src=x onerror=alert(1)>')"), pg.locator("#suites img, #recents b > b").count())
    (t, nsuites, trixie, hostile, nrec, nh, pastille, texte, balises), erreurs, natifs, _ = _nav(sc)
    assert t[0] == "3" and t[1] == "188" and t[2] == "465" and "Mo" in t[3]
    assert nsuites == 4 and "arm64 : 173 · amd64 : 173" in trixie and "—" in hostile and nrec == 2 and nh == 2 and pastille == "3 SUITES PUBLIÉES"
    assert texte and balises == 0 and erreurs == [] and natifs == []


def test_maintenance_demande_une_confirmation_grave_et_annuler_ne_poste_rien():
    def api(r):
        r.fulfill(status=200, content_type="application/json", body=json.dumps({"disponible": False}))

    def sc(pg):
        pg.click("#btnGpg"); pg.wait_for_selector("#dialogue:not([hidden])")
        m = pg.inner_text("#dialogue"); grave = pg.evaluate("document.getElementById('dialogue').classList.contains('grave')")
        pg.click("#dialogue .btn:not(.danger)"); pg.wait_for_selector("#dialogue[hidden]", state="attached")
        return m, grave, pg.inner_text("#retour")
    (m, grave, retour), erreurs, natifs, posts = _nav(sc, api=api)
    assert "clé de signature" in m and "ne vérifieront plus ses paquets" in m and grave and retour == ""
    assert posts == [] and erreurs == [] and natifs == []


def test_confirmer_poste_la_maintenance_et_dit_le_refus_du_serveur():
    def api(r):
        if r.request.method == "POST":
            return r.fulfill(status=500, content_type="application/json", body=json.dumps({"detail": "repoctl a échoué"}))
        r.fulfill(status=200, content_type="application/json", body=json.dumps({"disponible": False}))

    def sc(pg):
        pg.click("#btnInit"); pg.wait_for_selector("#dialogue:not([hidden])"); pg.click("#dialogue .btn.danger")
        pg.wait_for_function("document.getElementById('retour').textContent.includes('❌')")
        return pg.inner_text("#retour")
    retour, erreurs, natifs, posts = _nav(sc, api=api)
    assert posts == ["/init"] and "repoctl a échoué" in retour and erreurs == [] and natifs == []


def test_depot_illisible_donne_des_tirets_et_le_dit_pas_zero_paquet():
    def api(r):
        r.fulfill(status=200, content_type="application/json", body=json.dumps({"disponible": False, "suites": []}))

    def sc(pg):
        return [pg.inner_text(i) for i in ("#tSuites", "#tPaq", "#tDeb", "#tPool")], pg.inner_text("#pastille"), pg.inner_text("#suites")
    (t, pastille, suites), erreurs, _, _ = _nav(sc, api=api)
    assert t == ["—"] * 4 and pastille == "DÉPÔT ILLISIBLE" and "illisible" in suites and erreurs == []


def test_session_requise_est_dite():
    def api(r):
        r.fulfill(status=401, body="{}")
    (pastille, suites), erreurs, _, _ = _nav(lambda pg: (pg.inner_text("#pastille"), pg.inner_text("#suites")), api=api)
    assert pastille == "SESSION REQUISE" and "Session requise" in suites and erreurs == []
