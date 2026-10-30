# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2487 — /fleet/ au profil Aurora : tuiles et matrice calculées sur les nœuds lus, périmés signalés, flotte illisible DITE (pas « aucun nœud »), valeurs en texte brut."""
import concurrent.futures
import json
import pathlib
import re

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "fleet" / "index.html"


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
                def route(r):
                    u = r.request.url
                    if u.endswith("/page"):
                        return r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8"))
                    if "/api/" in u:
                        return api(r)
                    return r.fulfill(status=200, content_type="text/css" if u.endswith(".css") else "application/javascript", body="")      # menu partagé : hors sujet
                pg.route("http://t.test/**", route)
                pg.goto("http://t.test/page")
            else:
                pg.goto("file://" + str(PAGE) + query)
            pg.wait_for_timeout(600)
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, natifs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1], res[2], res[3]


def test_demo_tuiles_matrice_et_perimes():
    def sc(pg):
        return ([pg.inner_text(i) for i in ("#tN", "#tOn", "#tOff", "#tMod", "#tSoc")], pg.locator("#fleet-body tr.node-row").count(), pg.locator("#fleet-body tr.is-stale").count(),
                pg.inner_text("#pastille"), pg.is_visible("#demo"), pg.inner_text("#fleet-body tr.is-stale td:last-child"),
                pg.evaluate("document.getElementById('fleet-body').textContent.includes('<img src=x onerror=alert(1)>')"), pg.locator("#fleet-body img, #fleet-body b").count())
    (t, n, stale, pastille, demo, vu, texte, balises), erreurs, natifs = _nav(sc)
    assert t == ["3", "2", "1", "2", "3"] and n == 3 and stale == 1 and pastille == "2 / 3 EN LIGNE" and demo and vu == "hors ligne"
    assert texte and balises == 0 and erreurs == [] and natifs == []
    # mesure absente (cpu/charge/uptime du nœud périmé) : tiret, pas zéro


def test_mesure_absente_est_un_tiret():
    def sc(pg):
        return pg.evaluate("[...document.querySelectorAll('#fleet-body tr.is-stale td')].map(td => td.textContent.trim())")
    cellules, erreurs, _ = _nav(sc)
    assert cellules[1] == "—" and cellules[4] == "—" and cellules[5] == "—" and erreurs == []


def test_clic_sur_un_noeud_affiche_son_detail_et_reclic_le_masque():
    def sc(pg):
        pg.click("#fleet-body tr.node-row >> nth=0"); pg.wait_for_selector("#detail:not([hidden])")
        d = pg.inner_text("#detKv"); sel = pg.locator("#fleet-body tr.sel").count()
        pg.click("#fleet-body tr.node-row >> nth=0")
        return d, sel, pg.is_hidden("#detail")
    (d, sel, cache), erreurs, _ = _nav(sc)
    assert "did:plc:" in d and "Bannissements" in d and sel == 1 and cache and erreurs == []


def test_flotte_illisible_est_dite_et_pas_aucun_noeud():
    def api(r):
        r.fulfill(status=500, body="{}")

    def sc(pg):
        return pg.inner_text("#fleet-body"), pg.inner_text("#pastille"), pg.inner_text("#tN")
    (corps, pastille, n), erreurs, _ = _nav(sc, api=api)
    assert "illisible" in corps and "pas « aucun nœud »" in corps and pastille == "FLOTTE ILLISIBLE" and n == "—" and erreurs == []


def test_erreur_signalee_par_l_api_n_est_pas_une_flotte_vide_et_session_requise_est_dite():
    def api(r):
        r.fulfill(status=200, content_type="application/json", body=json.dumps({"nodes": [], "erreur": True}))

    def sc(pg):
        return pg.inner_text("#pastille")
    p1, erreurs, _ = _nav(sc, api=api)
    assert p1 == "FLOTTE ILLISIBLE" and erreurs == []

    def api401(r):
        r.fulfill(status=401, body="{}")
    corps, erreurs, _ = _nav(lambda pg: pg.inner_text("#fleet-body"), api=api401)
    assert "session requise" in corps


def test_flotte_vide_reelle_est_dite_vide():
    def api(r):
        r.fulfill(status=200, content_type="application/json", body=json.dumps({"nodes": []}))
    (corps, pastille), erreurs, _ = _nav(lambda pg: (pg.inner_text("#fleet-body"), pg.inner_text("#pastille")), api=api)
    assert "Aucun nœud" in corps and pastille == "AUCUN NŒUD" and erreurs == []


def test_aucune_boite_native_et_pas_d_innerhtml():
    src = PAGE.read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", src, flags=re.S)).replace("onerror=alert(1)", "")
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])" + f + r"\(", code), f
    assert "innerHTML" not in code
    # lecture seule hors page de la box (#3126 L2 tâche 8) : seul le bloc pilotage-box écrit, et seulement vers /api/v1/pilotage
    hors = re.sub(r"// ===== pilotage-box =====.*?// ===== fin pilotage-box =====", "", src, flags=re.S)
    assert not re.search(r"POST|DELETE|PUT|PATCH", hors)
    bloc = re.search(r"// ===== pilotage-box =====(.*?)// ===== fin pilotage-box =====", src, re.S)
    assert bloc and "/api/v1/pilotage/" in bloc.group(1) and "/api/v1/annuaire" not in bloc.group(1)


def test_get_fleet_signale_l_echec_au_lieu_de_rendre_une_flotte_vide(monkeypatch):
    """Appel direct de la route (sans passer par le jeton) : une lecture en échec rend erreur: true, jamais un 500 ni une flotte vide silencieuse."""
    import asyncio
    from api import main as apimain

    def explose():
        raise RuntimeError("store corrompu")
    monkeypatch.setattr(apimain.fleet_store, "read", explose)
    assert asyncio.run(apimain.get_fleet()) == {"nodes": [], "erreur": True}
    monkeypatch.setattr(apimain.fleet_store, "read", lambda: None)
    monkeypatch.setattr(apimain.mesh_sync, "read_mesh_peers", lambda: [])
    assert asyncio.run(apimain.get_fleet()) == {"nodes": []}                       # vraie flotte vide : sans erreur
