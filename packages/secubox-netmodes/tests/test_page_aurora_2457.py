# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2457 — page /netmodes/ au profil Aurora : mode jamais inventé, confirmation intégrée, aucune boîte native, valeurs échappées."""
import concurrent.futures
import pathlib
import re

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "netmodes" / "index.html"


def _navigateur(scenario, query="?demo=1#modes", route=None):   # #3190 : l'ancienne page est l'onglet « Modes (hérité) »
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
            if route:      # fetch() refuse file:// : la page est servie par une origine http fictive, l'API simulée par `route`
                pg.route("http://t.test/**", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")) if r.request.url.endswith("/page") else route(r))
                pg.goto("http://t.test/page#modes")
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


def test_aucune_boite_native_ni_fausse_sauvegarde():
    src = PAGE.read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", src, flags=re.S)).replace("onerror=alert(1)", "")
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])" + f + r"\(", code), f
    assert "/interfaces'" not in src and "/current_mode'" not in src          # routes qui n'existent pas : c'était la cause de « No interfaces »


def test_demo_modes_interfaces_et_wan():
    def scenario(pg):
        return (pg.locator(".mode").count(), pg.inner_text("#sMode"), pg.inner_text("#sWan"), pg.inner_text("#sIf"), pg.is_visible("#inconnu"),
                pg.evaluate("document.getElementById('interfaces').textContent.includes('<img src=x onerror=alert(1)>')"), pg.locator("#interfaces img").count())
    (n, mode, wan, ifs, inconnu, texte, imgs), erreurs, natifs = _navigateur(scenario)
    assert n == 5 and mode == "Routeur" and wan == "eth2" and ifs == "2 / 3" and not inconnu and texte and imgs == 0 and erreurs == [] and natifs == []


def test_appliquer_demande_une_confirmation_grave_integree_et_annuler_ne_fait_rien():
    def scenario(pg):
        pg.click(".mode:nth-child(2) .btn.danger")
        pg.wait_for_selector("#dialogue:not([hidden])")
        grave = pg.evaluate("document.getElementById('dialogue').classList.contains('grave')")
        m = pg.inner_text("#dialogue")
        pg.click("#dialogue .btn:not(.danger)")
        pg.wait_for_selector("#dialogue[hidden]", state="attached")
        return grave, m, pg.inner_text("#resultat")
    (grave, m, res), erreurs, natifs = _navigateur(scenario)
    assert grave and "netplan apply" in m and "Sniffer Inline" in m and res == "" and erreurs == [] and natifs == []


def test_confirmer_en_demo_reste_inerte():
    def scenario(pg):
        pg.click(".mode:nth-child(1) .btn.danger"); pg.wait_for_selector("#dialogue:not([hidden])"); pg.click("#dialogue .btn.danger")
        pg.wait_for_function("document.getElementById('resultat').textContent.includes('inerte')")
        return pg.inner_text("#resultat")
    r, erreurs, natifs = _navigateur(scenario)
    assert "inerte" in r and erreurs == [] and natifs == []


def test_detection_absente_expliquee_sans_alarme_et_apercu_en_texte_brut():
    def scenario(pg):
        det = pg.inner_text("#sDet"); note = pg.inner_text("#detection")
        pg.click(".mode:nth-child(1) .btn:not(.danger)"); pg.wait_for_selector("#aperc:not([hidden])")
        return det, note, pg.inner_text("#yaml")
    (det, note, yaml), erreurs, _ = _navigateur(scenario)
    assert det == "indisponible" and "secubox-net-detect" in note and "version: 2" in yaml and erreurs == []


def test_mode_non_enregistre_affiche_inconnu_pas_routeur():
    """API réelle simulée : pas de mode enregistré -> « Inconnu » et le bandeau d'explication."""
    import json

    def route(r):
        u = r.request.url
        if u.endswith("/get_available_modes"):
            r.fulfill(status=200, content_type="application/json", body=json.dumps([{"id": "router", "name": "Routeur", "desc": "d"}]))
        elif u.endswith("/status"):
            r.fulfill(status=200, content_type="application/json", body=json.dumps({"mode_connu": False, "current_mode": None, "last_change": None, "wan": {"interface": None, "passerelle": None}, "interfaces": []}))
        else:
            r.fulfill(status=500, body="{}")

    def scenario(pg):
        return pg.inner_text("#sMode"), pg.is_visible("#inconnu"), pg.inner_text("#sWan"), pg.locator(".mode.cur").count(), pg.inner_text("#sLast")
    (mode, bandeau, wan, cur, last), erreurs, _ = _navigateur(scenario, route=route)
    assert mode == "Inconnu" and bandeau and wan == "aucune" and cur == 0 and last == "—" and erreurs == []
