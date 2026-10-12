# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2438 — page /wireguard/ au profil Aurora : confirmations intégrées, données échappées, aucune boîte native."""
import concurrent.futures
import pathlib
import re

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "wireguard" / "index.html"


def _navigateur(scenario, query="?demo=1"):
    """Exécute `scenario(page)` dans un thread propre (Playwright refuse de tourner sous une boucle asyncio)."""
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
            pg.wait_for_selector("#ifaceList .iface")
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, natifs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1], res[2], res[3]


def test_aucune_boite_native_dans_le_code():
    src = PAGE.read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", src, flags=re.S))
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])%s\(" % f, code), f


def test_demo_affiche_tuiles_et_tunnels():
    def scenario(pg):
        return (pg.inner_text("#sIfaces"), pg.inner_text("#sPeers"), pg.locator("#ifaceList .iface").count(),
                pg.is_visible("#demo"), pg.inner_text("#pastille"))
    (n, pairs, ifs, demo, pastille), erreurs, natifs = _navigateur(scenario)
    assert (n, pairs, ifs, demo) == ("3", "118", 3, True) and "2 / 3" in pastille and erreurs == [] and natifs == []


def test_gros_tunnel_ne_liste_que_les_connectes_puis_tout_afficher():
    def scenario(pg):
        pg.click("#if-wg-toolbox .iface-head")
        pg.wait_for_selector("#peers-wg-toolbox .peer")
        connectes = pg.locator("#peers-wg-toolbox .peer").count()       # 112 pairs : seuls les connectés sont listés
        pg.click("#peers-wg-toolbox [data-act='force']")
        pg.wait_for_function("document.querySelectorAll('#peers-wg-toolbox .peer').length === 3")
        return connectes, pg.inner_text("#peers-wg-toolbox")
    (n, texte), erreurs, natifs = _navigateur(scenario)
    assert n == 2 and "10.99.1.5/32" in texte and erreurs == [] and natifs == []


def test_descendre_un_tunnel_critique_demande_une_confirmation_integree_grave():
    def scenario(pg):
        pg.click("#if-wg-admin .iface-head")
        pg.click("#if-wg-admin [data-act='down']")
        pg.wait_for_selector("#dialogue:not([hidden])")
        grave = pg.evaluate("document.getElementById('dialogue').classList.contains('grave')")
        msg = pg.inner_text("#dialogue")
        pg.click("#dialogue .btn:not(.danger)")                               # Annuler
        pg.wait_for_selector("#dialogue[hidden]", state="attached")
        return grave, msg, pg.evaluate("document.getElementById('toast').classList.contains('show')")
    (grave, msg, toast), erreurs, natifs = _navigateur(scenario)
    assert grave and "COUPE votre accès" in msg and not toast and erreurs == [] and natifs == []


def test_monter_un_tunnel_ordinaire_confirme_puis_action_inerte_en_demo():
    def scenario(pg):
        pg.click("#if-wg-mesh .iface-head")
        pg.click("#if-wg-mesh [data-act='up']")
        pg.wait_for_selector("#dialogue:not([hidden])")
        grave = pg.evaluate("document.getElementById('dialogue').classList.contains('grave')")
        pg.click("#dialogue .btn.danger")                                      # Confirmer
        pg.wait_for_selector("#toast.show.error")
        return grave, pg.inner_text("#toast")
    (grave, toast), erreurs, natifs = _navigateur(scenario)
    assert not grave and "inerte" in toast and erreurs == [] and natifs == []


def test_nom_de_pair_invalide_refuse_sans_appel():
    def scenario(pg):
        pg.click("#if-wg-admin .iface-head")
        pg.click("#if-wg-admin [data-act='addpeer']")
        pg.fill("#peerName", "<img src=x onerror=alert(1)>")
        pg.click("#peerGenBtn")
        pg.wait_for_selector("#toast.show.error")
        return pg.inner_text("#toast"), pg.locator("#modalContent img").count()
    (toast, imgs), erreurs, natifs = _navigateur(scenario)
    assert "lettres" in toast and imgs == 0 and erreurs == [] and natifs == []
