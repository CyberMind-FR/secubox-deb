# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2436 — page /ad-guard/ au profil Aurora : dialogues intégrés, données échappées, filtre par famille, aucune boîte native."""
import concurrent.futures
import pathlib
import re

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "ad-guard" / "index.html"


def _navigateur(scenario, query="?demo=1"):
    """Exécute `scenario(page)` dans un thread propre (Playwright refuse de tourner sous une boucle asyncio)."""
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e), [])
            pg = nav.new_page()
            erreurs, natifs = [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
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


def test_aucune_boite_native_dans_le_code():
    src = PAGE.read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", src, flags=re.S))
    code = code.replace("onerror=alert(1)", "")                              # charge de test de la démonstration (affichée comme texte)
    assert not re.search(r"(?<![A-Za-z.])confirm\(", code) and not re.search(r"(?<![A-Za-z.])alert\(", code) and not re.search(r"(?<![A-Za-z.])prompt\(", code)


def test_donnees_de_l_api_affichees_comme_texte_jamais_executees():
    def scenario(pg):
        return (pg.evaluate("document.querySelectorAll('#top-domains-table img').length"),
                pg.evaluate("document.getElementById('top-domains-table').textContent.includes('<img src=x onerror=alert(1)>')"),
                pg.evaluate("window.__pwned === undefined"))
    (images, texte, intact), erreurs, natifs = _navigateur(scenario)
    assert images == 0 and texte and intact and erreurs == [] and natifs == []      # ni balise injectée, ni boîte native


def test_filtre_par_famille_en_liste():
    def scenario(pg):
        pg.evaluate("document.getElementById('avance').open = true")            # la partie « Avancé » est repliée par défaut
        toutes = pg.evaluate("document.querySelectorAll('#top-domains-table tr').length")
        pg.click("#filtre-familles .puce:has-text('Publicité')")
        une = pg.evaluate("[...document.querySelectorAll('#top-domains-table tr')].map(r => r.cells[0].textContent)")
        actif = pg.evaluate("document.querySelector('#filtre-familles .puce.on').textContent")
        pg.click("#filtre-familles .puce:has-text('Toutes')")
        retour = pg.evaluate("document.querySelectorAll('#top-domains-table tr').length")
        return toutes, une, actif, retour
    (toutes, une, actif, retour), erreurs, _ = _navigateur(scenario)
    assert toutes == 6 and une == ["pub.exemple.test"] and actif.startswith("Publicité") and retour == 6 and erreurs == []


def test_debloquer_demande_une_confirmation_integree_et_annuler_ne_change_rien():
    def scenario(pg):
        pg.evaluate("document.getElementById('avance').open = true")
        pg.click("#top-domains-table [data-debloquer='pub.exemple.test']")
        pg.wait_for_selector("#dialogue:not([hidden])")
        msg = pg.inner_text("#dialogue")
        pg.click("#dialogue .btn:not(.btn-danger)")                           # Annuler
        pg.wait_for_selector("#dialogue[hidden]", state="attached")
        return msg, pg.evaluate("document.querySelectorAll('#top-domains-table tr').length")
    (msg, lignes), erreurs, natifs = _navigateur(scenario)
    assert "Débloquer pub.exemple.test" in msg and "Confirmer" in msg and lignes == 6 and erreurs == [] and natifs == []


def test_differer_un_blocage_demande_le_motif_dans_la_page():
    def scenario(pg):
        pg.evaluate("document.getElementById('avance').open = true")
        pg.click(".tab[data-tab='blocklist']")
        pg.fill("#block-domain-input", "regie.exemple.test")
        pg.click("text=Différer de 24 h")
        pg.wait_for_selector("#dialogue:not([hidden]) input")
        question = pg.inner_text("#dialogue")
        pg.fill("#dialogue input", "vu sur la TV")
        pg.click("#dialogue .btn-primary")                                    # Valider
        pg.wait_for_selector("#dialogue[hidden]", state="attached")
        return question
    question, erreurs, natifs = _navigateur(scenario)
    assert "Motif du blocage différé" in question and "regie.exemple.test" in question and erreurs == [] and natifs == []


def test_demonstration_annoncee_et_hauteur_mesuree_sur_le_cadre():
    src = PAGE.read_text(encoding="utf-8")
    assert "sbxVue" in src and "min-height:100vh" not in src and "scrollHeight" not in src
    (visible, titre), erreurs, _ = _navigateur(lambda pg: (pg.evaluate("!document.getElementById('demo').hidden"), pg.evaluate("document.getElementById('sp-titre').textContent")))
    assert visible and "Protection active" in titre and erreurs == []
