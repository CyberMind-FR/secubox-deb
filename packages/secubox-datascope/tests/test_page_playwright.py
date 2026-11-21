# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3853 — page Network Cockpit dans un vrai navigateur (sauté sans Playwright ni Chromium).

Captures facultatives : SECUBOX_DATASCOPE_CAPTURES=<dossier> écrit cockpit-1400.png et cockpit-420.png (?demo=1).
"""
import concurrent.futures
import os
import pathlib

import pytest

pytestmark = pytest.mark.playwright
sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "datascope" / "index.html"
CAPTURES = os.environ.get("SECUBOX_DATASCOPE_CAPTURES")


def _navigateur(scenario, query="?demo=1", largeur=1400, hauteur=900):
    """Exécute `scenario(page)` dans un thread propre (Playwright refuse de tourner sous une boucle asyncio)."""
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:  # navigateur absent
                return ("skip", str(e), [], [])
            pg = nav.new_page(viewport={"width": largeur, "height": hauteur})
            erreurs, natifs = [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
            pg.goto("file://" + str(PAGE) + query)
            pg.wait_for_timeout(400)
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, natifs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=90)
    if res[0] == "skip":
        pytest.skip("Chromium indisponible : " + res[1])
    assert res[2] == [], res[2]
    assert res[3] == [], res[3]
    return res[1]


def _debordement(pg):
    return pg.evaluate("document.documentElement.scrollWidth > window.innerWidth")


def test_demo_large_topologie_et_inspecteur():
    def sc(pg):
        r = {"bandeau": pg.is_visible("#demo"), "session": pg.is_visible("#session"),
             "noeuds": pg.locator("#topo svg.bulles .nd circle.b").count(),
             "plus": pg.eval_on_selector_all("#topo .plus", "l => l.map(n => n.getAttribute('data-n'))"),
             "liens": pg.locator("#topo svg.bulles .ar").count(),
             "deborde": _debordement(pg)}
        pg.click("#topo .nd[data-id='device:00:00:5e:00:53:01'] circle.prise")
        pg.wait_for_timeout(100)
        r["insp"] = pg.inner_text("#insp")
        # au clavier : les arêtes issues de la box partent du même point, leurs zones de clic se chevauchent à l'origine
        pg.focus("#topo .ar[data-cle='interface:eth2|BELONGS_TO|node:secubox-demo']")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(100)
        r["preuve"] = pg.inner_text("#insp")
        pg.click("#topo .nd[data-id='service:waf'] circle.prise")
        pg.wait_for_timeout(100)
        r["service"] = pg.inner_text("#insp")
        if CAPTURES:
            pg.click("#topo .nd[data-id='device:00:00:5e:00:53:01'] circle.prise")
            pg.wait_for_timeout(100)
            pg.screenshot(path=os.path.join(CAPTURES, "cockpit-1400.png"))
            pg.click("#vueArbre")
            pg.wait_for_timeout(100)
            pg.screenshot(path=os.path.join(CAPTURES, "cockpit-1400-arbre.png"))
        return r
    r = _navigateur(sc)
    assert r["bandeau"] and not r["session"]
    assert r["noeuds"] > 60 and not r["deborde"]
    assert r["plus"] == ["3"], r["plus"]  # wlan0 : 63 appareils, 60 dessinés et une bulle « +3 »
    assert r["liens"] >= 70  # toutes les relations entre bulles dessinées (hors IP)
    assert "poste-atelier" in r["insp"] and "observée" in r["insp"] and "inventaire du NAC" in r["insp"]
    assert "Ouvrir dans le NAC" in r["insp"]
    assert "inventaire du NAC" in r["preuve"] and "observée" in r["preuve"]
    assert "inconnu" in r["service"]  # source status inaccessible : jamais l'état stocké présenté comme courant
    assert "healthy" not in r["service"]


def test_demo_etroit_tiroirs_sans_debordement():
    def sc(pg):
        r = {"deborde": _debordement(pg), "insp_avant": pg.is_visible("#panInsp")}
        if CAPTURES:
            pg.screenshot(path=os.path.join(CAPTURES, "cockpit-420-bulles.png"), full_page=True)
        pg.click("#topo .nd[data-id='device:00:00:5e:00:53:04'] circle.prise")
        pg.wait_for_timeout(100)
        r["insp_apres"] = pg.is_visible("#panInsp")
        r["libelle_voisin"] = pg.is_visible("#topo .nd.voisin[data-id='interface:br-lan'] .lbl")
        r["deborde2"] = _debordement(pg)
        if CAPTURES:
            pg.screenshot(path=os.path.join(CAPTURES, "cockpit-420.png"), full_page=True)
        return r
    r = _navigateur(sc, largeur=420, hauteur=900)
    assert not r["deborde"] and not r["deborde2"]
    assert not r["insp_avant"] and r["insp_apres"]  # l'inspecteur est un tiroir ouvert par la sélection
    assert r["libelle_voisin"]


def test_embed_large_reste_en_tiroirs():
    r = _navigateur(lambda pg: (pg.is_visible("#panSources"), pg.is_visible("#btSources")), query="?demo=1&embed=1")
    assert r == [False, True] or r == (False, True)


def test_selection_survit_au_rafraichissement():
    cible = "device:00:00:5e:00:53:02"

    def sc(pg):
        pg.click(f"#topo .nd[data-id='{cible}'] circle.prise")
        pg.wait_for_timeout(100)
        pg.click("#rafraichir")
        pg.wait_for_timeout(200)
        apres_bouton = (pg.locator(f"#topo .nd.sel[data-id='{cible}']").count(), pg.inner_text("#insp"))
        pg.reload()
        pg.wait_for_timeout(400)
        apres_rechargement = (pg.locator(f"#topo .nd.sel[data-id='{cible}']").count(), pg.inner_text("#insp"))
        return apres_bouton, apres_rechargement
    (n1, t1), (n2, t2) = _navigateur(sc)
    assert n1 == 1 and "nas-salon" in t1
    assert n2 == 1 and "nas-salon" in t2


def test_sans_session_bandeau_et_tirets():
    def sc(pg):
        pg.wait_for_timeout(300)
        return (pg.is_visible("#session"), pg.inner_text("#tuiles"), pg.inner_text("#topo"), pg.is_visible("#demo"))
    session, tuiles, topo, demo = _navigateur(sc, query="")
    assert session and not demo
    assert "—" in tuiles and "0" not in tuiles
    assert "session requise" in topo


def test_arbre_borne_et_selection_survit_au_changement_de_vue():
    cible = "device:00:00:5e:00:53:03"

    def sc(pg):
        pg.click(f"#topo .nd[data-id='{cible}'] circle.prise")
        pg.wait_for_timeout(100)
        avant = pg.inner_text("#insp")
        pg.click("#vueArbre")
        pg.wait_for_timeout(100)
        arbre = (pg.get_attribute("#vueArbre", "aria-pressed"), pg.locator("#topo svg.arbre").count(),
                 pg.locator(f"#topo svg.arbre .nd.sel[data-id='{cible}']").count(), pg.inner_text("#insp"),
                 pg.eval_on_selector_all("#topo text.plus", "l => l.map(n => n.textContent)"))
        pg.reload()
        pg.wait_for_timeout(400)
        recharge = (pg.locator("#topo svg.arbre").count(), pg.locator(f"#topo .nd.sel[data-id='{cible}']").count())
        pg.click("#vueBulles")
        pg.wait_for_timeout(100)
        retour = (pg.locator(f"#topo svg.bulles .nd.sel[data-id='{cible}']").count(), pg.inner_text("#insp"))
        return avant, arbre, recharge, retour
    avant, arbre, recharge, retour = _navigateur(sc)
    assert arbre[0] == "true" and arbre[1] == 1 and arbre[2] == 1 and arbre[3] == avant
    assert any(x.startswith("+ 3 ") for x in arbre[4]), arbre[4]
    assert recharge == (1, 1)  # vue et sélection retenues en sessionStorage
    assert retour[0] == 1 and retour[1] == avant


def test_liste_au_doigt_a_420():
    def sc(pg):
        r = {"interfaces": pg.eval_on_selector_all("#liste button", "l => l.map(b => b.textContent)")}
        pg.click("#liste button[data-id='interface:wlan0']")
        pg.wait_for_timeout(100)
        r["lignes"] = pg.locator("#liste button.ligneApp").count()
        r["hauteur"] = pg.eval_on_selector("#liste button.ligneApp", "b => b.getBoundingClientRect().height")
        r["sous_graphe"] = pg.evaluate("document.getElementById('liste').getBoundingClientRect().top >= document.getElementById('topo').getBoundingClientRect().bottom")
        pg.click("#liste button.ligneApp[data-id='device:00:00:5e:00:53:14']")
        pg.wait_for_timeout(100)
        r["insp"] = pg.inner_text("#insp")
        # là où la place le permet (zone isolée) : 22 px ; partout : au moins min(22 px, mi-distance au voisin)
        r["prise"] = pg.eval_on_selector("#topo .nd[data-id='network:lan'] circle.prise", "c => c.getBoundingClientRect().width / 2")
        r["regle"] = pg.evaluate("""() => { const sv = document.querySelector('#topo svg.bulles'), k = sv.getBoundingClientRect().width / sv.viewBox.baseVal.width;
            return [...sv.querySelectorAll('circle.prise')].every(c => c.getBoundingClientRect().width / 2 >=
              Math.min(22, Math.max(+c.dataset.r, +c.dataset.libre / 2) * k) - 0.6); }""")
        r["deborde"] = _debordement(pg)
        return r
    r = _navigateur(sc, largeur=420, hauteur=900)
    assert any("wlan0" in x for x in r["interfaces"])
    assert r["lignes"] == 63 and r["hauteur"] >= 44  # toute l'interface, y compris les 3 non dessinés
    assert r["sous_graphe"]
    assert "objet-05" in r["insp"]
    assert r["prise"] >= 21.5 and r["regle"]
    assert not r["deborde"]


def test_liste_a_cote_du_graphe_en_large():
    def sc(pg):
        pg.click("#topo .nd[data-id='interface:br-lan'] circle.prise")
        pg.wait_for_timeout(100)
        return pg.evaluate("""() => { const l = document.getElementById('liste').getBoundingClientRect(),
            t = document.getElementById('topo').getBoundingClientRect(); return [l.left >= t.right - 1, l.top < t.bottom]; }"""), \
            pg.locator("#liste button.ligneApp").count(), pg.get_attribute("#topo svg.bulles .ar", "tabindex")
    (cote, nb, tab) = _navigateur(sc)
    assert cote == [True, True] and nb == 6 and tab == "-1"
