# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3853 — page Network Cockpit dans un vrai navigateur (sauté sans Playwright ni Chromium).

Captures facultatives : SECUBOX_DATASCOPE_CAPTURES=<dossier> écrit cockpit-1400.png et cockpit-420.png (?demo=1).
"""
import concurrent.futures
import json
import os
import pathlib
import time

import pytest

pytestmark = pytest.mark.playwright
sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "datascope" / "index.html"
CAPTURES = os.environ.get("SECUBOX_DATASCOPE_CAPTURES")


def _servir(pg, api):
    """Sert la page et reperes.js sur http://datascope.test/, l'API depuis `api` ({route: (code, corps)}) ; rien d'autre."""
    def repondre(route):
        chemin = route.request.url.split("datascope.test", 1)[1].split("?")[0]
        if chemin.startswith("/api/v1/datascope/"):
            code, corps = api.get(chemin[len("/api/v1/datascope/"):], (404, {}))
            return route.fulfill(status=code, content_type="application/json", body=json.dumps(corps))
        f = PAGE.parent / (chemin.removeprefix("/datascope/") or "index.html")
        if chemin.startswith("/datascope/") and f.is_file():
            return route.fulfill(path=str(f))
        return route.fulfill(status=404, body="")
    pg.route("**/*", repondre)
    return "http://datascope.test/datascope/"


def _navigateur(scenario, query="?demo=1", largeur=1400, hauteur=900, api=None, **contexte):
    """Exécute `scenario(page)` dans un thread propre (Playwright refuse de tourner sous une boucle asyncio)."""
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:  # navigateur absent
                return ("skip", str(e), [], [])
            pg = nav.new_page(viewport={"width": largeur, "height": hauteur}, **contexte)
            erreurs, natifs = [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
            pg.goto(("file://" + str(PAGE) if api is None else _servir(pg, api)) + query)
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
        r["ip"] = pg.inner_text("#liste button.ligneApp[data-id='device:00:00:5e:00:53:14'] .m")
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
    assert r["ip"].startswith("192.0.2.") and "IP —" not in r["ip"]  # attribut ip de l'appareil, sans nœud ip
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


# --- vue « Paysage » (#3921) ---------------------------------------------------------------------------------

def _capture(pg, nom):
    if CAPTURES:
        pg.screenshot(path=os.path.join(CAPTURES, nom), full_page=True)


def _paysage_max(age_s=60.0, partiel=False):
    """12 populations, 8 réseaux chacune et 3 classes repliées, 60 cibles, 20 CVE, libellés hostiles et longs."""
    n, a = [], []
    e = time.time() - age_s
    for i in range(12):
        p = f"pop:famille:p{i:02d}"
        n.append({"id": p, "type": "population", "libelle": "<img src=x onerror=document.title='xss'>" if i == 0 else
                  f"service-numero-{i}-au-nom-particulierement-long.demo.test",
                  "famille": ["collecte", "messagerie", "acces_distant", "balayage_web", "constructor"][i % 5],
                  "metriques": {"adresses": 2000 - 90 * i, "reseaux": 40, "bans": 30, "rotation": i % 4 == 0,
                                "etat": "observee", "une": 40, "le3": 80, "classes": {"hebergeur": 60, "acces": 40},
                                "actives_24h": 12, "bannies_24h": 3, "premier": int(e) - 86400, "dernier": int(e)}})
        n.append({"id": f"camp:sig{i:02d}", "type": "campagne", "libelle": f"sig{i:02d}", "metriques": {}})
        a.append({"de": f"camp:sig{i:02d}", "vers": p, "type": "MEMBRE_DE", "poids": 1})
        for j in range(8):
            r = f"asn:{64496 + i * 8 + j}"
            n.append({"id": r, "type": "reseau_source", "libelle": f"Opérateur de démonstration numéro {i * 8 + j}",
                      "classe": ["hebergeur", "proxy_loue", "acces", "toString"][j % 4], "metriques": {}})
            a.append({"de": r, "vers": p, "type": "SOURCE_DE", "poids": 400 - j * 45})
        for c in ("hebergeur", "acces", "inconnu"):
            n.append({"id": f"classe:p{i:02d}:{c}", "type": "classe_reseau", "libelle": c, "classe": c, "metriques": {}})
            a.append({"de": f"classe:p{i:02d}:{c}", "vers": p, "type": "SOURCE_DE", "poids": 20})
        n.append({"id": f"pays:X{chr(65 + i)}", "type": "pays", "libelle": f"X{chr(65 + i)}", "metriques": {}})
        a.append({"de": p, "vers": f"pays:X{chr(65 + i)}", "type": "ORIGINE", "poids": 40})
    for i in range(60):
        c = f"cible:hote-{i:02d}.sous-domaine.demo.test"
        n.append({"id": c, "type": "cible", "libelle": c[6:], "metriques": {}})
        a.append({"de": f"pop:famille:p{i % 12:02d}", "vers": c, "type": "VISE", "poids": 1})
        a.append({"de": c, "vers": "infra:box-demo", "type": "HEBERGE", "poids": 1})
    for i in range(20):
        n.append({"id": f"cve:CVE-2099-{10000 + i}", "type": "cve", "libelle": f"CVE-2099-{10000 + i}", "metriques": {}})
        a.append({"de": f"pop:famille:p{i % 12:02d}", "vers": f"cve:CVE-2099-{10000 + i}", "type": "EXPLOITE", "poids": 1})
    n.append({"id": "infra:box-demo", "type": "infra", "libelle": "box-demo", "metriques": {}})
    n.append({"id": "autres:populations", "type": "autres", "libelle": "+ 4 autres", "metriques": {"repliees": 4}})
    return {"disponible": True, "epoch": e, "age_s": age_s, "difference_24h": None,
            "motif_difference_24h": "aucun instantané antérieur d'au moins 12 h au dernier",
            "instantane": {"ts": "2026-11-24T10:00:00.000000Z", "epoch": e, "partiel": partiel,
                           "graphe": {"noeuds": n, "aretes": a},
                           "compteurs": {"populations": 16, "rotation": 3, "reseaux": 640, "adresses": 12000,
                                         "cibles": 60, "bans": 400, "cves": 20}}}


def _api(paysage, code=200):
    return {"paysage": (code, paysage), "overview": (200, {"disponible": False}), "sources": (200, {"sources": []}),
            "graph": (200, {"disponible": False, "motif": "relevé absent"})}


# géométrie à l'écran : libellés qui se chevauchent, libellés plus larges que leur case
MESURES = """() => { const sv = document.querySelector('#topo svg.paysage'),
  R = [...sv.querySelectorAll('.nd .lbl, .nd .sous')].map(t => [t.getBoundingClientRect(), t.textContent]), ch = [];
  for (let i = 0; i < R.length; i++) for (let j = i + 1; j < R.length; j++) { const a = R[i][0], b = R[j][0];
    if (Math.min(a.right, b.right) - Math.max(a.left, b.left) > 2 && Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > 3) ch.push([R[i][1], R[j][1]]); }
  const t = document.getElementById('topo');
  return {chevauche: ch, police: Math.min(...[...sv.querySelectorAll('.lbl')].map(t => parseFloat(getComputedStyle(t).fontSize) * sv.getBoundingClientRect().width / sv.viewBox.baseVal.width)),
    defile: t.scrollWidth >= t.clientWidth, cadre: t.getBoundingClientRect().right <= innerWidth, noeuds: sv.querySelectorAll('.nd').length}; }"""


@pytest.mark.parametrize("largeur", [1280, 400])
def test_paysage_demo(largeur):
    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(250)
        r = pg.evaluate(MESURES)
        r["deborde"] = _debordement(pg)
        r["etat"] = pg.inner_text("#pEtat")
        r["pays"] = pg.locator("#topo .p-pays").count()
        r["barre"] = pg.inner_text("#pBarre")
        r["legende_h"] = pg.eval_on_selector("#pLegende", "e => e.getBoundingClientRect().height")
        r["part"] = pg.evaluate("document.getElementById('topo').getBoundingClientRect().height / document.querySelector('.topoPan').getBoundingClientRect().height")
        r["replie"] = not pg.is_visible("#pAideC") and pg.inner_text("#pAideT")
        _capture(pg, f"paysage-demo-{largeur}.png")
        pg.click("#pAideT")
        r["puces"] = pg.locator("#pAideC .puce").all_inner_texts()
        pg.click("#pAideT")
        pg.check("#pt-pays")
        pg.wait_for_timeout(100)
        r["pays2"] = pg.locator("#topo .p-pays").count()
        r["focus_case"] = pg.evaluate("document.activeElement.id")
        pg.uncheck("#pt-pays")
        pg.focus("#topo .nd[data-id='pop:famille:balayage_web']")
        pg.wait_for_timeout(200)
        r["info"] = pg.evaluate("[...document.querySelectorAll('#topo .infob tspan')].map(t => t.textContent).join(' ')")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(200)
        r["insp"] = pg.inner_text("#insp")
        r["liens"] = pg.eval_on_selector_all("#insp .actions a", "l => l.map(a => a.getAttribute('href'))")
        r["sel"] = pg.locator("#topo .nd.sel").count()
        r["empile"] = pg.get_attribute("#insp .empile", "aria-label")
        r["petit"] = pg.eval_on_selector_all("#insp *, #pEtat *, #pLegende *, #pBarre *, #pAide summary",
            "l => l.filter(e => e.offsetParent && [...e.childNodes].some(n => n.nodeType === 3 && n.data.trim()) && parseFloat(getComputedStyle(e).fontSize) < 13.5).map(e => e.className + ':' + e.textContent.slice(0, 30))")
        r["deborde2"] = _debordement(pg)
        _capture(pg, f"paysage-demo-{largeur}-fiche.png")
        return r
    r = _navigateur(sc, largeur=largeur)
    assert r["chevauche"] == [] and r["police"] >= 13.5
    assert not r["deborde"] and not r["deborde2"] and r["cadre"]
    assert r["etat"].startswith("relevé de ") and "cumul par population" in r["barre"]
    assert r["legende_h"] <= 60 and r["part"] >= .6 and "repères" in r["replie"]
    assert "périmé" not in r["etat"] and "partiel" not in r["etat"]
    assert r["pays"] == 0 and r["pays2"] == 3 and r["focus_case"] == "pt-pays"
    assert any("proxy loué" in p for p in r["puces"]) and any("rotation" in p for p in r["puces"])
    assert "620 adresses" in r["info"] and "Balayage des sites web : boutique.demo.test" in r["info"]
    assert "Hébergement Démonstration et Associés" in r["insp"] and "160 adresses" in r["insp"]
    assert r["empile"] == "hébergeur / cloud 80 %, inconnu 20 %" and r["petit"] == []
    assert r["liens"] == ["/actor/", "/waf/", "/garde/"] and r["sel"] == 1


@pytest.mark.parametrize("largeur", [1280, 400])
def test_paysage_taille_reelle(largeur):
    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        r = pg.evaluate(MESURES)
        r["deborde"] = _debordement(pg)
        _capture(pg, f"paysage-max-{largeur}.png")
        pg.focus("#topo .nd[data-id='asn:64510']")
        pg.wait_for_timeout(200)
        r["info"] = pg.evaluate("[...document.querySelectorAll('#topo .infob tspan')].map(t => t.textContent).join(' ')")
        r["info_visible"] = pg.evaluate("""() => { const i = document.querySelector('#topo .infob').getBoundingClientRect(),
            t = document.getElementById('topo').getBoundingClientRect(); return i.left >= t.left - 2 && i.right <= t.right + 2 && i.width > 0; }""")
        pg.focus("#topo .nd[data-id='pop:famille:p00']")
        pg.keyboard.press(" ")
        pg.wait_for_timeout(200)
        r["insp"] = pg.inner_text("#insp")
        r["titre"] = pg.title()
        r["img"] = pg.locator("#insp img, #topo img").count()
        pos = pg.evaluate("[document.getElementById('topo').scrollLeft, document.getElementById('topo').scrollTop]")
        pg.evaluate("document.querySelector('#topo svg').dataset.temoin = '1'")
        pg.click("#rafraichir")
        pg.wait_for_timeout(300)
        r["garde"] = pg.locator("#topo svg[data-temoin]").count()
        r["pos"] = pos == pg.evaluate("[document.getElementById('topo').scrollLeft, document.getElementById('topo').scrollTop]")
        return r
    r = _navigateur(sc, query="", largeur=largeur, api=_api(_paysage_max()))
    assert r["chevauche"] == [], r["chevauche"][:5]
    assert r["police"] >= 13.5 and r["noeuds"] == 12 * (1 + 1 + 8 + 3) + 60 + 20 + 2
    assert not r["deborde"] and r["cadre"]
    assert "Opérateur de démonstration numéro 14" in r["info"] and r["info_visible"]
    assert "<img src=x onerror" in r["insp"] and r["img"] == 0 and r["titre"] != "xss"  # texte, jamais HTML
    assert "aucun instantané antérieur" in r["insp"]
    assert r["garde"] == 1 and r["pos"]  # mêmes données : graphe et défilement gardés


def test_paysage_partiel_et_perime_en_clair():
    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        return pg.inner_text("#pEtat")
    t = _navigateur(sc, query="", api=_api(_paysage_max(age_s=7300.0, partiel=True)))
    assert "relevé de " in t and "partiel" in t and "périmé · plus de 2 h" in t


@pytest.mark.parametrize("corps,code,attendu", [
    ({"disponible": False}, 200, "relevé des populations indisponible"), ({"detail": "x"}, 503, "relevé des populations indisponible"),
    ({}, 401, "session requise"), ({"disponible": True, "instantane": {"ts": "x", "graphe": {"noeuds": [None, 3], "aretes": "x"}}}, 200,
                                   "Aucune population")])
def test_paysage_etats_vides(corps, code, attendu):
    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        return pg.inner_text("#topo"), pg.locator("#topo svg").count()
    t, n = _navigateur(sc, query="", api=_api(corps, code))
    assert attendu in t and n == 0


def test_paysage_embed_mouvement_reduit_et_retour():
    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(200)
        r = [pg.evaluate("getComputedStyle(document.querySelector('#topo .nd')).transitionDuration"), _debordement(pg)]
        pg.reload()
        pg.wait_for_timeout(400)
        r.append(pg.locator("#topo svg.paysage").count())  # vue retenue
        pg.click("#topo .nd[data-id='infra:secubox-demo'] .prise")
        pg.wait_for_timeout(150)
        pg.click("#insp button:has-text('vue Bulles')")
        pg.wait_for_timeout(150)
        r += [pg.locator("#topo svg.bulles .nd.sel[data-id='node:secubox-demo']").count(), pg.is_visible("#pEtat"),
              pg.is_visible("#pLegende"), pg.get_attribute("#vueBulles", "aria-pressed")]
        return r
    r = _navigateur(sc, query="?demo=1&embed=1", largeur=900, reduced_motion="reduce")
    assert r == ["0s", False, 1, 1, False, False, "true"]
