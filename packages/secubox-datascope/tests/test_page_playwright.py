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


def _servir(pg, api, crochet=None, reperes_lents=None, vus=None):
    """Sert la page et reperes.js sur http://datascope.test/, l'API depuis `api` ({route: (code, corps)}) ; rien d'autre.

    `crochet` : expression exposée en window.__t depuis la fermeture de la page ; `reperes_lents` : liste où la requête de
    reperes.js est retenue (à libérer par le scénario) ; `vus` : liste où chaque appel de l'API est noté, requête comprise."""
    def repondre(route):
        if reperes_lents is not None and route.request.url.endswith("/reperes.js"):
            return reperes_lents.append(route)
        chemin = route.request.url.split("datascope.test", 1)[1].split("?")[0]
        if chemin.startswith("/api/v1/datascope/"):
            if vus is not None:
                vus.append(route.request.url.split("/api/v1/datascope/", 1)[1])
            code, corps = api.get(chemin[len("/api/v1/datascope/"):], (404, {}))
            return route.fulfill(status=code, content_type="application/json", body=json.dumps(corps))
        f = PAGE.parent / (chemin.removeprefix("/datascope/") or "index.html")
        if crochet and f.name == "index.html":
            corps = f.read_text(encoding="utf-8").replace("\n})();\n</script>", f"\nwindow.__t={crochet};\n}})();\n</script>")
            return route.fulfill(content_type="text/html; charset=utf-8", body=corps)
        if chemin.startswith("/datascope/") and f.is_file():
            return route.fulfill(path=str(f))
        return route.fulfill(status=404, body="")
    pg.route("**/*", repondre)
    return "http://datascope.test/datascope/"


def _navigateur(scenario, query="?demo=1", largeur=1400, hauteur=900, api=None, barres=False, crochet=None,
                reperes_lents=None, vus=None, **contexte):
    """Exécute `scenario(page)` dans un thread propre (Playwright refuse de tourner sous une boucle asyncio)."""
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch(ignore_default_args=["--hide-scrollbars"] if barres else None)
            except Exception as e:  # navigateur absent
                return ("skip", str(e), [], [])
            pg = nav.new_page(viewport={"width": largeur, "height": hauteur}, **contexte)
            erreurs, natifs = [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
            pg.goto(("file://" + str(PAGE) if api is None else _servir(pg, api, crochet, reperes_lents, vus)) + query,
                    wait_until="load" if reperes_lents is None else "domcontentloaded")
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
        r["sans_nom"] = pg.eval_on_selector_all("svg.histo", "l => l.filter(s => !s.getAttribute('aria-label') || !s.querySelector('g > title')).length")
        _capture(pg, f"paysage-demo-{largeur}-fiche.png")
        return r
    r = _navigateur(sc, largeur=largeur)
    assert r["chevauche"] == [] and r["police"] >= 13.5 and r["sans_nom"] == 0
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


# contraste réel d'un texte du graphe : couleur, opacités cumulées, sur le fond le plus clair du panneau (15,32,64)
CONTRASTE = """() => { const lin = v => { v /= 255; return v <= .03928 ? v / 12.92 : Math.pow((v + .055) / 1.055, 2.4); },
  L = c => .2126 * lin(c[0]) + .7152 * lin(c[1]) + .0722 * lin(c[2]), fond = [15, 32, 64];
  return Math.min(...[...document.querySelectorAll('#topo .lbl, #topo .sous, #topo .col, #pLegende label span')].map(t => {
    const st = getComputedStyle(t), c = (t.namespaceURI.endsWith('svg') ? st.fill : st.color).match(/[0-9.]+/g).map(Number);
    let o = c.length > 3 ? c[3] : 1; for (let e = t; e && e.nodeType === 1; e = e.parentNode) o *= +getComputedStyle(e).opacity;
    const m = [0, 1, 2].map(i => c[i] * o + fond[i] * (1 - o)); return (L(m) + .05) / (L(fond) + .05); })); }"""
ATTENUE = """() => { const f = document.querySelector("#topo .nd[data-id='infra:secubox-demo'] .f"); let o = 1;
  for (let e = f; e.nodeType === 1; e = e.parentNode) o *= +getComputedStyle(e).opacity; return o < .6; }"""
NOEUD = "#topo .nd[data-id='pop:famille:balayage_web']"


def test_paysage_selection_lisible_et_sortie_au_clavier():
    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(250)
        r = {"avant": pg.evaluate(CONTRASTE)}
        pg.focus(NOEUD)
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(300)
        r["choisi"] = (pg.evaluate(CONTRASTE), pg.evaluate(ATTENUE), pg.get_attribute(NOEUD, "aria-pressed"))
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(300)
        r["second"] = (pg.evaluate(ATTENUE), pg.get_attribute(NOEUD, "aria-pressed"), pg.inner_text("#insp"))
        pg.keyboard.press("Enter")
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(300)
        r["echap"] = (pg.evaluate(ATTENUE), pg.get_attribute(NOEUD, "aria-pressed"))
        pg.keyboard.press("Enter")
        pg.focus("#insp .actions a")
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(300)
        r["echap_fiche"] = (pg.get_attribute(NOEUD, "aria-pressed"), pg.evaluate("document.activeElement.getAttribute('data-id')"))
        pg.keyboard.press("Enter")
        pg.reload()
        pg.wait_for_timeout(500)
        r["retour"] = (pg.evaluate(ATTENUE), pg.get_attribute(NOEUD, "aria-pressed"), "boutique.demo.test" in pg.inner_text("#insp"))
        return r
    r = _navigateur(sc, reduced_motion="reduce")
    assert r["avant"] >= 4.5
    assert r["choisi"][0] >= 4.5 and r["choisi"][1:] == (True, "true")
    assert r["second"][:2] == (False, "false") and "Choisir un élément" in r["second"][2]
    assert r["echap"] == (False, "false")
    assert r["echap_fiche"] == ("false", "pop:famille:balayage_web")  # focus rendu au nœud, la fiche n'existe plus
    assert r["retour"] == (False, "true", True)  # sélection et fiche retrouvées, rien d'atténué sans geste


def test_paysage_largeur_avec_barres_de_defilement():
    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        return pg.evaluate("""() => { const t = document.getElementById('topo'); return [t.offsetWidth - t.clientWidth, t.scrollWidth - t.clientWidth,
            t.querySelector('svg').getBoundingClientRect().height > t.clientHeight]; }""")
    for hauteur in (500, 1600):
        barre, trop, vertical = _navigateur(sc, largeur=1400, hauteur=hauteur, barres=True)
        assert barre > 0 and trop <= 0 and vertical is (hauteur == 500)


def test_paysage_fiche_survit_aux_bascules_et_au_rafraichissement():
    d = _paysage_max()

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.focus("#topo .nd[data-id='pop:famille:p01']")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(150)
        pg.click("#insp details:last-of-type summary")
        pg.evaluate("document.querySelector('#insp details:last-of-type summary').dataset.t = '1'")
        pg.evaluate("document.getElementById('pt-pays').click()")
        pg.focus("#insp details:last-of-type summary")
        pg.click("#rafraichir", force=True)
        pg.focus("#insp details:last-of-type summary")
        pg.evaluate("window.dispatchEvent(new Event('resize')); document.dispatchEvent(new Event('visibilitychange'))")
        pg.wait_for_timeout(300)
        r = [pg.locator("#insp details[open] summary[data-t]").count(), pg.evaluate("document.activeElement.dataset.t")]
        d["instantane"]["ts"] = "2026-11-24T10:30:00.000000Z"  # nouveau relevé : la fiche est refaite
        pg.focus("#insp .fJetons .lien")
        pg.evaluate("document.getElementById('rafraichir').click()")
        pg.wait_for_timeout(300)
        r += [pg.locator("#insp summary[data-t]").count(), pg.locator("#insp details[open]").count(),
              pg.evaluate("document.activeElement.className + ' ' + !!document.activeElement.closest('#insp')")]
        return r
    assert _navigateur(sc, query="", api=_api(d)) == [1, "1", 0, 1, "lien true"]


def test_paysage_relecture_protegee_du_direct():
    d = _paysage_max()

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.evaluate("""() => __t.rejouer({ts: '2026-11-23T10:00:00.000000Z', epoch: 1795000000, partiel: false, compteurs: {populations: 1},
            graphe: {noeuds: [{id: 'pop:ancienne', type: 'population', libelle: 'ancienne', famille: 'collecte', metriques: {adresses: 7}}], aretes: []}}, null)""")
        pg.click("#topo .nd[data-id='pop:ancienne'] .prise")
        pg.evaluate("document.querySelector('#topo svg').dataset.t = '1'")
        d["instantane"]["ts"] = "2026-11-24T10:30:00.000000Z"
        d["age_s"] = 9000
        pg.click("#rafraichir")
        pg.wait_for_timeout(300)
        r = [pg.locator("#topo svg[data-t]").count(), pg.locator("#topo .nd").count(), pg.evaluate("Object.keys(__t.paysage.noeuds)"),
             "ancienne" in pg.inner_text("#insp"), "périmé" in pg.inner_text("#pEtat"), "aucun instantané antérieur" in pg.inner_text("#insp")]
        pg.evaluate("__t.rejouer(null)")
        pg.wait_for_timeout(200)
        r += [pg.locator("#topo .nd").count(), pg.locator("#topo .nd[data-id='pop:ancienne']").count(), pg.evaluate("__t.paysage.ts"),
              "Absent du relevé" in pg.inner_text("#insp")]
        return r
    r = _navigateur(sc, query="", api=_api(d), crochet="{rejouer:rejouerPaysage,paysage:paysage}")
    assert r == [1, 1, ["pop:ancienne"], True, False, False, 12 * 13 + 82, 0, "2026-11-24T10:30:00.000000Z", True]


def test_paysage_session_refusee_efface_la_relecture():
    api = _api(_paysage_max())

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.evaluate("__t.rejouer(__t.paysage.rep.instantane, null)")
        api["paysage"] = (401, {})
        pg.click("#rafraichir")
        pg.wait_for_timeout(300)
        return pg.inner_text("#topo"), pg.evaluate("Object.keys(__t.paysage.noeuds).length")
    t, n = _navigateur(sc, query="", api=api, crochet="{rejouer:rejouerPaysage,paysage:paysage}")
    assert "session requise" in t and n == 0


def test_paysage_reperes_tardifs_refont_graphe_et_fiche():
    lents = []

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.focus("#topo .nd[data-id='pop:famille:p01']")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(150)
        avant = pg.inner_text("#insp")
        lents[0].fulfill(path=str(PAGE.parent / "reperes.js"))
        pg.wait_for_timeout(400)
        return avant, pg.inner_text("#insp"), pg.text_content("#topo .nd[data-id='pop:famille:p01'] .emo")
    avant, apres, emo = _navigateur(sc, query="", api=_api(_paysage_max()), reperes_lents=lents)
    assert "Mots de passe sur la messagerie" not in avant and "✉️ Mots de passe sur la messagerie" in apres and emo == "✉️"


def test_paysage_lien_de_la_fiche_donne_le_focus_au_nouveau_titre():
    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(250)
        pg.focus(NOEUD)
        pg.keyboard.press("Enter")
        pg.focus("#insp .fJetons .lien")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(200)
        return pg.evaluate("[document.activeElement.className, document.activeElement.textContent]")
    assert _navigateur(sc) == ["fTitre", "blog.demo.test"]


# --- tâche 6 : compteurs, tendance, synthèse et fil -------------------------------------------------------------

def _iso(e):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(e)) + ".000000Z"


def _paysage_et_chronologie(nb=60, pas=1800, trou=(8, 13), partiels=(1, 2)):
    """Le paysage maximal et une chronologie irrégulière ; `trou` : relevés manquants (indices, du plus récent).

    Partiels 1 et 2 : à toute minute de l'horloge, une heure et une seule finit sur un relevé partiel."""
    d = _paysage_max(age_s=120.0)
    e0 = d["epoch"]
    d["instantane"]["ts"] = _iso(e0)
    c = d["instantane"]["compteurs"]
    ent = [{"ts": _iso(e0 - i * pas), "epoch": e0 - i * pas, "partiel": i in partiels,
            "compteurs": {**c, "adresses": c["adresses"] - 10 * i, "bans": None if i == 3 else c["bans"]}}
           for i in range(nb) if not trou[0] <= i < trou[1]]
    v = {"apparus": [], "disparus": [], "hausses": [], "baisses": [], "rotation_levee": [], "rotation_tombee": [], "tronque": False}
    fil = [{"ts": x["ts"], "epoch": x["epoch"], "partiel": x["partiel"], "difference": dict(v)} for x in ent[:12]]
    fil[0]["difference"] = {**v, "apparus": ["pop:famille:p00", "asn:64510", "asn:64511"], "rotation_levee": ["pop:famille:p04"],
                            "hausses": [{"id": "pop:famille:p01", "metrique": "adresses", "de": 1000, "a": 1910}]}
    fil[4]["difference"] = None
    fil[7]["difference"] = {"sans_precedent": "illisible"}
    fil[9]["difference"] = {**v, "disparus": ["pop:<b>parti"]}  # identifiant hors format : écarté
    tend = {"id": "pop:famille:p01", "illisibles": 0, "points": [
        {"ts": x["ts"], "epoch": x["epoch"], "adresses": 1900 - 5 * i, "bans": None, "reseaux": 40}
        for i, x in enumerate(ent[:54]) if i % 2 == 0][::-1]}
    api = _api(d)
    api["paysage/chronologie"] = (200, {"instantanes": ent[::-1], "tronque": False, "differences": fil})
    api["paysage/tendance/pop%3Afamille%3Ap01"] = (200, tend)
    return d, api


BARRES = """(cle) => [...document.querySelectorAll(`svg[data-k='h-${cle}'] > g`)].map(g => [g.getAttribute('class'), g.querySelector('title').textContent, !!g.querySelector('.b')])"""


def test_compteurs_histogrammes_et_bascule():
    _, api = _paysage_et_chronologie()
    vus = []

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        r = {"texte": pg.inner_text("#pBarre"), "cases": pg.locator("#pBarre .pbCase").count(), "h24": pg.evaluate(BARRES, "c-adresses"),
             "bans": pg.evaluate(BARRES, "c-bans"), "ecarts": pg.eval_on_selector_all("#pBarre .ecart", "l => l.map(e => [e.textContent, e.title])"),
             "bas": pg.eval_on_selector("#pBarre", "e => Math.round(e.getBoundingClientRect().bottom - innerHeight)")}
        pg.evaluate("document.querySelector('#pBarre .pbCases').dataset.t = '1'")
        for _ in range(3):  # rafraîchissements : ni redessin, ni requête de plus
            pg.click("#rafraichir")
            pg.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
            pg.wait_for_timeout(150)
        r["garde"] = pg.locator("#pBarre .pbCases[data-t]").count()
        pg.focus("[data-k='per-7j']")
        pg.keyboard.press("Enter")
        r["foc"] = pg.evaluate("[document.activeElement.dataset.k, document.activeElement.getAttribute('aria-pressed')]")
        r["h7"] = pg.evaluate(BARRES, "c-adresses")
        r["ecarts7"] = pg.eval_on_selector_all("#pBarre .ecart", "l => l.map(e => e.textContent)")
        pg.focus("svg[data-k='h-c-adresses']")
        pg.keyboard.press("ArrowLeft")
        r["lu"] = pg.inner_text("#pBarre .pLecture")
        pg.reload()
        pg.wait_for_timeout(500)
        r["retenue"] = pg.get_attribute("[data-k='per-7j']", "aria-pressed")
        return r
    r = _navigateur(sc, query="", api=api, vus=vus)
    assert r["cases"] == 7 and r["bas"] <= 0 and "Σ : cumul par population" in r["texte"]
    assert "non mesuré : " in r["texte"] and "partiel : 1 h" in r["texte"] and "historique depuis" in r["texte"]
    assert len(r["h24"]) == 24 and r["h24"][-1][0].startswith("cour")
    trous = [b for b in r["h24"] if "e-non_mesure" in b[0]]
    assert trous and all("non mesuré" in b[1] and not b[2] for b in trous) and not any(" : 0 " in b[1] for b in r["h24"])
    assert sum("part " in b[0] for b in r["h24"]) == 1
    assert r["ecarts"][3][0] == "▲ +480" and "24 h plus tôt" in r["ecarts"][3][1] and r["ecarts"][0][0] == "= 0"
    assert r["garde"] == 1 and r["foc"] == ["per-7j", "true"] and len(r["h7"]) == 7
    assert set(r["ecarts7"]) == {"—"}  # historique trop court : aucun écart inventé
    assert "adresses" in r["lu"] and r["retenue"] == "true"
    chrono = [v for v in vus if v.startswith("paysage/chronologie")]
    assert len(chrono) == 2 and "differences=12" in chrono[0], chrono  # une au chargement, une après rechargement de la page


@pytest.mark.parametrize("corps,code,attendu", [({"detail": "x"}, 503, "historique indisponible"),
                                                ({"instantanes": [], "tronque": False, "differences": []}, 200, "historique depuis")])
def test_compteurs_sans_historique(corps, code, attendu):
    _, api = _paysage_et_chronologie()
    api["paysage/chronologie"] = (code, corps)
    vus = []

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        for _ in range(3):
            pg.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
            pg.wait_for_timeout(100)
        return pg.inner_text("#pBarre"), pg.eval_on_selector_all("#pBarre .ecart", "l => l.map(e => e.textContent)"), \
            pg.eval_on_selector_all("#pBarre b", "l => l.map(e => e.textContent)"), pg.inner_text("#insp")
    t, e, b, insp = _navigateur(sc, query="", api=api, vus=vus)
    assert attendu in t and set(e) == {"—"} and b[0] == "16" and b[3] == "12 000"
    assert "comparaison indisponible" in insp and ("fil indisponible" in insp) == (code != 200)
    assert len([v for v in vus if v.startswith("paysage/chronologie")]) == 1  # un échec n'est pas retenté toutes les 30 s


def test_synthese_et_fil():
    d, api = _paysage_et_chronologie()
    d["difference_24h"] = {"apparus": ["pop:famille:p00", "cve:CVE-2099-10003", "asn:64510"], "disparus": ["pop:famille:partie"],
                           "hausses": [{"id": "pop:famille:p01", "metrique": "adresses", "de": 1000, "a": 1910}], "baisses": [],
                           "rotation_levee": ["pop:famille:p04"], "rotation_tombee": [], "tronque": False, "reference_ts": "x",
                           "reference_epoch": d["epoch"] - 86400, "reference_partiel": False, "ecart_s": 86400,
                           "motif": "<b>texte libre</b>"}

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        r = {"insp": pg.inner_text("#insp"), "img": pg.locator("#insp img, #insp .filL b b").count(),
             "fil": pg.eval_on_selector_all("#insp .filL", "l => l.map(e => e.innerText)"),
             "petit": pg.eval_on_selector_all("#insp *, #pBarre *", "l => l.filter(e => e.offsetParent && [...e.childNodes].some(n => n.nodeType === 3 && n.data.trim()) && parseFloat(getComputedStyle(e).fontSize) < 13.5).length"),
             "hauteurs": pg.evaluate("[document.querySelector('.topoPan').getBoundingClientRect().height, document.getElementById('panInsp').getBoundingClientRect().height]")}
        pg.focus("#insp .lien")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(150)
        r["fiche"] = pg.evaluate("document.activeElement.textContent")
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(150)
        r["retour"] = pg.inner_text("#inspType")
        pg.click("#vueBulles")
        r["bulles"] = pg.inner_text("#insp")
        pg.click("#vuePaysage")
        # relecture (tâche 7) d'un premier instantané : sans précédent, rien n'est présenté comme « apparu »
        pg.evaluate("__t({...__p.rep.instantane, ts: 'x', epoch: __p.rep.epoch - 7200}, {apparus: ['pop:famille:p00'], sans_precedent: 'premier'})")
        pg.wait_for_timeout(150)
        r["rejeu"] = (pg.inner_text("#insp"), pg.locator("#insp .filL").count(), pg.evaluate(BARRES, "c-adresses")[-1][0])
        return r
    r = _navigateur(sc, query="", api=api, crochet="rejouerPaysage;window.__p=paysage")
    assert "comparaison indisponible" in r["rejeu"][0] and "✚ apparues" not in r["rejeu"][0]
    assert 0 < r["rejeu"][1] < len(r["fil"]) and r["rejeu"][2].startswith("cour")  # fil et compteurs suivent le temps affiché
    i = r["insp"]
    assert "16 populations, dont 3 en rotation" in i and "changements depuis 24 h" in i and "texte libre" not in i
    for t in ("✚ apparues", "famille:partie", "rotation apparue", "1 000 → 1 910", "CVE-2099-10003", "✚ 1 · ✖ 0"):
        assert t in i, t
    assert "onerror" in i and r["img"] == 0  # libellé hostile : du texte
    assert "réseau source ✚ 2" in r["fil"][0] and "rotation" in r["fil"][0]
    assert any("comparaison illisible" in f for f in r["fil"]) and any("pas de comparaison" in f for f in r["fil"])
    assert any("relevés sans changement" in f for f in r["fil"]) and any("partiel" in f for f in r["fil"]) and "parti\n" not in i
    assert r["petit"] == 0 and abs(r["hauteurs"][0] - r["hauteurs"][1]) < 2
    assert "onerror" in r["fiche"] and r["retour"] == "synthèse" and "synthèse" not in r["bulles"] and "Fil des" not in r["bulles"]


def test_tendance_de_la_fiche_en_cache():
    _, api = _paysage_et_chronologie()
    vus = []

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        r = {"avant": len([v for v in vus if "tendance" in v])}
        pg.focus("#topo .nd[data-id='pop:famille:p01']")
        for _ in range(3):
            pg.keyboard.press("Enter")
            pg.wait_for_timeout(250)
        r["b"] = pg.evaluate(BARRES, "t-adresses")
        r["bans"] = pg.evaluate(BARRES, "t-bans")
        r["ecarts"] = pg.eval_on_selector_all("#pTendance .ecart", "l => l.map(e => e.textContent)")
        pg.evaluate("document.querySelector('#pTendance .fChiffres').dataset.t = '1'")
        pg.click("#rafraichir")
        pg.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
        pg.wait_for_timeout(250)
        r["garde"] = pg.locator("#pTendance [data-t]").count()
        pg.focus("#topo .nd[data-id='asn:64510']")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(200)
        r["asn"] = pg.locator("#pTendance").count()
        pg.focus("#topo .nd[data-id='pop:famille:p02']")  # tendance absente : 404, dit en clair
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(200)
        r["echec"] = pg.inner_text("#pTendance")
        return r
    r = _navigateur(sc, query="", api=api, vus=vus)
    assert r["avant"] == 0 and r["garde"] == 1 and r["asn"] == 0
    assert len(r["b"]) == 24 and "1 910 adresses" in [b for b in r["b"] if b[2]][-1][1]  # le chiffre affiché est le dernier point
    assert any("non mesuré" in b[1] for b in r["b"]) and any("mesure absente" in b[1] for b in r["bans"])
    assert r["ecarts"][2] == "—" and r["ecarts"][1] == "= 0"
    assert "tendance indisponible" in r["echec"]
    assert [v for v in vus if "p01" in v] == ["paysage/tendance/pop%3Afamille%3Ap01?jours=7"]


def test_tendance_lue_seulement_si_la_fiche_se_voit():
    _, api = _paysage_et_chronologie()
    vus = []

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.evaluate("document.querySelector(\"#topo .nd[data-id='pop:famille:p01']\").dispatchEvent(new MouseEvent('click', {bubbles: true}))")
        pg.wait_for_timeout(200)
        pg.click("#panInsp .fermer")
        pg.reload()  # sélection retenue, tiroir fermé
        pg.wait_for_timeout(500)
        n = len([v for v in vus if "tendance" in v])
        pg.click("#btInsp")
        pg.wait_for_timeout(300)
        return n, len([v for v in vus if "tendance" in v]), pg.locator("#pTendance svg.histo").count(), _debordement(pg)
    assert _navigateur(sc, query="?embed=1", largeur=400, api=api, vus=vus) == (1, 2, 3, False)


def test_vue_cachee_aucune_requete_d_historique():
    _, api = _paysage_et_chronologie()
    vus = []

    def sc(pg):
        pg.click("#rafraichir")
        pg.wait_for_timeout(200)
        a = len([v for v in vus if v.startswith("paysage")])
        pg.evaluate("Object.defineProperty(document, 'hidden', {get: () => true})")
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        return a, [v for v in vus if "chronologie" in v or "tendance" in v]
    assert _navigateur(sc, query="", api=api, vus=vus) == (0, [])


def test_echap_hors_du_graphe_ne_touche_pas_la_selection():
    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(250)
        pg.focus(NOEUD)
        pg.keyboard.press("Enter")
        pg.evaluate("window.__pris = []; document.addEventListener('keydown', e => { if (e.key === 'Escape') __pris.push(e.defaultPrevented); })")
        r = []
        for cible in ("svg[data-k='h-c-adresses']", "#pt-pays", "#rafraichir"):
            pg.focus(cible)
            pg.keyboard.press("Escape")
            r.append(pg.get_attribute(NOEUD, "aria-pressed"))
        pg.focus(NOEUD)
        pg.keyboard.press("Escape")
        return r, pg.evaluate("__pris"), pg.get_attribute(NOEUD, "aria-pressed")
    assert _navigateur(sc) == (["true"] * 3, [False] * 3 + [True], "false")


@pytest.mark.parametrize("fiche", [True, False])
def test_reperes_tardifs_gardent_parties_depliees_et_focus(fiche):
    lents = []
    _, api = _paysage_et_chronologie()
    api["paysage/chronologie"][1]["differences"][0]["difference"]["apparus"] += [f"cve:CVE-2099-{10000 + i}" for i in range(8)]

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        if fiche:
            pg.focus("#topo .nd[data-id='pop:famille:p01']")
            pg.keyboard.press("Enter")
            pg.wait_for_timeout(250)
        pg.click("#insp details summary")
        pg.focus("#insp .lien[data-k^='l-pop']" if not fiche else "#insp .lien[data-k^='l-pays']")
        k = pg.evaluate("document.activeElement.dataset.k")
        avant = pg.inner_text("#insp")
        lents[0].fulfill(path=str(PAGE.parent / "reperes.js"))
        pg.wait_for_timeout(400)
        return avant != pg.inner_text("#insp"), pg.locator("#insp details[open]").count(), pg.evaluate("document.activeElement.dataset.k") == k
    assert _navigateur(sc, query="", api=api, reperes_lents=lents) == (True, 1, True)


def test_anneau_et_contraste_des_compteurs():
    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(250)
        return pg.eval_on_selector_all("#topo .p-population", "l => l.map(g => [g.dataset.id, g.querySelectorAll('.pisteBan').length, (g.querySelector('.anneauBan') || {getAttribute: () => ''}).getAttribute('stroke-dasharray')])"), \
            pg.evaluate(CONTRASTE.replace("#topo .lbl, #topo .sous, #topo .col, #pLegende label span", "#pBarre .pbTete span, #pBarre .l, #pBarre .ecart, #pBarre b, #insp .fPuces, #insp .filL span, #insp .t"))
    a, k = _navigateur(sc)
    a = {x[0]: x[1:] for x in a}
    assert a["pop:famille:balayage_web"] == [1, "81 100"] and a["pop:profileur:demo2"] == [1, ""] and k >= 4.5


# --- tâche 6, relecture (tour 1) --------------------------------------------------------------------------------

VISIBLE = """(sel) => { const e = document.querySelector(sel); if (!e) return null; const r = e.getBoundingClientRect(), c = getComputedStyle(e);
  return r.width > 1 && r.height > 1 && (c.fill !== 'none' && !/, 0\\)$/.test(c.fill) || c.stroke !== 'none') && +c.opacity > .5; }"""


def test_case_en_cours_et_derniere_mesure_toujours_marquees():
    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        r = []
        for k in ("24h", "7j"):
            pg.click(f"[data-k='per-{k}']")
            s = "svg[data-k='h-c-adresses']"
            r.append([pg.locator(f"{s} g.cour .b").count(), pg.evaluate(VISIBLE, f"{s} g.cour .encours"), pg.locator(f"{s} g.dern").count(),
                      pg.evaluate("""s => { const f = e => getComputedStyle(e).fill; return f(document.querySelector(s + ' g.dern .b')) !== f(document.querySelector(s + ' g:not(.dern):not(.part) .b')); }""", s)])
        return r
    # démonstration à 11:00 pile : l'heure en cours n'a encore aucun relevé (pas de barre), elle reste repérée
    assert _navigateur(sc) == [[0, True, 1, True], [1, True, 1, True]]


def test_trou_mesure_absente_et_noeud_absent_se_distinguent():
    _, api = _paysage_et_chronologie(pas=3600)

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        st = """s => { const e = document.querySelector(s), c = getComputedStyle(e); return [c.fill, c.stroke, e.getBoundingClientRect().height > 8]; }"""
        return pg.evaluate(st, "svg[data-k='h-c-bans'] g.e-non_mesure .trou"), pg.evaluate(st, "svg[data-k='h-c-bans'] g.e-vide .trou"), \
            pg.eval_on_selector("svg[data-k='h-c-bans'] g.e-non_mesure .bord", "e => e.getBoundingClientRect().width > 2 && getComputedStyle(e).stroke !== 'none'"), pg.inner_text("#pBarre .pbTete")
    nm, vide, bord, tete = _navigateur(sc, query="", api=api)
    assert nm[0] != vide[0] and vide[0] == "none" and vide[1] != "none" and bord is True
    assert "url(" not in nm[0]  # teinte pleine : une trame devient invisible dans une barre de 3 px
    assert "mesure absente" in tete


def test_cibles_tactiles():
    _, api = _paysage_et_chronologie()
    d = api["paysage"][1]
    d["difference_24h"] = {"apparus": ["pop:famille:p01", "cve:CVE-2099-10003"], "disparus": [], "hausses": [], "baisses": [], "rotation_levee": [],
                           "rotation_tombee": [], "tronque": False, "reference_ts": "x", "reference_epoch": d["epoch"] - 86400, "ecart_s": 86400}

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        pg.click("#btInsp")
        pg.wait_for_timeout(200)
        return pg.evaluate("matchMedia('(pointer:coarse)').matches"), pg.locator("#insp .sLigne .lien").count(), pg.locator("#insp .filL .lien").count(), \
            pg.eval_on_selector_all("#insp .sLigne .lien, #insp .filL .lien, #insp summary, #pBarre button, #pBarre svg.histo",
                                    "l => l.map(e => [e.textContent.slice(0, 30), e.getBoundingClientRect()]).filter(x => x[1].height < 40 || x[1].width < 40).map(x => x[0])"), \
            _debordement(pg)
    coarse, s, f, petits, deborde = _navigateur(sc, query="", api=api, largeur=400, has_touch=True, is_mobile=True)
    assert coarse and s >= 2 and f >= 2 and petits == [] and not deborde


def test_partiel_signale_des_deux_cotes_de_la_comparaison():
    d, api = _paysage_et_chronologie(partiels=(2, 12))
    d["instantane"]["partiel"] = True
    d["difference_24h"] = {"apparus": [], "disparus": [], "hausses": [{"id": "pop:famille:p01", "metrique": "adresses", "de": 1000, "a": 1910}],
                           "baisses": [], "rotation_levee": [], "rotation_tombee": [], "tronque": False, "reference_ts": "x",
                           "reference_epoch": d["epoch"] - 86400, "reference_partiel": False, "ecart_s": 86400}
    c = api["paysage/chronologie"][1]
    # les 12 lignes du fil vont de l'indice 0 à 11 ; le prédécesseur de la plus ancienne n'est que dans la chronologie
    e0 = d["epoch"]
    c["instantanes"] = sorted(({"ts": _iso(e0 - i * 1800), "epoch": e0 - i * 1800, "partiel": i in (2, 12),
                                "compteurs": d["instantane"]["compteurs"]} for i in range(20)), key=lambda x: x["epoch"])
    vide = {k: [] for k in ("apparus", "disparus", "hausses", "baisses", "rotation_levee", "rotation_tombee")}
    c["differences"] = [{"ts": _iso(e0 - i * 1800), "epoch": e0 - i * 1800, "partiel": i == 2, "difference": dict(vide)} for i in range(12)]

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        r = [pg.inner_text("#insp"), pg.eval_on_selector_all("#insp .filL", "l => l.map(e => e.innerText)")]
        pg.focus("#topo .nd[data-id='pop:famille:p01']")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(200)
        return r + [pg.inner_text("#insp")]
    syn, fil, fiche = _navigateur(sc, query="", api=api)
    assert "relevé affiché partiel" in syn and "relevé affiché partiel" in fiche
    prec = [i for i, t in enumerate(fil) if "comparé à un relevé partiel" in t]
    assert len(prec) == 2 and prec[1] == len(fil) - 1  # le suivant du partiel, et la plus ancienne ligne
    assert sum("partiel" in t and "comparé" not in t for t in fil) == 1


def test_defilement_et_parties_depliees_gardes_au_nouveau_releve():
    d, api = _paysage_et_chronologie()
    d["difference_24h"] = {"apparus": [], "disparus": [], "hausses": [], "baisses": [], "rotation_tombee": [], "tronque": False,
                           "rotation_levee": [f"pop:famille:p{i:02d}" for i in range(12)], "reference_ts": "x", "reference_epoch": d["epoch"] - 86400,
                           "ecart_s": 86400}

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        pg.click("#insp details[data-k='syn-rotation_levee'] summary")
        pg.evaluate("document.getElementById('panInsp').scrollTop = 120")
        av = pg.evaluate("document.getElementById('panInsp').scrollTop")
        d["instantane"]["ts"] = _iso(d["epoch"] + 60)
        d["epoch"] += 60
        pg.evaluate("document.querySelector('#insp .sPhrase').dataset.t = '1'; document.getElementById('rafraichir').click()")
        pg.wait_for_timeout(400)
        return av, pg.evaluate("document.getElementById('panInsp').scrollTop"), pg.locator("#insp [data-t]").count(), pg.locator("#insp details[data-k='syn-rotation_levee'][open]").count()
    assert _navigateur(sc, query="", api=api, largeur=1400, hauteur=700) == (120, 120, 0, 1)


def test_session_refusee_pendant_la_lecture_de_l_historique():
    _, api = _paysage_et_chronologie()

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.evaluate("__p.chrono.enVol = 'en-cours'; __p.chrono.echec = true")
        api["paysage"], bon = (401, {}), api["paysage"]
        pg.click("#rafraichir")
        pg.wait_for_timeout(200)
        r = pg.evaluate("[__p.chrono.enVol, __p.chrono.rep, __p.chrono.echec]")
        api["paysage"] = bon
        pg.click("#rafraichir")
        pg.wait_for_timeout(300)
        return r, pg.evaluate("!!__p.chrono.rep")
    assert _navigateur(sc, query="", api=api, crochet="0;window.__p=paysage") == (["", None, False], True)
