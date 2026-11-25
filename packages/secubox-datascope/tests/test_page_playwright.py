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
import statistics
import time

import pytest

pytestmark = pytest.mark.playwright
sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "datascope" / "index.html"
CAPTURES = os.environ.get("SECUBOX_DATASCOPE_CAPTURES")


def _servir(pg, api, crochet=None, reperes_lents=None, vus=None, retenir=None):
    """Sert la page et reperes.js sur http://datascope.test/, l'API depuis `api` ({route: (code, corps)}) ; rien d'autre.

    `crochet` : expression exposée en window.__t depuis la fermeture de la page ; `reperes_lents` : liste où la requête de
    reperes.js est retenue (à libérer par le scénario) ; `vus` : liste où chaque appel de l'API est noté, requête comprise ; `retenir` : (préfixe, liste) d'appels laissés sans réponse."""
    def repondre(route):
        if reperes_lents is not None and route.request.url.endswith("/reperes.js"):
            return reperes_lents.append(route)
        chemin = route.request.url.split("datascope.test", 1)[1].split("?")[0]
        if chemin.startswith("/api/v1/datascope/"):
            if vus is not None:
                vus.append(route.request.url.split("/api/v1/datascope/", 1)[1])
            if retenir is not None and retenir[2:] != (False,) and chemin.startswith("/api/v1/datascope/" + retenir[0]):
                return retenir[1].append(route)
            code, corps = api.get(chemin[len("/api/v1/datascope/"):], (404, {}))
            return route.fulfill(status=code, content_type="application/json", body=corps if isinstance(corps, str) else json.dumps(corps))
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
                reperes_lents=None, vus=None, retenir=None, **contexte):
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
            pg.goto(("file://" + str(PAGE) if api is None else _servir(pg, api, crochet, reperes_lents, vus, retenir)) + query,
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
    assert r["pays"] == 0 and r["pays2"] == 10 and r["focus_case"] == "pt-pays"
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
        pg.mouse.move(2, 2)  # aucun survol : l'infobulle est celle du focus
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


def _src(etat, motif):
    return {"source": "paysage", "etat": etat, "motif": motif, "vu_le": "2026-11-24T10:00:00Z"}


@pytest.mark.parametrize("sources, attendu", [
    ([_src("inaccessible", "droit refusé")], "inaccessible : droit refusé"),
    ([_src("inaccessible", "relevé absent")], "inaccessible : relevé absent"),
    ([_src("inaccessible", "relevé daté dans le futur (2026-11-25T00:00:00Z) : écarté")], "daté dans le futur"),
    ([_src("inaccessible", "<img src=x onerror=document.title='xss'>")], "<img src=x"),
    ([_src("inaccessible", None)], "inaccessible : motif inconnu"),
    ([_src("ok", None)], "aucun instantané enregistré pour le moment"), ([], "aucun instantané enregistré pour le moment")])
def test_paysage_vide_dit_l_etat_de_sa_source(sources, attendu):
    """I3 : sans instantané, la page dit pourquoi (état publié par le collecteur)."""
    api = _api({"disponible": False})
    api["sources"] = (200, {"sources": sources})

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        return pg.inner_text("#topo"), pg.title(), pg.locator("#topo img").count()
    t, titre, img = _navigateur(sc, query="", api=api)
    assert attendu in t and "xss" not in titre and img == 0
    assert ("aucun instantané" in t) == ("aucun instantané" in attendu)


def test_paysage_source_en_panne_dite_a_cote_du_dernier_instantane():
    """I3 : un instantané est affiché mais le relevé n'est plus lisible : la pastille le dit, avec le motif."""
    api = _api(_paysage_max())
    api["sources"] = (200, {"sources": [_src("inaccessible", "droit refusé"), {**_src("ok", None), "source": "network"}]})

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        r = [pg.inner_text("#pEtat"), _debordement(pg)]
        pg.click("#vueBulles")
        pg.wait_for_timeout(150)
        # source du paysage : montrée avec son motif, sans case (elle n'a aucune entité à masquer)
        return r + [pg.inner_text("#sources"), pg.locator("#sources input").count(), pg.locator("#src-network").count()]
    etat, deborde, liste, cases, reseau = _navigateur(sc, query="", api=api)
    assert "relevé inaccessible : droit refusé" in etat and not deborde
    assert "paysage" in liste and "droit refusé" in liste and (cases, reseau) == (1, 1)
    api["sources"] = (200, {"sources": [_src("ok", None)]})
    assert "inaccessible" not in _navigateur(sc, query="", api=api)[0]


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


# --- tâche 7 : mode évolution et enregistreur --------------------------------------------------------------------

def _enregistrements(nb=40, pas=1800, trou=(), partiels=(), codes=None, grand=False, jours=0):
    """Paysage, chronologie et un instantané par relevé (indice 0 : le plus récent). Les adresses suivent l'indice ; la population p05
    n'existe qu'aux indices pairs ; `codes` : {indice: code HTTP} des instantanés en panne ; `jours` : un relevé par heure en plus."""
    d = _paysage_max(age_s=120.0)
    e0 = float(int(d["epoch"]))
    d["epoch"] = d["instantane"]["epoch"] = e0
    d["instantane"]["ts"] = _iso(e0)
    if not grand:
        g = d["instantane"]["graphe"]
        garde = {n["id"] for n in g["noeuds"] if n["id"] in ("infra:box-demo", "asn:64496", "asn:64497", "cible:hote-00.sous-domaine.demo.test")
                 or n["id"].startswith("pop:famille:p0") and n["id"][-1] < "6"}
        g["noeuds"] = [n for n in g["noeuds"] if n["id"] in garde]
        g["aretes"] = [a for a in g["aretes"] if a["de"] in garde and a["vers"] in garde]
    base, ecarts = d["instantane"], [i * pas for i in range(nb) if i not in trou]
    ecarts += [nb * pas + 3600 * k for k in range(24 * jours)]
    vide = {k: [] for k in ("apparus", "disparus", "hausses", "baisses", "rotation_levee", "rotation_tombee")}
    api, ent = _api(d), []
    for rang, x in enumerate(ecarts):
        ts, g = _iso(e0 - x), {"aretes": base["graphe"]["aretes"], "noeuds": []}
        for n in base["graphe"]["noeuds"]:
            if n["id"] == "pop:famille:p05" and rang % 2:
                continue
            m = dict(n["metriques"])
            if n["type"] == "population" and "adresses" in m and rang:
                m["adresses"] = int(m["adresses"] * (.6 if rang % 4 == 2 else 1)) + rang
            g["noeuds"].append({**n, "metriques": m})
        g["aretes"] = [a for a in g["aretes"] if rang % 2 == 0 or "pop:famille:p05" not in (a["de"], a["vers"])]
        h = {"ts": ts, "epoch": e0 - x, "partiel": rang in partiels, "compteurs": {**base["compteurs"], "adresses": 12000 - 10 * rang}}
        ent.append(h)
        api["paysage/instantane/" + ts.replace(":", "%3A")] = ((codes or {}).get(rang, 200), {**h, "graphe": g, "difference": dict(vide)})
    api["paysage/chronologie"] = (200, {"instantanes": ent[::-1], "tronque": False,
                                        "differences": [{k: x[k] for k in ("ts", "epoch", "partiel")} | {"difference": dict(vide)} for x in ent[:12]]})
    api["paysage/difference"] = (200, {**vide, "apparus": ["pop:famille:p01"], "disparus": ["pop:famille:messagerie", "asn:64999"], "tronque": False})
    return d, api, ent


E_CROCHET = "{E:Enregistreur,p:paysage,evo:evo}"


def _bandeau(pg):
    return pg.inner_text("#eBandeau") if pg.is_visible("#eBandeau") else None


def _instants(vus):
    return [v.split("/")[-1] for v in vus if v.startswith("paysage/instantane/")]


def test_enregistreur_demo_rembobine_avance_partiel_et_trou():
    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(250)
        r = {"direct": (_bandeau(pg), pg.inner_text("#eHeure"), pg.get_attribute("#eSuiv", "aria-disabled"), pg.get_attribute("#eDirect", "aria-disabled"))}
        pg.focus("#eDebut")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(300)
        r["debut"] = (_bandeau(pg), pg.evaluate("document.activeElement.id"))
        for _ in range(3):
            pg.click("#eSuiv")
            pg.wait_for_timeout(120)
        r["quatre"] = (_bandeau(pg), pg.evaluate("[__t.E.etat().i, __t.p.ts === __t.E.etat().liste[3].ts, __t.p.rejoue.instantane.ts === __t.p.ts]"),
                       pg.inner_text("#pEtat"), pg.evaluate("document.activeElement.id"))
        r["trou"], r["partiel"], r["disparu"] = None, None, None
        for k in range(120):
            pg.evaluate("__t.E.pas(1)")
            pg.wait_for_timeout(25)
            t = _bandeau(pg) or ""
            r["trou"] = t if "trou" in t and not r["trou"] else r["trou"]
            r["partiel"] = t if "partiel" in t and not r["partiel"] else r["partiel"]
            if not r["disparu"] and pg.locator("#topo .nd.fantome").count():
                r["disparu"] = pg.eval_on_selector_all("#topo .nd.fantome", "l => l.map(g => g.getAttribute('aria-label') + '|' + g.querySelector('.badge').textContent)")
        r["apparu"] = pg.evaluate("__t.E.etat().i === __t.E.etat().n - 1")
        pg.click("#eDirect")
        pg.wait_for_timeout(200)
        r["retour"] = (_bandeau(pg), pg.evaluate("[__t.p.rejoue, __t.E.etat().cache, __t.p.ts === __t.p.rep.instantane.ts]"), pg.evaluate("document.activeElement.id"))
        return r
    # la page de démonstration servie en http pour y poser le crochet ; aucun appel d'API ne part
    vus = []
    r = _navigateur(sc, api={}, vus=vus, crochet=E_CROCHET)
    assert vus == []
    assert r["direct"][0] is None and r["direct"][1].startswith("direct") and r["direct"][2:] == ("true", "true")
    assert "relevé 1 sur " in r["debut"][0] and r["debut"][0].startswith("lecture du ") and r["debut"][1] == "eDebut"
    assert "relevé 4 sur " in r["quatre"][0] and r["quatre"][1] == [3, True, True] and r["quatre"][3] == "eSuiv"
    assert r["quatre"][2].split(" · ")[0].replace("relevé de ", "").split(" ")[0][:5] in r["quatre"][0]
    assert "trou de 3 h 30 sauté" in r["trou"] and "relevé partiel" in r["partiel"]
    assert any("✖ disparu" in x for x in r["disparu"]) and r["apparu"]
    assert r["retour"] == (None, [None, 0, True], "eDirect")


def test_enregistreur_partiel_dans_l_etat_et_lecture_jusqu_a_la_fin():
    _, api, ent = _enregistrements(nb=6, partiels=(2,))

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.click("#eV16")
        pg.click("#eLire")
        vu = []
        for _ in range(60):
            pg.wait_for_timeout(25)
            t = _bandeau(pg)
            if t and t not in vu:
                vu.append(t)
        return vu, pg.get_attribute("#eLire", "aria-label"), pg.evaluate("document.activeElement.id"), pg.inner_text("#pEtat"), pg.get_attribute("#pEtat", "aria-live")
    vu, lire, foc, etat, live = _navigateur(sc, query="", api=api)
    assert [n for n in range(1, 7) if any(f"relevé {n} sur 6" in t for t in vu)] == [1, 2, 3, 4, 5, 6]
    assert any("relevé partiel" in t and "relevé 4 sur 6" in t for t in vu) and "fin de la fenêtre" in vu[-1] and "en pause" in vu[-1]
    assert lire == "Lire l’enregistrement" and foc == "eLire" and live == "off"


def test_enregistreur_en_boucle_sans_lecture_de_plus():
    """#3921 : la lecture reprend seule à la fin, sans requête au second tour ; pause et bascule l'arrêtent."""
    _, api, _ent = _enregistrements(nb=6)
    vus = []

    def relectures():
        return len([u for u in vus if "instantane" in str(u)])

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        r = {"avant": pg.get_attribute("#eBoucle", "aria-pressed")}
        pg.click("#eBoucle")
        r["apres"] = pg.get_attribute("#eBoucle", "aria-pressed")
        pg.click("#eV16")
        pg.click("#eLire")
        tours, dernier, n1 = 0, False, None
        for _ in range(400):
            pg.wait_for_timeout(25)
            t = _bandeau(pg) or ""
            if "relevé 6 sur 6" in t and not dernier:
                dernier, tours = True, tours + 1
                n1 = relectures() if tours == 1 else n1
            elif "relevé 2 sur 6" in t:
                dernier = False
            if tours == 3:
                break
        r["tours"], r["requetes"] = tours, (n1, relectures())
        pg.click("#eLire")
        pg.wait_for_timeout(2500)
        r["pause"] = _bandeau(pg)
        return r
    r = _navigateur(sc, query="", api=api, vus=vus)
    assert (r["avant"], r["apres"], r["tours"]) == ("false", "true", 3)
    assert r["requetes"][0] == r["requetes"][1] and r["requetes"][0] > 0
    assert "en pause" in r["pause"]


@pytest.mark.parametrize("code", [404, 503])
def test_enregistreur_saute_un_instantane_illisible_et_le_dit(code):
    _, api, ent = _enregistrements(nb=10, codes={6: code, 5: code})
    vus = []

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.click("#eDebut")
        pg.wait_for_timeout(300)
        pg.click("#eSuiv")
        pg.click("#eSuiv")
        pg.wait_for_timeout(300)
        r = [_bandeau(pg)]
        pg.click("#eSuiv")
        pg.wait_for_timeout(300)
        r.append(_bandeau(pg))
        pg.click("#ePrec")
        pg.wait_for_timeout(300)
        r.append(_bandeau(pg))
        return r
    r = _navigateur(sc, query="", api=api, vus=vus)
    assert "relevé 3 sur 10" in r[0] and "saut" not in r[0]
    assert "relevé 6 sur 10" in r[1] and "2 relevés illisibles ou retirés sautés" in r[1]
    assert "relevé 3 sur 10" in r[2] and "sautés" in r[2]
    assert len(_instants(vus)) == len(set(_instants(vus))) <= 10  # un instantané en panne n'est pas redemandé


def test_enregistreur_panne_generale_et_api_injoignable_bornees():
    for code, mot in ((503, "5 relevés de suite illisibles ou retirés"), (500, "5 relevés de suite illisibles ou retirés"), (502, "API DataScope injoignable")):
        _, api, ent = _enregistrements(nb=90, codes={i: code for i in range(1, 90)})
        vus = []

        def sc(pg):
            pg.click("#vuePaysage")
            pg.wait_for_timeout(300)
            pg.click("#eLire")
            pg.wait_for_timeout(700)
            return pg.inner_text("#eHeure"), _bandeau(pg), pg.locator("#topo svg.paysage").count(), pg.get_attribute("#eLire", "aria-label")
        t, b, n, lire = _navigateur(sc, query="", api=api, vus=vus)
        assert mot in t and b is None and n == 1 and lire == "Lire l’enregistrement"  # dit, et retour au direct
        assert len(_instants(vus)) <= 12, len(_instants(vus))


def test_enregistreur_cache_et_requetes_bornes():
    _, api, ent = _enregistrements(nb=90)
    vus = []

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.click("#eDebut")
        pg.wait_for_timeout(500)
        r = {"lot": len(_instants(vus)), "maxi": 0, "vols": 0}
        for _ in range(95):
            pg.evaluate("__t.E.pas(1)")
            pg.wait_for_timeout(30)
            e = pg.evaluate("(({cache, vols, file}) => [cache, vols, file])(__t.E.etat())")
            r["maxi"], r["vols"] = max(r["maxi"], e[0]), max(r["vols"], e[1])
        r["fin"] = pg.evaluate("[__t.E.etat().i, __t.E.etat().n]")
        r["total"] = len(_instants(vus))
        for _ in range(8):  # vus à l'instant : repris du cache
            pg.evaluate("__t.E.pas(-1)")
            pg.wait_for_timeout(20)
        r["retour"] = len(_instants(vus))
        return r
    r = _navigateur(sc, query="", api=api, vus=vus, crochet=E_CROCHET)
    assert 12 <= r["lot"] <= 14 and r["maxi"] <= 60 and r["vols"] <= 4
    assert r["fin"] == [89, 90] and r["total"] == 90 and r["retour"] == 90


def test_enregistreur_requetes_abandonnees_en_sortant():
    _, api, ent = _enregistrements(nb=30)
    tenues, vus = [], []

    def sc(pg):
        abandons = []
        pg.on("requestfailed", lambda q: abandons.append(q.url))
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        r = []
        for sortie in ("#eDirect", "#vueArbre"):
            del abandons[:], vus[:]
            pg.click("#eDebut")
            pg.wait_for_timeout(200)
            avant = (len(_instants(vus)), _bandeau(pg))
            pg.click(sortie)
            pg.wait_for_timeout(200)
            r.append((avant, len(abandons), pg.evaluate("[__t.E.etat().vols, __t.E.etat().file, __t.E.actif(), __t.p.rejoue]"), _bandeau(pg), len(_instants(vus))))
        return r
    for (nb, bandeau), abandons, etat, apres, total in _navigateur(sc, query="", api=api, vus=vus, retenir=("paysage/instantane/", tenues), crochet=E_CROCHET):
        assert nb == 4 and "chargement" in bandeau and abandons == 4 and etat == [0, 0, False, None] and apres is None and total == 4


def test_enregistreur_direct_ne_bouge_rien_et_401_termine():
    d, api, ent = _enregistrements(nb=12)
    vus = []

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.click("#eDebut")
        pg.wait_for_timeout(300)
        pg.evaluate("document.querySelector('#topo svg').dataset.t = '1'; document.querySelector('#pBarre .pbCases').dataset.t = '1'; document.querySelector('#insp .sPhrase').dataset.t = '1'")
        n0 = [len([v for v in vus if v.startswith("paysage/chronologie")]), pg.evaluate("__t.E.etat().n"), pg.evaluate("__t.p.ts")]
        d["instantane"]["ts"] = _iso(d["epoch"] + 900)
        d["epoch"] += 900
        pg.click("#rafraichir")
        pg.wait_for_timeout(300)
        r = [pg.locator("[data-t]").count(), n0 == [len([v for v in vus if v.startswith("paysage/chronologie")]), pg.evaluate("__t.E.etat().n"), pg.evaluate("__t.p.ts")]]
        for k in list(api):
            if k.startswith("paysage/instantane/"):
                api[k] = (401, {})
        pg.evaluate("__t.E.direct()")
        pg.wait_for_timeout(200)
        pg.click("#eDebut")
        pg.wait_for_timeout(300)
        return r + [pg.inner_text("#topo"), pg.is_visible("#pEnreg"), _bandeau(pg), pg.evaluate("[Object.keys(__t.p.noeuds).length, __t.E.actif(), __t.E.etat().cache, __t.p.chrono.rep]")]
    r = _navigateur(sc, query="", api=api, vus=vus, crochet=E_CROCHET)
    assert r[:2] == [3, True]
    assert "session requise" in r[2] and r[3:] == [False, None, [0, False, 0, None]]


@pytest.mark.parametrize("nb", [0, 1, 2])
def test_enregistreur_historique_court(nb):
    d, api, ent = _enregistrements(nb=max(nb, 1))
    if nb == 0:
        api["paysage"] = (200, {"disponible": False})

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        if nb == 0:
            return pg.is_visible("#pEnreg"), pg.inner_text("#topo")
        r = [pg.inner_text("#eHeure"), pg.get_attribute("#eLire", "aria-disabled")]
        for b in ("#eDebut", "#ePrec", "#eLire", "#eSuiv", "#eDirect"):
            pg.click(b, force=True)  # aria-disabled : la commande reste cliquable et dit pourquoi elle ne fait rien
            pg.wait_for_timeout(120)
            if b == "#ePrec":
                r.append(_bandeau(pg))
            if b == "#eLire":
                pg.click("#eLire", force=True)
        pg.wait_for_timeout(700)
        return r + [_bandeau(pg), pg.inner_text("#eAnnonce"), pg.locator("#topo svg.paysage").count()]
    r = _navigateur(sc, query="", api=api)
    if nb == 0:
        assert r[0] is False and "aucun instantané" in r[1]
    elif nb == 1:
        assert "un seul relevé" in r[0] and r[1] == "true" and r[2:4] == [None, None] and r[4] != "" and r[5] == 1
    else:
        assert "2 relevés" in r[0] and r[1] == "false" and "relevé 1 sur 2" in r[2] and r[3] is None and r[5] == 1


def test_enregistreur_selection_gardee_et_absente_a_cette_date():
    _, api, ent = _enregistrements(nb=10)

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.focus("#topo .nd[data-id='pop:famille:p05']")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(150)
        r, foc = [], []
        for n in (-1, 1):  # focus dans le graphe : gardé sur le nœud, devenu fantôme puis revenu
            pg.focus("#topo .nd[data-id='pop:famille:p05']")
            pg.evaluate(f"__t.E.pas({n})")
            pg.wait_for_timeout(250)
            foc.append(pg.evaluate("document.activeElement.dataset.id"))
        pg.evaluate("__t.E.direct()")
        assert foc == ["pop:famille:p05"] * 2, foc
        for _ in range(2):
            pg.click("#ePrec")
            pg.wait_for_timeout(250)
            r.append((pg.inner_text("#insp"), pg.get_attribute("#topo .nd[data-id='pop:famille:p05']", "class"), pg.evaluate("sessionStorage.getItem('datascope.selection')")))
        return r
    r = _navigateur(sc, query="", api=api, crochet=E_CROCHET)
    assert "Absent à cette date" in r[0][0] and "pop:famille:p05" in r[0][0] and "fantome" in r[0][1] and "sel" in r[0][1].split()
    assert "Absent" not in r[1][0] and "service-numero-5" in r[1][0] and "fantome" not in r[1][1] and "sel" in r[1][1].split()
    assert all(x[2] == '"pop:famille:p05"' for x in r)


@pytest.mark.parametrize("reduit", [False, True])
def test_enregistreur_transitions_et_mouvement_reduit(reduit):
    _, api, ent = _enregistrements(nb=10)

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.click("#eDebut")
        pg.wait_for_timeout(500)
        # animations du graphe juste après un pas, dans la même passe
        return pg.evaluate("""() => { __t.E.pas(1); const a = document.getAnimations().filter(x => x.effect && x.effect.target.closest('#topo') && !x.transitionProperty);
            return [a.length, Math.max(0, ...a.map(x => x.effect.getTiming().duration))]; }"""), pg.locator("#topo .nd .badge").count()
    (n, duree), badges = _navigateur(sc, query="", api=api, crochet=E_CROCHET, reduced_motion="reduce" if reduit else "no-preference")
    assert badges > 0
    assert (n, duree) == (0, 0) if reduit else (n > 0 and duree == 300)


# travail étalon (1 500 textes SVG créés et mis en page) : ~31 ms au repos sur le poste de référence, où un pas en prend ~58
ETALON = """() => { const t0 = performance.now(), N = 'http://www.w3.org/2000/svg', s = document.createElementNS(N, 'svg'); document.body.appendChild(s);
  for (let i = 0; i < 1500; i++) { const x = document.createElementNS(N, 'text'); x.setAttribute('x', i % 900); x.setAttribute('y', i % 700); x.textContent = 'repère ' + i; s.appendChild(x); }
  s.getBBox(); s.remove(); return performance.now() - t0; }"""


def test_enregistreur_pas_sans_gel_sur_le_graphe_maximal():
    """Critère 3 : un pas < 100 ms. Machine chargée : la durée est rapportée à un étalon mesuré juste avant chaque pas
    (100 ms ≈ 3,2 étalons au repos ; ~2 mesurés, chargé ou non) ; un seul nouvel essai."""
    _, api, ent = _enregistrements(nb=60, jours=26, grand=True)

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        pg.click("#eF30")
        pg.wait_for_timeout(400)
        pg.click("#eDebut")
        pg.wait_for_timeout(1500)
        t, etalons = [], []
        for _ in range(10):
            etalons.append(pg.evaluate(ETALON))
            t.append(pg.evaluate("() => { const t0 = performance.now(); __t.E.pas(1); return performance.now() - t0; }"))
            pg.wait_for_timeout(400)
        return t, etalons, pg.evaluate("[__t.E.etat().i, __t.E.etat().n]"), pg.locator("#topo .nd").count()
    for _ in range(2):
        t, etalons, (i, n), noeuds = _navigateur(sc, query="", api=api, crochet=E_CROCHET)
        assert i == 10 and n > 600 and noeuds >= 237
        tenu = statistics.median(t) < 100 or statistics.median(x / e for x, e in zip(t, etalons)) < 3.2
        if tenu:
            break
    assert tenu, (t, etalons)


def test_evolution_badges_et_comparaisons():
    d, api, ent = _enregistrements(nb=20, jours=9)
    d["difference_24h"] = {"apparus": ["asn:64496"], "disparus": ["pop:famille:balayage_web", "cible:parti.demo.test", "cve:CVE-2099-10009"], "hausses": [
        {"id": "pop:famille:p01", "metrique": "adresses", "de": 1000, "a": 1910}], "baisses": [{"id": "pop:famille:p01", "metrique": "bans", "de": 90, "a": 30},
        {"id": "infra:box-demo", "metrique": "bans", "de": 90, "a": 30}], "rotation_levee": [], "rotation_tombee": [], "tronque": False, "reference_ts": "x",
        "reference_epoch": d["epoch"] - 86400, "reference_partiel": False, "ecart_s": 86400}
    vus = []
    BADGES = "l => l.map(g => [g.dataset.id, [...g.querySelectorAll('.badge')].map(t => t.textContent).join('+')]).filter(x => x[1])"

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        r = {"b24": dict(pg.eval_on_selector_all("#topo .nd", BADGES)), "comp": pg.inner_text("#pComp"), "nb": len(vus),
             "chevauche": pg.evaluate(MESURES.replace(".nd .lbl, .nd .sous", ".nd .lbl, .nd .sous, .nd .badge"))["chevauche"],
             "dehors": pg.evaluate("""() => { const s = document.querySelector('#topo svg').getBoundingClientRect(); return [...document.querySelectorAll('#topo .badge')].filter(t => { const b = t.getBoundingClientRect(); return b.left < s.left || b.right > s.right; }).length; }"""),
             "contraste": pg.evaluate(CONTRASTE.replace("#topo .lbl,", "#topo .badge, #topo .lbl,")), "legende": pg.inner_text("#pLegende"),
             "fantome": pg.eval_on_selector_all("#topo .fantome .f", "l => l.map(f => getComputedStyle(f).stroke)"),
             "colle": pg.eval_on_selector_all("#topo .nd", """l => l.filter(g => { const b = g.querySelector('.badge'), f = g.querySelector('.f'); if (!b) return false;
                 const x = b.getBoundingClientRect(), y = f.getBoundingClientRect(); return x.left < y.right + 1 && x.right > y.left - 1 && x.top < y.bottom && x.bottom > y.top; }).map(g => g.dataset.id)""")}
        pg.click("#eEvo")
        pg.wait_for_timeout(150)
        r["sans"] = (pg.locator("#topo .badge, #topo .fantome").count(), "✚ apparues" in pg.inner_text("#insp") or "▲" in pg.inner_text("#insp"), pg.get_attribute("#eEvo", "aria-pressed"))
        pg.click("#eEvo")
        pg.click("#eC7j")
        pg.wait_for_timeout(400)
        r["b7"] = dict(pg.eval_on_selector_all("#topo .nd", BADGES))
        r["comp7"] = (pg.inner_text("#pComp"), pg.inner_text("#insp"), pg.get_attribute("#eC7j", "aria-pressed"))
        r["req"] = [v for v in vus if v.startswith("paysage/difference")]
        pg.click("#rafraichir")
        pg.wait_for_timeout(300)
        pg.click("#eC24h")
        pg.click("#eC7j")
        pg.wait_for_timeout(200)
        r["req2"] = len([v for v in vus if v.startswith("paysage/difference")])
        pg.click("#eCdate")
        pg.wait_for_timeout(300)
        r["date"] = (pg.is_visible("#eDate"), pg.input_value("#eDate") != "", pg.inner_text("#pComp"))
        pg.fill("#eDate", "2001-01-01T00:00")
        pg.dispatch_event("#eDate", "change")
        pg.wait_for_timeout(300)
        r["vieille"] = pg.inner_text("#pComp")
        r["large"] = [v for v in vus if v.startswith("paysage/chronologie")]
        # relecture : le relevé précédent d'abord ; « 24 h » à la demande, relatif à l'instant affiché
        pg.click("#ePrec")
        pg.wait_for_timeout(400)
        r["pas"] = (pg.inner_text("#pComp"), pg.get_attribute("#eCpas", "aria-pressed"), pg.is_visible("#eDate"))
        pg.click("#eC24h")
        pg.wait_for_timeout(700)
        r["rejeu24"] = (pg.inner_text("#pComp"), dict(pg.eval_on_selector_all("#topo .nd", BADGES)).get("pop:famille:p01"), [v for v in vus if v.startswith("paysage/difference")][-1])
        api["paysage/difference"] = (404, {})
        pg.click("#ePrec")
        pg.wait_for_timeout(700)
        r["panne"] = (pg.inner_text("#pComp"), pg.locator("#topo .badge").count())
        return r
    r = _navigateur(sc, query="", api=api, vus=vus)
    assert r["b24"] == {"asn:64496": "✚ apparu", "pop:famille:p01": "▲ en hausse+▼ en baisse", "infra:box-demo": "▼ en baisse",
                        "pop:famille:balayage_web": "✖ disparu", "cible:parti.demo.test": "✖ disparu", "cve:CVE-2099-10009": "✖ disparu"}
    assert "24 h plus tôt" in r["comp"] and r["chevauche"] == [] and r["dehors"] == 0 and r["contraste"] >= 4.5
    assert set(r["fantome"]) == {"rgb(159, 179, 214)"} and r["colle"] == []
    assert "populations 6" in r["legende"]  # un fantôme ne compte pas
    assert r["sans"] == (0, True, "false")
    assert r["b7"].get("pop:famille:p01") == "✚ apparu" and r["b7"].get("pop:famille:messagerie") == "✖ disparu" == r["b7"].get("asn:64999")
    assert "7 j plus tôt" in r["comp7"][0] and "depuis 7 j" in r["comp7"][1] and r["comp7"][2] == "true"
    assert len(r["req"]) == 1 == r["req2"] and ent[0]["ts"].replace(":", "%3A") in r["req"][0]
    assert r["date"][:2] == (True, True) and "plus tôt" in r["date"][2] and "plus tôt" in r["vieille"]
    assert len(r["large"]) == 2 and "differences=12" in r["large"][1]  # 8 jours, puis 30 quand une date est demandée
    assert "30 min plus tôt" in r["pas"][0] and r["pas"][1:] == ("true", False)
    assert "plus tôt" in r["rejeu24"][0] and r["rejeu24"][1] == "✚ apparu" and "a=" + ent[1]["ts"].replace(":", "%3A") in r["rejeu24"][2]
    assert "comparaison non lue" in r["panne"][0] and r["panne"][1] == 0


def test_evolution_sans_precedent_aucun_badge():
    _, api, ent = _enregistrements(nb=4)
    for k, v in api.items():
        if k.startswith("paysage/instantane/"):
            v[1]["difference"] = {"apparus": ["pop:famille:p01"], "disparus": ["pop:famille:px"], "sans_precedent": "premier"}

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.click("#eDebut")
        pg.wait_for_timeout(300)
        r = [pg.locator("#topo .badge, #topo .fantome").count(), pg.inner_text("#pComp"), pg.inner_text("#insp")]
        pg.click("#eSuiv")
        pg.wait_for_timeout(300)
        return r + [pg.inner_text("#pComp")]
    r = _navigateur(sc, query="", api=api)
    assert r[0] == 0 and "premier relevé enregistré" in r[1] and "✚ apparues" not in r[2]
    assert "comparé au relevé de " in r[3]  # ensuite, les deux graphes affichés sont comparés


def test_enregistreur_fenetre_30j_et_curseur():
    _, api, ent = _enregistrements(nb=20, jours=20)
    vus = []

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        r = [pg.evaluate("__t.E.etat().n"), pg.locator("#eBande .r").count()]
        pg.click("#eF30")
        pg.wait_for_timeout(400)
        r += [pg.evaluate("__t.E.etat().n"), pg.get_attribute("#eF30", "aria-pressed"), len([v for v in vus if v.startswith("paysage/chronologie")])]
        b = pg.locator("#eCurseur").bounding_box()
        for x in (.8, .6, .5, .3):  # glissé : la date suit, une seule lecture au repos
            pg.mouse.move(b["x"] + b["width"] * x, b["y"] + 10)
            pg.mouse.down() if x == .8 else None
            pg.wait_for_timeout(20)
        n = len(_instants(vus))
        pg.mouse.up()
        pg.wait_for_timeout(500)
        i = pg.evaluate("__t.E.etat().i / __t.E.etat().n")
        r += [n, .2 < i < .4, _bandeau(pg)]
        pg.focus("#eCurseur")
        av = pg.evaluate("__t.E.etat().i")
        for t in ("ArrowRight", "ArrowRight", "ArrowLeft", "PageDown"):
            pg.keyboard.press(t)
            pg.wait_for_timeout(250)
        r += [pg.evaluate("__t.E.etat().i") - av, pg.get_attribute("#eCurseur", "aria-valuetext")]
        pg.click("#eF48")
        pg.wait_for_timeout(400)
        r += [pg.evaluate("[__t.E.etat().i, __t.p.ts === __t.E.etat().liste[0].ts]")]
        pg.focus("#eCurseur")
        pg.keyboard.press("End")
        pg.wait_for_timeout(200)
        return r + [_bandeau(pg)]
    r = _navigateur(sc, query="", api=api, vus=vus, crochet=E_CROCHET)
    assert 20 < r[0] == r[1] < 60 and r[2] > 400 and r[3] == "true" and r[4] == 2
    assert r[5] <= 1 and r[6] is True and r[7].startswith("lecture du ")
    assert r[8] == 1 - 12 and " sur " in r[9] and r[10] == [0, True] and r[11] is None


def test_enregistreur_annonces_espacees_et_compteurs_au_temps_lu():
    _, api, ent = _enregistrements(nb=40)

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.evaluate("window.__dit = []; new MutationObserver(() => __dit.push(document.getElementById('eAnnonce').textContent)).observe(document.getElementById('eAnnonce'), {childList: true, characterData: true, subtree: true})")
        pg.click("#eV16")
        pg.click("#eLire")
        pg.wait_for_timeout(2600)
        n, i = pg.evaluate("__dit.length"), pg.evaluate("__t.E.etat().i")
        pg.click("#eLire")
        pg.wait_for_timeout(300)
        k = pg.evaluate("__t.E.etat().i")
        return n, i, k, pg.inner_text("#pBarre .pbCase:nth-child(4) b"), pg.get_attribute("#eAnnonce", "aria-live")
    n, i, k, adr, live = _navigateur(sc, query="", api=api, crochet=E_CROCHET)
    assert n <= 2 and i >= 8 and live == "polite"
    assert adr.replace("\u202f", "").replace(" ", "") == str(12000 - 10 * (39 - k))


@pytest.mark.parametrize("largeur", [1280, 400])
def test_enregistreur_tient_dans_la_page(largeur):
    tactile = {"has_touch": True, "is_mobile": True} if largeur == 400 else {}

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.evaluate("document.getElementById('eC7j').click(); document.getElementById('eCdate').click()")
        pg.wait_for_timeout(200)
        r = {"deborde": [_debordement(pg)]}
        for _ in range(12):
            pg.click("#ePrec")
            pg.wait_for_timeout(60)
        pg.wait_for_timeout(450)
        r["deborde"].append(_debordement(pg))
        r["petit"] = pg.eval_on_selector_all("#pEnreg *, #eBandeau", "l => l.filter(e => e.offsetParent && !e.classList.contains('horsVue') && [...e.childNodes].some(n => n.nodeType === 3 && n.data.trim()) && parseFloat(getComputedStyle(e).fontSize) < 13.5).map(e => e.id)")
        r["cibles"] = pg.eval_on_selector_all("#pEnreg button, #pEnreg input", "l => l.filter(e => e.offsetParent).map(e => [e.id, e.getBoundingClientRect()]).filter(x => x[1].width < 40 || x[1].height < 40).map(x => x[0])")
        r["contraste"] = pg.evaluate(CONTRASTE.replace("#topo .lbl, #topo .sous, #topo .col, #pLegende label span", "#pEnreg button, #pComp, #eHeure"))
        r["chevauche"] = pg.evaluate(MESURES.replace(".nd .lbl, .nd .sous", ".nd .lbl, .nd .sous, .nd .badge"))["chevauche"]
        _capture(pg, f"paysage-t7-demo-{largeur}-lecture.png")  # en dernier : une capture pleine page retire l'émulation du doigt
        return r
    r = _navigateur(sc, largeur=largeur, **tactile)
    assert r["deborde"] == [False, False] and r["petit"] == [] and r["contraste"] >= 4.5 and r["chevauche"] == []
    assert largeur != 400 or r["cibles"] == []


# --- tâche 7, relecture (tour 1) --------------------------------------------------------------------------------

def test_focus_reste_dans_le_graphe_apres_une_disparition_sans_fantome():
    _, api, ent = _enregistrements(nb=12)

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.click("#eEvo")  # sans badges : pas de fantôme
        pg.evaluate("__t.E.pas(-1); __t.E.pas(-1)")
        pg.wait_for_timeout(300)
        pg.focus("#topo .nd[data-id='pop:famille:p05']")
        r = []
        for _ in range(4):
            pg.evaluate("__t.E.pas(-1)")
            pg.wait_for_timeout(250)
            r.append(pg.evaluate("[document.activeElement.tagName, !!document.activeElement.closest('#topo')]"))
        # plus aucun nœud à dessiner : le focus reste sur le cadre, puis revient au graphe
        pg.evaluate("__t.rejouer({ts: 'vide', epoch: 1, graphe: {noeuds: [], aretes: []}, compteurs: {}}, null)")
        r.append(pg.evaluate("document.activeElement.id"))
        pg.evaluate("__t.E.pas(-1)")
        pg.wait_for_timeout(250)
        r.append(pg.evaluate("document.activeElement.tagName"))
        return r
    r = _navigateur(sc, query="", api=api, crochet="{E:Enregistreur,p:paysage,rejouer:rejouerPaysage}")
    assert r == [["svg", True]] * 4 + ["topo", "svg"]


@pytest.mark.parametrize("largeur", [1280, 400])
def test_selection_absente_dite_au_bandeau_et_annoncee(largeur):
    _, api, ent = _enregistrements(nb=10)

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.evaluate("document.querySelector(\"#topo .nd[data-id='pop:famille:p05']\").dispatchEvent(new MouseEvent('click', {bubbles: true}))")
        pg.wait_for_timeout(150)
        if largeur == 400:
            pg.click("#panInsp .fermer")
        r = [pg.is_visible("#panInsp") == (largeur == 1280)]
        for _ in range(2):
            pg.click("#ePrec")
            pg.wait_for_timeout(3000)
            r.append((_bandeau(pg), pg.inner_text("#eAnnonce")))
        pg.click("#ePrec")
        pg.wait_for_timeout(300)
        r.append(_bandeau(pg))
        pg.evaluate("document.querySelector(\"#topo .nd[data-id='pop:famille:p01']\").dispatchEvent(new MouseEvent('click', {bubbles: true}))")
        pg.wait_for_timeout(150)
        r.append(_bandeau(pg))
        return r, _debordement(pg)
    (ok, absent, present, encore, autre), deborde = _navigateur(sc, query="", api=api, largeur=largeur)
    m = "sélection absente à cette date"
    assert ok and m in absent[0] and m in absent[1] and m not in present[0] and m not in present[1]
    assert m in encore and m not in autre and not deborde


def test_reponse_tronquee_sautee_et_erreur_persistante_contournee():
    for panne, mot in ((lambda c: (200, '{"ts": "2026'), "illisible"), (lambda c: (500, {}), "en erreur"), (lambda c: (502, {}), "injoignable")):
        _, api, ent = _enregistrements(nb=20)
        cle = "paysage/instantane/" + ent[15]["ts"].replace(":", "%3A")  # cinquième relevé de la fenêtre
        api[cle] = panne(api[cle])
        vus = []

        def sc(pg):
            pg.click("#vuePaysage")
            pg.wait_for_timeout(300)
            pg.click("#eDebut")
            pg.wait_for_timeout(400)
            t = []
            for _ in range(6):
                pg.click("#eSuiv")
                pg.wait_for_timeout(200)
                t.append(_bandeau(pg))
            return t
        t = _navigateur(sc, query="", api=api, vus=vus)
        assert "relevé 4 sur 20" in t[2] and any("sauté" in x and mot in x and "relevé 6 sur 20" in x for x in t), (mot, t)
        assert "relevé 7 sur 20" in "".join(t), (mot, t)
        assert mot == "injoignable" or not any("injoignable" in x for x in t)
        assert len([v for v in _instants(vus) if ent[15]["ts"][:19].replace(":", "%3A") in v]) <= 3


def test_lignes_de_lecture_vivantes_a_l_arret():
    _, api, ent = _enregistrements(nb=12)
    api["paysage/tendance/pop%3Afamille%3Ap01"] = (200, {"points": [], "illisibles": 0})
    VIFS = "['#pEtat', '#pBarre .pLecture', '#pTendance .tNote'].map(s => document.querySelector(s).getAttribute('aria-live'))"

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.focus("#topo .nd[data-id='pop:famille:p01']")
        pg.keyboard.press("Enter")
        pg.click("#eV16")
        pg.click("#eLire")
        pg.wait_for_timeout(700)
        r = [pg.evaluate(VIFS)]
        pg.click("#eLire")
        pg.wait_for_timeout(200)
        r.append(pg.evaluate(VIFS))
        pg.click("#eLire")
        pg.wait_for_timeout(2500)  # jusqu'à la fin de la fenêtre
        r.append(pg.evaluate(VIFS))
        pg.click("#eDirect")
        pg.wait_for_timeout(200)
        return r + [pg.evaluate(VIFS)]
    r = _navigateur(sc, query="", api=api)
    assert r[0] == ["off"] * 3 and r[1] == r[2] == ["off", "polite", "polite"]  # #pEtat : en relecture, l'enregistreur annonce seul
    assert r[3] == ["polite"] * 3


def test_viser_puis_lire_avant_le_chargement_part_du_point_vise():
    _, api, ent = _enregistrements(nb=40)

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        r = []
        for _ in range(2):  # depuis le direct, puis depuis une relecture
            pg.evaluate("__t.E.viser(__t.E.etat().liste[20].epoch); __t.E.lecture()")
            pg.wait_for_timeout(500)
            r.append(pg.evaluate("[__t.E.etat().i, __t.E.enCours()]"))
            pg.evaluate("__t.E.pause(); __t.E.rembobiner()")
            pg.wait_for_timeout(300)
        pg.evaluate("__t.E.viser(__t.E.etat().liste[30].epoch); __t.E.pas(1)")
        pg.wait_for_timeout(400)
        return r + [pg.evaluate("__t.E.etat().i")]
    assert _navigateur(sc, query="", api=api, crochet=E_CROCHET) == [[20, True], [20, True], 31]


def test_fenetre_30j_en_echec_revient_a_48h_et_le_dit():
    _, api, ent = _enregistrements(nb=20)

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        bonne, api["paysage/chronologie"] = api["paysage/chronologie"], (503, {})
        r = []
        for relecture in (False, True):
            if relecture:
                pg.click("#ePrec")
                pg.wait_for_timeout(300)
            pg.click("#eF30")
            pg.wait_for_timeout(400)
            r.append((pg.get_attribute("#eF30", "aria-pressed"), pg.get_attribute("#eF48", "aria-pressed"), _bandeau(pg) or pg.inner_text("#eHeure")))
        api["paysage/chronologie"] = bonne
        pg.click("#eF30")
        pg.wait_for_timeout(400)
        return r + [pg.get_attribute("#eF30", "aria-pressed")]
    r = _navigateur(sc, query="", api=api)
    for a, b, t in r[:2]:
        assert (a, b) == ("false", "true") and "30 jours" in t and "indisponible" in t
    assert "lecture du" in r[1][2] and r[2] == "true"


@pytest.mark.parametrize("vue", ["paysage", "arbre"])
def test_session_refusee_vide_aussi_ce_qui_est_cache(vue):
    _, api, ent = _enregistrements(nb=10)

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.focus("#topo .nd[data-id='pop:famille:p01']")
        pg.keyboard.press("Enter")
        pg.click("#eDebut")
        pg.wait_for_timeout(400)
        if vue == "arbre":
            pg.click("#vueArbre")
            pg.wait_for_timeout(200)
        avant = len(pg.evaluate("document.getElementById('pBarre').textContent"))
        api["paysage"] = (401, {})
        pg.click("#rafraichir")
        pg.wait_for_timeout(3000)
        return avant, pg.evaluate("""['pEtat', 'pBarre', 'pLegende', 'pAideC', 'pAideT', 'eBandeau', 'pComp', 'eHeure', 'eBande', 'eAnnonce'].map(i => {
            const e = document.getElementById(i); return e.textContent.length + e.children.length; })"""), pg.inner_text("#insp"), \
            pg.get_attribute("#eCurseur", "aria-valuetext"), pg.evaluate("[__t.E.etat().n, __t.E.etat().cache, Object.keys(__t.p.noeuds).length, __t.p.vus]")
    avant, textes, insp, val, etat = _navigateur(sc, query="", api=api, crochet=E_CROCHET)
    assert avant > 100 and textes == [0] * 10 and "adresses" not in insp and not val and etat == [0, 0, 0, None]


def test_lecture_arretee_par_une_panne_relance_la_comparaison_et_garde_la_note():
    _, api, ent = _enregistrements(nb=40, codes={i: 503 for i in range(4, 34)})
    vus = []

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(300)
        pg.click("#eDebut")
        pg.wait_for_timeout(400)
        pg.evaluate("__t.evo.modeR = '24h'")
        pg.click("#eV16")
        pg.click("#eLire")
        pg.wait_for_timeout(2500)
        return _bandeau(pg), pg.inner_text("#pComp"), pg.inner_text("#eAnnonce"), [v for v in vus if "difference?" in v], pg.evaluate("__t.E.etat().i"), pg.evaluate("__t.E.enCours()")
    b, comp, dit, req, i, lit = _navigateur(sc, query="", api=api, crochet=E_CROCHET, vus=vus)
    assert i == 5 and not lit and "5 relevés de suite illisibles ou retirés" in b and "relevé 6 sur 40" in b and "5 relevés de suite" in dit
    assert "arrêt de la lecture" not in comp and "aucun relevé d’au moins 12 h" in comp


@pytest.mark.parametrize("partiel", [False, True])
def test_compteurs_visibles_avec_le_menu_lateral_a_1280x900(partiel):
    _, api, ent = _enregistrements(nb=90, grand=True, trou=(10, 11, 12), partiels=(0, 1, 2) if partiel else (), jours=6)
    api["paysage"][1]["instantane"]["partiel"] = partiel

    def sc(pg):
        pg.click("#vuePaysage")
        pg.wait_for_timeout(400)
        r = [pg.evaluate("getComputedStyle(document.querySelector('.principal')).marginLeft")]
        for action in (None, "#ePrec", "#eC24h"):
            if action:
                pg.click(action)
                pg.wait_for_timeout(600)
            r.append(pg.evaluate("[Math.ceil(document.getElementById('pBarre').getBoundingClientRect().bottom), scrollY, document.getElementById('topo').clientHeight]"))
        _capture(pg, "paysage-t7-max-1280-menu.png")
        return r
    r = _navigateur(sc, query="", api=api, largeur=1280, hauteur=900)
    assert r[0] == "220px" and all(b <= 900 and y == 0 and h >= 260 for b, y, h in r[1:]), r


# --- vue « Carte » (tâche 7b) --------------------------------------------------------------------------------

def _avec_pays(nb=40, **k):
    """Les enregistrements avec deux vrais pays (US partout, VN absent des indices impairs) et un pays sans position (XK)."""
    d, api, ent = _enregistrements(nb=nb, **k)
    graphes = [api[c][1]["graphe"] for c in api if c.startswith("paysage/instantane/")] + [d["instantane"]["graphe"]]
    for rang, g in enumerate(graphes):
        impair = rang % 2 and rang < len(graphes) - 1
        for c, part in [("US", 50), ("XK", 10)] + ([] if impair else [("VN", 5)]):
            g["noeuds"].append({"id": "pays:" + c, "type": "pays", "libelle": c, "metriques": {}})
            g["aretes"] = g["aretes"] + [{"de": "pop:famille:p01", "vers": "pays:" + c, "type": "ORIGINE", "poids": part}]
    return d, api, ent


C_ETAT = """() => ({pouls: document.querySelectorAll('#topo svg[data-sbxp="carte"]').length, quand: document.querySelectorAll('#topo [data-sbxp="quand"]').length,
  points: [...document.querySelectorAll('#topo .pt')].map(n => n.dataset.id).sort(), liste: [...document.querySelectorAll('#topo button.cP')].map(n => n.dataset.id)})"""


@pytest.mark.parametrize("largeur", [1280, 400])
def test_carte_demo(largeur):
    def sc(pg):
        pg.click("#vueCarte")
        pg.mouse.move(2, 2)  # le survol de la carte fige le pouls
        pg.wait_for_function("document.querySelectorAll('#topo [data-sbxp=\"quand\"]').length === 1")
        r = {"etat": pg.evaluate(C_ETAT), "texte": pg.inner_text("#topo"), "deborde": _debordement(pg), "vie": pg.is_visible("#topo [data-sbxp='vie']")}
        _capture(pg, f"paysage-t7b-demo-{largeur}-direct.png")
        pg.wait_for_function("document.querySelector('#topo .cQuand').textContent.includes('il y a')", timeout=12000)
        _capture(pg, f"paysage-t7b-demo-{largeur}-recul.png")
        r["petit"] = pg.eval_on_selector_all("#topo *", "l => l.filter(e => e.offsetParent && [...e.childNodes].some(n => n.nodeType === 3 && n.data.trim()) && parseFloat(getComputedStyle(e).fontSize) < 13.5).map(e => e.className + ':' + e.textContent)")
        r["haut"] = pg.eval_on_selector_all("#topo button.cP", "l => Math.min(...l.map(b => b.getBoundingClientRect().height))")
        pg.focus("#topo .pt[tabindex='0']")
        a = pg.evaluate("document.activeElement.dataset.id")
        pg.keyboard.press("ArrowRight")
        r["fleche"] = (a, pg.evaluate("document.activeElement.dataset.id"), pg.inner_text("#topo .cLit"))
        pg.keyboard.press("Home")
        pg.keyboard.press("Enter")
        pg.wait_for_timeout(200)
        r["insp"], r["choisi"] = pg.inner_text("#insp"), pg.evaluate(C_ETAT)
        _capture(pg, f"paysage-t7b-demo-{largeur}-fiche.png")
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(150)
        r["repos"] = pg.evaluate("document.querySelectorAll('#topo .pt.sel').length")
        pg.click("#eDebut")
        pg.wait_for_timeout(300)
        r["lecture"], r["bandeau"] = pg.evaluate(C_ETAT), _bandeau(pg)
        _capture(pg, f"paysage-t7b-demo-{largeur}-lecture.png")
        pg.click("#vuePaysage")
        pg.wait_for_timeout(150)
        r["garde"] = _bandeau(pg), pg.locator("#topo svg.paysage").count()
        pg.click("#vueCarte")
        pg.click("#eDirect")
        pg.wait_for_timeout(300)
        r["fin"], r["deborde2"] = pg.evaluate(C_ETAT), _debordement(pg)
        pg.click("#vueBulles")
        r["bulles"] = pg.locator("#topo svg.bulles").count(), pg.locator("#topo .cMonde").count(), pg.is_visible("#pEnreg")
        return r
    r = _navigateur(sc, largeur=largeur)
    assert not r["deborde"] and not r["deborde2"] and r["petit"] == [] and r["haut"] >= 40
    assert r["etat"]["pouls"] == 1 and r["etat"]["quand"] == 1 and r["vie"]
    assert "pays:US" in r["etat"]["points"] and "pays:XK" not in r["etat"]["points"] and "pays:XK" in r["etat"]["liste"]
    for t in ("estimation incomplète", "en nombre inconnu", "hors carte", "origine non mesurée : 1 population", "2 populations repliées"):
        assert t in r["texte"], t
    assert r["fleche"][0] == "pays:US" and r["fleche"][1] != "pays:US" and "estimation" in r["fleche"][2]
    for t in ("États-Unis", "Collecte : forge.demo.test", "Mandataires Exemple", "Tous pays confondus"):
        assert t in r["insp"], t
    assert r["choisi"]["pouls"] == 0 and r["repos"] == 0  # au repos seulement
    assert r["lecture"]["pouls"] == 0 and r["lecture"]["quand"] == 0 and "relevé 1 sur" in r["bandeau"]
    assert "pays:VN" not in r["lecture"]["liste"] and "pays:VN" in r["fin"]["liste"]  # chaque pas est son instantané
    assert "relevé 1 sur" in r["garde"][0] and r["garde"][1] == 1 and r["fin"]["pouls"] == 1
    assert r["bulles"] == (1, 0, False)


def test_carte_pilotee_par_l_enregistreur_focus_et_requetes_bornees():
    _, api, ent = _avec_pays()
    vus = []

    def sc(pg):
        pg.click("#vueCarte")
        pg.wait_for_function("__t.c.version > 0")
        r = {"req": len(_instants(vus)), "doublons": len(_instants(vus)) - len(set(_instants(vus)))}
        pg.click("#eDebut")
        pg.wait_for_timeout(500)
        pg.focus("#topo .pt[data-id='pays:US']")
        r["pas"] = []
        for _ in range(4):
            pg.evaluate("__t.E.pas(1)")
            pg.wait_for_timeout(120)
            e = pg.evaluate(C_ETAT)
            r["pas"].append((e["pouls"], "pays:VN" in e["liste"], pg.evaluate("document.activeElement.dataset.id"), pg.evaluate("__t.p.ts===__t.E.etat().ts")))
        pg.click("#eV16")
        pg.click("#eLire")
        pg.wait_for_timeout(400)
        r["lit"] = pg.evaluate(C_ETAT)["pouls"]
        pg.click("#eDirect")
        pg.wait_for_timeout(300)
        n = len(_instants(vus))
        pg.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
        pg.wait_for_timeout(400)
        r["encore"] = len(_instants(vus)) - n
        return r
    r = _navigateur(sc, query="", api=api, vus=vus, crochet="{E:Enregistreur,p:paysage,c:carte}", largeur=1280)
    assert 0 < r["req"] <= 12 and r["doublons"] == 0 and r["encore"] == 0 and r["lit"] == 0
    assert all(p == 0 and f == "pays:US" and juste for p, _, f, juste in r["pas"]) and {v for _, v, _, _ in r["pas"]} == {True, False}


@pytest.mark.parametrize("cas", ["reduit", "sans_scripts", "sans_origine", "refus", "partiel"])
def test_carte_degradee(cas):
    d, api, ent = _avec_pays() if cas != "sans_origine" else _enregistrements()
    if cas == "partiel":
        d["instantane"]["partiel"] = True

    def sc(pg):
        if cas == "sans_scripts":
            pg.route("**/pouls.js", lambda x: x.fulfill(status=404, body=""))
            pg.route("**/carte-monde.js", lambda x: x.fulfill(status=404, body=""))
        pg.click("#vueCarte")
        pg.wait_for_timeout(900)
        r = {"texte": pg.inner_text("#topo")}
        if cas == "refus":
            api["paysage"] = (401, {})
            pg.click("#rafraichir")
            pg.wait_for_timeout(500)
            r["apres"], r["mem"] = pg.inner_text("#topo"), pg.evaluate("[Object.keys(__t.c.pays).length, __t.c.pouls]")
        r["etat"] = pg.evaluate(C_ETAT)
        if cas == "reduit":
            a = pg.inner_text("#topo .cQuand")
            pg.wait_for_timeout(3500)
            r["fixe"] = a == pg.inner_text("#topo .cQuand")
        return r
    k = {"reduced_motion": "reduce"} if cas == "reduit" else {}
    r = _navigateur(sc, query="", api=api, crochet="{c:carte}", **k)
    if cas == "reduit":
        assert r["fixe"]
    elif cas == "sans_scripts":
        assert "fond de carte non chargé" in r["texte"] and "pays:US" in r["etat"]["liste"] and r["etat"]["pouls"] == 0
    elif cas == "sans_origine":
        assert "Aucune origine dans ce relevé" in r["texte"] and r["etat"]["liste"] == []
    elif cas == "refus":
        assert "session requise" in r["apres"] and r["etat"]["liste"] == [] and r["mem"] == [0, None]
    else:
        assert r["etat"]["pouls"] == 0 and "pays:US" in r["etat"]["liste"]


@pytest.mark.parametrize("largeur", [1280, 400])
def test_carte_clic_sur_la_carte(largeur):
    def sc(pg):
        pg.click("#vueCarte")
        pg.wait_for_timeout(600)
        b = pg.locator("#topo .pt[data-id='pays:BR'] .r").bounding_box()
        pg.mouse.click(b["x"] + b["width"] / 2 + 8, b["y"] + b["height"] / 2)
        pg.wait_for_timeout(200)
        return pg.inner_text("#insp"), pg.is_visible("#panInsp"), pg.locator("#topo .cP.sel").count()
    t, vis, sel = _navigateur(sc, largeur=largeur)
    assert "Brésil" in t and vis and sel == 1


@pytest.mark.parametrize("partiel", [False, True])
def test_carte_compteurs_visibles_avec_le_menu_lateral(partiel):
    d, api, ent = _avec_pays(nb=60)
    d["instantane"]["partiel"] = partiel

    def sc(pg):
        pg.click("#vueCarte")
        pg.wait_for_timeout(700)
        a = pg.evaluate("Math.ceil(document.getElementById('pBarre').getBoundingClientRect().bottom)")
        y = pg.evaluate("document.getElementById('pEnreg').getBoundingClientRect().top")
        pg.click("#ePrec")
        pg.wait_for_timeout(400)
        return a, pg.evaluate("Math.ceil(document.getElementById('pBarre').getBoundingClientRect().bottom)"), pg.evaluate("document.getElementById('pEnreg').getBoundingClientRect().top") - y
    r = _navigateur(sc, query="", api=api, largeur=1280, hauteur=900)
    assert r[0] <= 900 and r[1] <= 900, r


# --- relecture de la vue Carte (I1, I2, M1, M2, M3) ----------------------------------------------------------

def test_carte_rayon_exact_a_x16():
    """En relecture, le rayon calculé est tout de suite celui du relevé nommé : aucune valeur intermédiaire."""
    _, api, ent = _avec_pays()

    def sc(pg):
        pg.click("#vueCarte")
        pg.wait_for_function("window.TERRE && __t.c.version > 0")
        pg.mouse.move(2, 2)
        pg.click("#eDebut")
        pg.wait_for_timeout(400)
        pg.evaluate("""() => { window.ecarts = []; const lire = () => { const x = document.querySelector("#topo .pt[data-id='pays:US'] .r");
            if (x && __t.p.rejoue && __t.p.ts === __t.p.rejoue.instantane.ts) { const e = __t.est().pays.find(y => y.code === 'US');
              ecarts.push([__t.p.ts, Math.abs(parseFloat(getComputedStyle(x).r) - __t.r(e.n, __t.k()))]); } requestAnimationFrame(lire); }; lire(); }""")
        pg.click("#eV16")
        pg.click("#eLire")
        pg.wait_for_timeout(1500)
        return pg.evaluate("ecarts")
    mesures = _navigateur(sc, query="", api=api, largeur=1280, crochet="{E:Enregistreur,p:paysage,c:carte,est:estimerAffiche,r:rayonPays,k:echelleCarte}")
    assert len({ts for ts, _ in mesures}) >= 3 and max(e for _, e in mesures) < .01, max(e for _, e in mesures)


@pytest.mark.parametrize("cas", ["perime", "echec", "panne", "sain"])
def test_carte_pouls_jamais_direct_sur_un_releve_douteux(cas):
    d, api, ent = _avec_pays()
    if cas == "perime":
        d["age_s"] = 9000.0
    if cas == "panne":
        api["sources"] = (200, {"sources": [{"source": "paysage", "etat": "inaccessible", "motif": "droit refusé", "vu_le": None}]})

    def sc(pg):
        pg.click("#vueCarte")
        pg.mouse.move(2, 2)
        pg.wait_for_function("window.SbxPouls && __t.c.version > 0")
        pg.wait_for_timeout(200)
        if cas == "echec":
            api["paysage"] = (500, {})
            pg.click("#rafraichir")
            pg.wait_for_timeout(500)
        return pg.evaluate(C_ETAT), pg.inner_text("#topo .cQuand")
    e, quand = _navigateur(sc, query="", api=api, crochet="{c:carte}")
    if cas == "sain":
        assert e["pouls"] == 1 and "relevé de " in quand and "direct" not in quand
    else:
        assert e["pouls"] == 0 and quand == ""


def test_carte_premier_clic_depuis_le_paysage_garde_les_lectures():
    _, api, ent = _avec_pays()

    def sc(pg):
        lents = []
        pg.route("**/carte-monde.js", lambda x: lents.append(x))
        pg.click("#vuePaysage")
        pg.wait_for_function("__t.p.chrono.rep")
        pg.evaluate("window.avortes = 0; void (AbortController.prototype.abort = (f => function () { avortes++; return f.call(this); })(AbortController.prototype.abort))")
        pg.route("**/paysage/instantane/**", lambda x: (time.sleep(.15), x.fallback())[1])
        pg.click("#vueCarte")
        pg.wait_for_function("__t.c.ctl")
        lents[0].fulfill(path=str(PAGE.parent / "carte-monde.js"))
        pg.wait_for_function("window.TERRE")
        pg.wait_for_function("__t.c.version > 0", timeout=8000)
        return pg.evaluate("[avortes, Object.keys(__t.c.pays).length, !!document.querySelector('#topo .terre')]")
    a, n, terre = _navigateur(sc, query="", api=api, crochet="{p:paysage,c:carte}")
    assert a == 0 and n > 3 and terre


def test_carte_fiche_sans_reseau_et_trace():
    d, api, ent = _avec_pays()
    g = d["instantane"]["graphe"]
    g["aretes"] = [x for x in g["aretes"] if x["type"] != "SOURCE_DE"]
    for x in g["aretes"]:
        if x["vers"] == "pays:VN":
            x["poids"] = 0

    def sc(pg):
        pg.click("#vueCarte")
        pg.mouse.move(2, 2)
        pg.wait_for_function("window.SbxPouls && __t.c.version > 0")
        v = pg.inner_text("#topo .cP[data-id='pays:VN'] .v"), pg.evaluate("(__t.m(__t.est()) || []).map(x => x.code)")
        pg.click("#topo .cP[data-id='pays:VN']")
        pg.wait_for_timeout(200)
        return v, pg.inner_text("#insp"), pg.eval_on_selector("#topo .cP[data-id='pays:VN'] svg", "x => x.lastElementChild.getAttribute('class')")
    (v, codes), insp, derniere = _navigateur(sc, query="", api=api, crochet="{c:carte,m:paysMesures,est:estimerAffiche}")
    assert v == "moins de 1 %" and "VN" not in codes and "US" in codes and derniere == "t"
    assert "aucun réseau rendu (non mesuré)" in insp and "moins de 1 % adresses" not in insp
