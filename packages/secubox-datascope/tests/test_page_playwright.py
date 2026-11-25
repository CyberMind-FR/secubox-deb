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


def _servir(pg, api, crochet=None, reperes_lents=None):
    """Sert la page et reperes.js sur http://datascope.test/, l'API depuis `api` ({route: (code, corps)}) ; rien d'autre.

    `crochet` : expression exposée en window.__t depuis la fermeture de la page ; `reperes_lents` : liste où la requête de
    reperes.js est retenue (à libérer par le scénario)."""
    def repondre(route):
        if reperes_lents is not None and route.request.url.endswith("/reperes.js"):
            return reperes_lents.append(route)
        chemin = route.request.url.split("datascope.test", 1)[1].split("?")[0]
        if chemin.startswith("/api/v1/datascope/"):
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
                reperes_lents=None, **contexte):
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
            pg.goto(("file://" + str(PAGE) if api is None else _servir(pg, api, crochet, reperes_lents)) + query,
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
