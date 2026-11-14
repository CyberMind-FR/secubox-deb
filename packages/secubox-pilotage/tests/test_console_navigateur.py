# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3702 tâche 7 : la console de pilotage dans un vrai navigateur (Playwright). L'API est simulée par `page.route`, aux formes réelles
de api/main.py (catalogue, flotte, macros, exécutions, flux SSE) ; `?demo=1` sous file:// pour les captures et la démonstration."""
import concurrent.futures
import json
import pathlib
import time
import urllib.parse

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "pilotage" / "console" / "index.html"
BASE = "http://t.test"
MAINTENANT = int(time.time())
XSS = "<img src=x onerror=alert(1)>"


def _catalogue():
    defs = {"reboot": ([], True), "maj-paquets": ([], False), "installer": (["paquet"], True), "service-demarrer": (["unite"], False),
            "service-arreter": (["unite"], True), "service-redemarrer": (["unite"], False), "renommer": (["nom"], True),
            "renouveler": ([], True), "interface-distante": ([], True), "interface-locale": ([], True)}
    return [{"cle": k, "parametres": p, "forte": f, "macro": k != "renommer"} for k, (p, f) in sorted(defs.items())]


def _box(nom, *, en_ligne=True, vu_il_y_a=5, modele="Raspberry Pi 4 Model B", interface="locale", reseau="maillage", mem=812, cpu=12.5,
         swap=3, echecs=0):
    cle = f"{reseau}:{nom}"
    return {"cle": cle, "nom": nom, "reseau": reseau, "client": None if reseau == "maillage" else "client-1", "adresse": "192.0.2.10",
            "en_ligne": en_ligne, "vu_le": MAINTENANT - vu_il_y_a, "agent_version": "0.8.1", "mains_liees": False, "memoire_dispo_mo": mem,
            "swap_utilise_pct": swap, "cpu_pct": cpu, "services_en_echec": echecs, "boucles_24h": 0, "interface": interface, "modele": modele,
            "inventaire_le": MAINTENANT - 30, "inventaire_partiel": False, "materiel": "RPi" if "Raspberry" in (modele or "") else "autre",
            "cochable": en_ligne}


def _flotte():
    boxes = [_box("gk7"), _box("gk6", interface="distante", mem=None, cpu=None, swap=None),
             _box("gk12", en_ligne=False, vu_il_y_a=2 * 86400 + 600)]
    return {"boxes": boxes, "groupes": {"materiel": {"RPi": [b["cle"] for b in boxes]},
                                        "interface": {"legeres": ["maillage:gk6"], "locales": ["maillage:gk7", "maillage:gk12"]},
                                        "etat": {"en_ligne": ["maillage:gk7", "maillage:gk6"], "muettes": ["maillage:gk12"]}}}


MACROS = [
    {"id": "livree:mise-a-jour-sure", "nom": "Mise à jour sûre", "livree": True, "cibles": [], "programmation": None, "cree_le": 1,
     "maj_le": 1, "auteur": None,
     "etapes": [{"type": "releve", "duree_s": 60, "nom": "avant"},
                {"type": "condition", "mesure": "services_en_echec", "releve": "avant", "op": ">", "seuil": 0, "alors": "arreter"},
                {"type": "action", "action": "maj-paquets", "args": {}, "delai_s": 900},
                {"type": "releve", "duree_s": 60, "nom": "apres"},
                {"type": "comparer", "avant": "avant", "apres": "apres", "regle": "nouveau_service_en_echec", "seuil": 0}]},
    {"id": "m1", "nom": "Nuit tranquille", "livree": False, "cibles": ["maillage:gk6"], "programmation": {"quotidien": "03:00"},
     "cree_le": 1, "maj_le": 1, "auteur": "admin", "etapes": [{"type": "releve", "duree_s": 60, "nom": "diag"}]},
]


def _execution(ident=7, etat="en_cours", unite="secubox-portal"):
    return {"id": ident, "macro_id": "livree:mise-a-jour-sure", "macro_nom": "Mise à jour sûre",
            "cibles": [{"cle": "maillage:gk7", "nom": "gk7"}], "etat": etat, "acteur": "admin", "debut": MAINTENANT - 120, "fin": None,
            "raison": None,
            "etapes": [{"box": "maillage:gk7", "rang": 0, "type": "releve", "etat": "ok", "debut": MAINTENANT - 110, "fin": MAINTENANT - 50,
                        "resultat": {"memoire_dispo_mo": 640, "cpu_pct": 9.0, "swap_utilise_pct": 2, "services_en_echec": 1,
                                     "services": [unite], "inventaire_le": MAINTENANT - 50}},
                       {"box": "maillage:gk7", "rang": 1, "type": "condition", "etat": "en_cours", "debut": MAINTENANT - 40, "fin": None,
                        "resultat": None}] + [
                       {"box": "maillage:gk7", "rang": r, "type": t, "etat": "en_attente", "debut": None, "fin": None, "resultat": None}
                       for r, t in ((2, "action"), (3, "releve"), (4, "comparer"))]}


def _sse(nom, data):
    return f"event: {nom}\ndata: {json.dumps(data)}\n\n"


def _api_simulee(executions=None, detail=None, flux=None, ecritures=None):
    """Répondeur des routes /api/v1/pilotage/… : (statut, corps) ; `ecritures` : réponse des POST (statut, corps) par motif de chemin."""
    executions = executions if executions is not None else []

    def repondre(methode, chemin, requete):
        if methode == "GET" and chemin == "/catalogue":
            return 200, _catalogue()
        if methode == "GET" and chemin == "/flotte":
            return 200, _flotte()
        if methode == "GET" and chemin == "/macros":
            return 200, MACROS
        if methode == "GET" and chemin == "/executions":
            return 200, [{k: v for k, v in e.items() if k != "etapes"} for e in executions]
        if methode == "GET" and chemin.startswith("/executions/") and chemin.endswith("/flux"):
            return 200, flux or ""
        if methode == "GET" and chemin.startswith("/executions/"):
            return (200, detail) if detail is not None else (404, {"detail": "exécution inconnue"})
        if methode == "GET" and chemin.startswith("/boxes/") and chemin.endswith("/support"):
            return 200, []
        if methode == "GET" and chemin.startswith("/boxes/"):
            nom = urllib.parse.unquote(chemin.split("/")[2]).split(":")[-1]
            b = next(x for x in _flotte()["boxes"] if x["nom"] == nom)
            return 200, {**b, "inventaire": {}, "inventaire_tronques": 0, "services_en_echec_noms": ["secubox-portal"] if nom == "gk7" else []}
        for motif, rep in (ecritures or {}).items():
            if methode != "GET" and motif in chemin:
                return rep
        return 404, {"detail": "route inconnue du simulateur"}
    return repondre


def _nav(scenario, *, api=None, largeur=1440, hauteur=900, query="?demo=1", avant=None):
    """`api` : répondeur simulé (page servie sur http://t.test) ; sinon la page en file:// avec `query`. Rend (résultat, erreurs JS,
    dialogues natifs, requêtes [(méthode, url)])."""
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e), [], [], [])
            pg = nav.new_page(viewport={"width": largeur, "height": hauteur})
            erreurs, natifs, requetes = [], [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
            pg.on("request", lambda r: requetes.append((r.method, r.url)))
            if avant:
                avant(pg)
            if api is not None:
                def route(r):
                    u = urllib.parse.urlsplit(r.request.url)
                    if u.path == "/pilotage/console/":
                        return r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8"))
                    if u.path.startswith("/api/v1/pilotage/"):
                        chemin = u.path[len("/api/v1/pilotage"):]
                        statut, corps = api(r.request.method, chemin, r.request)
                        if isinstance(corps, str):
                            return r.fulfill(status=statut, content_type="text/event-stream", body=corps)
                        return r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
                    return r.fulfill(status=200, content_type="text/css" if u.path.endswith(".css") else "application/javascript", body="")
                pg.route(BASE + "/**", route)
                pg.goto(BASE + "/pilotage/console/" + (query if query != "?demo=1" else ""))
            else:
                pg.goto("file://" + str(PAGE) + query)
            pg.wait_for_timeout(700)
            r = scenario(pg, requetes)
            nav.close()
            return ("ok", r, erreurs, natifs, requetes)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=90)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1], res[2], res[3], res[4]


PANNEAUX_VISIBLES = """[...document.querySelectorAll('.zoomable')].filter(p => p.offsetParent !== null).map(p => p.id)"""


def test_console_1440_sans_debordement():
    def sc(pg, _):
        return (pg.evaluate("[document.documentElement.scrollWidth, innerWidth]"), pg.evaluate(PANNEAUX_VISIBLES),
                pg.is_visible("#demo"), pg.locator("#journal .ligne").count(), pg.inner_text("#pastille"))
    ((sw, iw), visibles, demo, lignes, pastille), erreurs, natifs, _ = _nav(sc)
    assert sw <= iw and sorted(visibles) == ["pan-box", "pan-flotte", "pan-journal", "pan-macros"]
    assert demo and lignes > 0 and "en ligne" in pastille and erreurs == [] and natifs == []


def test_console_420_un_panneau_agrandi():
    def sc(pg, _):
        return (pg.evaluate("[document.documentElement.scrollWidth, innerWidth]"), pg.evaluate(PANNEAUX_VISIBLES),
                pg.is_visible("nav[aria-label='Panneaux de la console']"))
    ((sw, iw), visibles, nav), erreurs, natifs, _ = _nav(sc, largeur=420)
    assert sw <= iw and len(visibles) == 1 and nav and erreurs == [] and natifs == []


def test_box_muette_non_cochable():
    def sc(pg, _):
        ligne = pg.locator("#flotte-liste label", has_text="gk12")
        return ligne.locator("input[type=checkbox]").is_disabled(), ligne.inner_text(), \
            pg.locator("#flotte-liste label", has_text="gk7").locator("input").is_disabled()
    (muette, texte, active), erreurs, _, _ = _nav(sc, api=_api_simulee())
    assert muette and "muette 2 j" in texte and not active and erreurs == []


def test_zoom_echap_garde_le_flux():
    ex = _execution()
    flux = _sse("etat", {"execution": 7, "connecte": True, "etat": "en_cours"})

    def sc(pg, requetes):
        n_flux = sum(1 for m, u in requetes if u.endswith("/executions/7/flux"))
        lignes = pg.locator("#journal .ligne").count()
        pg.click("[aria-label='Agrandir le panneau Journal en direct']")
        agrandi = pg.evaluate(PANNEAUX_VISIBLES)
        filtres = pg.is_visible("#journal-filtres")
        pg.keyboard.press("Escape")
        visibles = pg.evaluate(PANNEAUX_VISIBLES)
        return (n_flux, sum(1 for m, u in requetes if u.endswith("/executions/7/flux")), lignes, pg.locator("#journal .ligne").count(),
                agrandi, filtres, visibles)
    (avant, apres, l_avant, l_apres, agrandi, filtres, visibles), erreurs, _, _ = _nav(sc, api=_api_simulee([ex], ex, flux))
    assert avant == 1 and apres == 1 and l_avant == l_apres > 0
    assert agrandi == ["pan-journal"] and filtres and len(visibles) == 4 and erreurs == []


def test_zoom_chaque_panneau_puis_reduire():
    def sc(pg, requetes):
        vus = {}
        n = len(requetes)
        for bouton in pg.locator("button[aria-label^='Agrandir le panneau']").all():
            bouton.click()
            vus[bouton.get_attribute("aria-label")] = (pg.evaluate(PANNEAUX_VISIBLES), pg.is_visible("nav[aria-label='Panneaux de la console']"))
            pg.click("#reduire")
        return vus, pg.evaluate(PANNEAUX_VISIBLES), len(requetes) - n, pg.evaluate("sessionStorage.getItem('pilotage.console.zoom')")
    (vus, fin, nouvelles, garde), erreurs, _, _ = _nav(sc, api=_api_simulee())
    assert len(vus) == 4 and all(len(v[0]) == 1 and v[1] for v in vus.values())
    assert vus["Agrandir le panneau Flotte"][0] == ["pan-flotte"] and vus["Agrandir le panneau Macros"][0] == ["pan-macros"]
    assert len(fin) == 4 and nouvelles == 0 and garde == "entier" and erreurs == []


def test_zoom_garde_dans_la_session():
    def avant(pg):
        pg.add_init_script("try { sessionStorage.setItem('pilotage.console.zoom', 'pan-macros'); } catch (e) {}")
    visibles, erreurs, _, _ = _nav(lambda pg, _: pg.evaluate(PANNEAUX_VISIBLES), api=_api_simulee(), avant=avant)
    assert visibles == ["pan-macros"] and erreurs == []


def test_journal_texte_brut():
    ex = _execution(unite=XSS)
    flux = _sse("etat", {"execution": 7, "connecte": True, "etat": "en_cours"}) + _sse("macro", {
        "execution": 7, "evenement": "etape", "box": XSS, "cle": "maillage:gk7", "rang": 4, "type": "comparer", "etat": "ecart",
        "resultat": {"ecart": True, "nouveaux": [XSS], "hausse": 1, "propositions": [{"action": "service-redemarrer", "args": {"unite": XSS}}]},
        "raison": XSS})

    def sc(pg, _):
        return (pg.locator("#journal img, #journal b, #journal script").count(), pg.evaluate("document.querySelectorAll('img').length"),
                pg.inner_text("#journal"))
    (balises, imgs, texte), erreurs, natifs, _ = _nav(sc, api=_api_simulee([ex], ex, flux))
    assert balises == 0 and imgs == 0 and XSS in texte and "relancer " + XSS + " sur gk7 ?" in texte
    assert erreurs == [] and natifs == []


def test_demo_aucun_appel_d_ecriture():
    def sc(pg, requetes):
        pg.check("#flotte-liste label:has-text('atelier') input")
        pg.click("#actions button:has-text('Mettre à jour')")
        pg.click("#macros-liste button:has-text('Lancer') >> nth=0")
        pg.keyboard.press("Escape")
        pg.fill("#commande", "maj")
        pg.keyboard.press("Enter")
        pg.keyboard.press("Escape")
        pg.wait_for_timeout(300)
        return [m for m, u in requetes if m != "GET"], pg.inner_text("#message")
    (ecritures, message), erreurs, natifs, _ = _nav(sc)
    assert ecritures == [] and "démonstration" in message.lower() and erreurs == [] and natifs == []


def test_rechargement_reprend_l_execution_en_cours():
    ex = _execution()
    flux = _sse("etat", {"execution": 7, "connecte": True, "etat": "en_cours"}) + _sse("macro", {
        "execution": 7, "evenement": "etape", "box": "gk7", "cle": "maillage:gk7", "rang": 1, "type": "condition", "etat": "ok",
        "resultat": {"vrai": False, "mesure_absente": False, "valeur": 1}, "raison": None})
    anciennes = [{**ex, "id": 6, "etat": "terminee"}, {**ex, "id": 5, "etat": "en_cours"}]

    def sc(pg, requetes):
        chemins = [urllib.parse.urlsplit(u).path for m, u in requetes if "/api/" in u]
        return chemins, pg.inner_text("#journal"), pg.is_visible("#arreter")
    (chemins, texte, arreter), erreurs, _, _ = _nav(sc, api=_api_simulee([ex] + anciennes, ex, flux))
    i_flux, i_lire = chemins.index("/api/v1/pilotage/executions/7/flux"), chemins.index("/api/v1/pilotage/executions/7")
    assert i_flux < i_lire                                   # abonné AVANT de relire : rien de perdu entre les deux
    assert "/api/v1/pilotage/executions/5/flux" not in chemins   # seule la dernière en cours est suivie
    assert "Mise à jour sûre" in texte and "relevé 60 s" in texte and "relancer secubox-portal sur gk7 ?" in texte
    assert arreter and erreurs == []


def test_action_refusee_409_message_dans_la_page():
    msg = "box tenue par une exécution de macro en cours : l'arrêter ou attendre sa fin"
    api = _api_simulee(ecritures={"/executions/action": (409, {"detail": msg})})

    def sc(pg, requetes):
        pg.check("#flotte-liste label:has-text('gk7') input")
        pg.click("#actions button:has-text('Mettre à jour')")
        pg.wait_for_timeout(300)
        envoi = next(r for r in requetes if r[0] == "POST")
        return pg.inner_text("#message"), envoi[1]
    (texte, url), erreurs, natifs, _ = _nav(sc, api=api)
    assert msg in texte and url.endswith("/api/v1/pilotage/executions/action") and natifs == [] and erreurs == []


def test_action_simple_lance_puis_suit_l_execution():
    ex = _execution(ident=9)
    api = _api_simulee(detail=ex, flux=_sse("etat", {"execution": 9, "connecte": True, "etat": "en_cours"}),
                       ecritures={"/executions/action": (202, {"execution": 9})})
    corps = []

    def sc(pg, requetes):
        pg.on("request", lambda r: corps.append(r.post_data_json) if r.method == "POST" else None)
        pg.check("#flotte-liste label:has-text('gk7') input")
        pg.click("#actions button:has-text('Mettre à jour')")
        pg.wait_for_timeout(500)
        chemins = [urllib.parse.urlsplit(u).path for m, u in requetes if "/api/" in u]
        return chemins
    chemins, erreurs, _, _ = _nav(sc, api=api)
    assert corps == [{"action": "maj-paquets", "args": {}, "cibles": ["maillage:gk7"], "confirmations": {}, "support": {}}]
    assert chemins.index("/api/v1/pilotage/executions/9/flux") < chemins.index("/api/v1/pilotage/executions/9") and erreurs == []


def test_action_forte_ouvre_l_ecran_de_lancement():
    def sc(pg, requetes):
        pg.check("#flotte-liste label:has-text('gk7') input")
        pg.click("#actions button:has-text('Redémarrer')")
        ouvert = pg.is_visible("#lancement")
        pg.keyboard.press("Escape")
        return ouvert, pg.is_visible("#lancement"), [m for m, u in requetes if m != "GET"]
    (ouvert, encore, ecritures), erreurs, _, _ = _nav(sc, api=_api_simulee())
    assert ouvert and not encore and ecritures == [] and erreurs == []
