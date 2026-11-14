# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3702 tâche 7 : la console de pilotage dans un vrai navigateur (Playwright). L'API est simulée par `page.route`, aux formes réelles
de api/main.py (catalogue, flotte, macros, exécutions, flux SSE) ; `?demo=1` sous file:// pour les captures et la démonstration."""
import json
import pathlib
import threading
import time
import urllib.parse

import pytest

from api.main import _resume_etape
from pilotage import macros as MAC
from pilotage.operations import CATALOGUE

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


# #3702 tâche 8 : macro à confirmation forte (redémarrage), étapes normalisées comme l'API les rend
MACRO_REBOOT = {"id": "m2", "nom": "Redémarrage contrôlé", "livree": False, "cibles": [], "programmation": None, "cree_le": 1,
                "maj_le": 1, "auteur": "admin",
                "etapes": MAC.valider_etapes([{"type": "releve", "duree_s": 60, "nom": "avant"}, {"type": "action", "action": "reboot"},
                                              {"type": "attendre", "delai_s": 300}, {"type": "releve", "duree_s": 60, "nom": "apres"},
                                              {"type": "comparer", "avant": "avant", "apres": "apres", "regle": "nouveau_service_en_echec"}])}


def _simulation(m, b):
    """Réponse de POST /macros/{id}/simuler, construite par les fonctions mêmes de l'API (api/main.py)."""
    etapes = [{"rang": i, "type": e["type"], "resume": _resume_etape(e), "forte": bool(e["type"] == "action" and CATALOGUE[e["action"]].forte),
               "coupure": MAC.coupure(e), "duree_estimee_s": MAC.estimer_s(e)} for i, e in enumerate(m["etapes"], 1)]
    cliente = b["reseau"] != "maillage"
    return {"box": b["nom"], "cle": b["cle"], "en_ligne": b["en_ligne"], "cliente": cliente, "forte_requise": MAC.contient_forte(m["etapes"]),
            "support_requis": cliente, "etapes": etapes, "duree_totale_s": sum(e["duree_estimee_s"] for e in etapes)}


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


def _api_simulee(executions=None, detail=None, flux=None, ecritures=None, flotte=None, macros=None):
    """Répondeur des routes /api/v1/pilotage/… : (statut, corps) ; `ecritures` : réponse des POST (statut, corps) par motif de chemin."""
    executions = executions if executions is not None else []
    flotte = flotte or _flotte()
    macros = macros if macros is not None else MACROS

    def repondre(methode, chemin, requete):
        if methode == "GET" and chemin == "/catalogue":
            return 200, _catalogue()
        if methode == "GET" and chemin == "/flotte":
            return 200, flotte
        if methode == "GET" and chemin == "/macros":
            return 200, macros
        if methode == "GET" and chemin.startswith("/macros/"):
            m = next((x for x in macros if x["id"] == urllib.parse.unquote(chemin.split("/")[2])), None)
            return (200, m) if m else (404, {"detail": "macro inconnue"})
        if methode == "POST" and chemin.startswith("/macros/") and chemin.endswith("/simuler"):
            m = next((x for x in macros if x["id"] == urllib.parse.unquote(chemin.split("/")[2])), None)
            cible = (requete.post_data_json or {}).get("box")
            b = next((x for x in flotte["boxes"] if cible in (x["cle"], x["nom"])), None)
            if m is None or b is None:
                return 404, {"detail": "macro inconnue" if m is None else "box inconnue"}
            return 200, _simulation(m, b)
        if methode == "GET" and chemin == "/executions":
            return 200, [{k: v for k, v in e.items() if k != "etapes"} for e in executions]
        if methode == "GET" and chemin.startswith("/executions/") and chemin.endswith("/flux"):
            return 200, flux or ""
        if methode == "GET" and chemin.startswith("/executions/"):
            return (200, detail) if detail is not None else (404, {"detail": "exécution inconnue"})
        for motif, rep in (ecritures or {}).items():
            if methode != "GET" and motif in chemin:
                return rep
        if methode == "GET" and chemin.startswith("/boxes/") and chemin.endswith("/support"):
            return 200, []
        if methode == "GET" and chemin.startswith("/boxes/"):
            nom = urllib.parse.unquote(chemin.split("/")[2]).split(":")[-1]
            b = next(x for x in flotte["boxes"] if x["nom"] == nom)
            return 200, {**b, "inventaire": {}, "inventaire_tronques": 0, "services_en_echec_noms": ["secubox-portal"] if nom == "gk7" else []}
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
            try:
                pg.wait_for_timeout(700)
                r = scenario(pg, requetes)
            finally:
                nav.close()
            return ("ok", r, erreurs, natifs, requetes)
    # fil démon borné : un navigateur bloqué fait échouer le test, jamais bloquer pytest (ni sa sortie)
    sortie = []

    def fil():
        try:
            sortie.append(tache())
        except BaseException as e:   # rendu au fil de pytest
            sortie.append(("exc", e))
    t = threading.Thread(target=fil, daemon=True)
    t.start()
    t.join(90)
    if not sortie:
        pytest.fail("navigateur bloqué : scénario non fini en 90 s")
    res = sortie[0]
    if res[0] == "exc":
        raise res[1]
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


def test_renommer_par_sa_route_une_seule_box():
    """renommer (`macro` faux au catalogue) : POST /boxes/{x}/actions/renommer {args, confirmation}, une seule box ; jamais /executions."""
    api = _api_simulee(ecritures={"/actions/renommer": (200, {"operation": 4, "box": "gk7", "cle": "maillage:gk7", "action": "renommer",
                                                                "etat": "accepte", "job": "j1", "raison": "", "operation_etat": "en_cours"})})
    corps = []

    def sc(pg, requetes):
        pg.on("request", lambda r: corps.append((r.url, r.post_data_json)) if r.method == "POST" else None)
        pg.check("#flotte-liste label:has-text('gk7') input")
        pg.check("#flotte-liste label:has-text('gk6') input")
        pg.click("#actions button:has-text('Secrets')")
        deux = pg.locator("#fenetre-corps [data-action='renommer']").is_disabled()
        pg.keyboard.press("Escape")
        pg.uncheck("#flotte-liste label:has-text('gk6') input")
        pg.click("#actions button:has-text('Secrets')")
        une = pg.locator("#fenetre-corps [data-action='renommer']").is_disabled()
        pg.fill("#param-nom", "gk9")
        pg.click("#fenetre-corps [data-action='renommer']")
        pg.fill("#lancement-corps input", "gk7")
        pg.click("#lancement-ok")
        pg.wait_for_timeout(300)
        return deux, une, pg.inner_text("#message"), pg.inner_text("#journal"), pg.is_visible("#lancement")
    (deux, une, msg, journal, ouvert), erreurs, natifs, requetes = _nav(sc, api=api)
    assert deux and not une and not ouvert
    assert corps == [(BASE + "/api/v1/pilotage/boxes/maillage%3Agk7/actions/renommer", {"args": {"nom": "gk9"}, "confirmation": "gk7"})]
    assert not any("/executions/" in u for m, u in requetes if "/api/" in u and "limite" not in u)
    assert "renommer gk9" in journal and "acceptée" in journal and erreurs == [] and natifs == []


def test_renommer_refus_de_l_api_affiche():
    msg = "box tenue par une exécution de macro en cours : l'arrêter ou attendre sa fin"
    api = _api_simulee(ecritures={"/actions/renommer": (409, {"detail": msg})})

    def sc(pg, _):
        pg.check("#flotte-liste label:has-text('gk7') input")
        pg.fill("#commande", "renommer")
        pg.keyboard.press("Enter")
        pg.fill("#param-nom", "gk9")
        pg.click("#fenetre-corps [data-action='renommer']")
        pg.fill("#lancement-corps input", "gk7")
        pg.click("#lancement-ok")
        pg.wait_for_timeout(300)
        return pg.inner_text("#lancement-msg"), pg.is_visible("#lancement")
    (texte, ouvert), erreurs, natifs, _ = _nav(sc, api=api)
    assert msg in texte and ouvert and erreurs == [] and natifs == []


def test_flux_trop_volumineux_annule_le_lecteur():
    ex = _execution()
    flux = _sse("etat", {"execution": 7, "connecte": True, "etat": "en_cours"}) + ": " + "x" * (1 << 20) + "\n"

    def avant(pg):
        pg.add_init_script("""window.__annule = 0; window.__abandon = 0;
            const c = ReadableStreamDefaultReader.prototype.cancel;
            ReadableStreamDefaultReader.prototype.cancel = function () { window.__annule++; return c.apply(this, arguments); };
            const a = AbortController.prototype.abort;
            AbortController.prototype.abort = function () { window.__abandon++; return a.apply(this, arguments); };""")

    def sc(pg, _):
        pg.wait_for_timeout(300)
        return pg.evaluate("[window.__annule, window.__abandon]"), pg.inner_text("#flux-etat")
    ((annule, abandon), etat), erreurs, _, _ = _nav(sc, api=_api_simulee([ex], ex, flux), avant=avant)
    assert annule >= 1 and abandon >= 1 and "reconnexion" in etat and erreurs == []


def test_flux_normal_ne_force_pas_d_annulation():
    ex = _execution()
    flux = _sse("etat", {"execution": 7, "connecte": True, "etat": "en_cours"})

    def avant(pg):
        pg.add_init_script("""window.__annule = 0; const c = ReadableStreamDefaultReader.prototype.cancel;
            ReadableStreamDefaultReader.prototype.cancel = function () { window.__annule++; return c.apply(this, arguments); };""")
    annule, erreurs, _, _ = _nav(lambda pg, _: pg.evaluate("window.__annule"), api=_api_simulee([ex], ex, flux), avant=avant)
    assert annule == 0 and erreurs == []


def test_releve_ligne_resolue_ok_puis_echec():
    reponses = iter([(202, {"cle": "maillage:gk7", "nom": "gk7", "duree_s": 60, "statut": "demande"}),
                     (409, {"detail": "un relevé est déjà en cours pour cette box"})])
    base = _api_simulee()

    def api(methode, chemin, requete):
        if methode == "POST" and chemin.endswith("/releve"):
            return next(reponses)
        return base(methode, chemin, requete)

    def sc(pg, _):
        pg.check("#flotte-liste label:has-text('gk7') input")
        pg.click("#actions button:has-text('Relevé')")
        pg.wait_for_timeout(200)
        pg.click("#actions button:has-text('Relevé')")
        pg.wait_for_timeout(200)
        return [x.inner_text() for x in pg.locator("#journal .ligne").all()]
    lignes, erreurs, _, _ = _nav(sc, api=api)
    assert len(lignes) == 2 and "… en cours" not in " ".join(lignes)
    assert "relevé 60 s" in lignes[0] and "ok" in lignes[0] and "échec" in lignes[1] and "déjà en cours" in lignes[1] and erreurs == []


# ---- #3702 tâche 8 : écran de lancement (plan simulé, noms retapés) et éditeur de macro ----

def _ecrits(pg):
    """Corps JSON des requêtes d'écriture, dans l'ordre : [(méthode, chemin, corps)]."""
    corps = []
    pg.on("request", lambda r: corps.append((r.method, urllib.parse.urlsplit(r.url).path[len("/api/v1/pilotage"):], r.post_data_json))
          if r.method != "GET" and "/api/" in r.url else None)
    return corps


def test_lancer_inactif_tant_qu_un_nom_manque():
    api = _api_simulee(macros=MACROS + [MACRO_REBOOT], ecritures={"/lancer": (202, {"execution": 11})})

    def sc(pg, _):
        ecrits = _ecrits(pg)
        pg.check("#flotte-liste label:has-text('gk7') input")
        pg.check("#flotte-liste label:has-text('gk6') input")
        pg.click("#macros-liste button[aria-label='Lancer Redémarrage contrôlé']")
        pg.wait_for_selector("#lancement-plan table")
        dlg = pg.locator("#lancement [role='dialog']")
        plan, coupures = pg.inner_text("#lancement-plan"), pg.locator("#lancement-plan .coupure").count()
        rappel = pg.inner_text("#lancement-corps")
        etats = []
        pg.fill("#lancement-corps input[data-cle='maillage:gk7']", "gk7")
        etats.append((pg.is_disabled("#lancement-ok"), pg.inner_text("#lancement-ok")))
        pg.fill("#lancement-corps input[data-cle='maillage:gk6']", "gk6")
        etats.append((pg.is_disabled("#lancement-ok"), pg.inner_text("#lancement-ok")))
        pg.fill("#lancement-corps input[data-cle='maillage:gk6']", "GK6")
        etats.append((pg.is_disabled("#lancement-ok"), pg.inner_text("#lancement-ok")))
        pg.fill("#lancement-corps input[data-cle='maillage:gk6']", "gk6")
        pg.click("#lancement-ok")
        pg.wait_for_timeout(300)
        return dlg.count(), plan, coupures, rappel, etats, ecrits, pg.is_visible("#lancement")
    (n_dlg, plan, coupures, rappel, etats, ecrits, ouvert), erreurs, natifs, _ = _nav(sc, api=api)
    assert n_dlg == 1
    assert "gk7" in plan and "gk6" in plan and "reboot" in plan and "redémarrage" in plan and coupures == 2
    assert "Une box après l'autre : gk6 ne commence qu'une fois gk7 revenue et son relevé sain" in rappel
    assert etats == [(True, "Lancer (1 nom sur 2)"), (False, "Lancer (2 noms sur 2)"), (True, "Lancer (1 nom sur 2)")]
    assert ecrits == [("POST", "/macros/m2/simuler", {"box": "maillage:gk7"}), ("POST", "/macros/m2/simuler", {"box": "maillage:gk6"}),
                      ("POST", "/macros/m2/lancer", {"cibles": ["maillage:gk7", "maillage:gk6"],
                                                     "confirmations": {"maillage:gk7": "gk7", "maillage:gk6": "gk6"}, "support": {}})]
    assert not ouvert and erreurs == [] and natifs == []


def test_programmation_desactivee_si_reboot():
    fl = _flotte()
    fl["boxes"].append(_box("cabane", reseau="clients"))

    def sc(pg, _):
        pg.click("#macro-nouvelle")
        pg.fill("[aria-label='Nom de la macro']", "Nuit et redémarrage")
        pg.click("#ed-catalogue [data-ajout='releve']")
        avant = pg.is_disabled("#ed-nuit")
        pg.check("#ed-nuit")
        pg.click("#ed-catalogue [data-ajout='action:reboot']")
        apres = (pg.is_disabled("#ed-nuit"), pg.is_checked("#ed-demande"), pg.inner_text("#ed-quand-raison"))
        pg.click("[aria-label='Supprimer l\\'étape 2']")
        retire = pg.is_disabled("#ed-nuit")
        pg.check("#ed-cibles input[data-cle='clients:cabane']")
        client = (pg.is_disabled("#ed-nuit"), pg.inner_text("#ed-quand-raison"))
        return avant, apres, retire, client
    (avant, (bloque, demande, raison), retire, (bloque_client, raison_client)), erreurs, natifs, _ = _nav(sc, api=_api_simulee(flotte=fl))
    assert not avant and bloque and demande and "confirmation forte" in raison and "reboot" in raison
    assert not retire and bloque_client and "cliente" in raison_client and erreurs == [] and natifs == []


def test_editeur_ordre_au_clavier():
    api = _api_simulee(ecritures={"/macros": (201, {"id": "m9"})})

    def sc(pg, _):
        ecrits = _ecrits(pg)
        pg.click("#macro-nouvelle")
        pg.fill("[aria-label='Nom de la macro']", "Ordre test")
        pg.click("#ed-catalogue [data-ajout='action:maj-paquets']")
        pg.click("#ed-catalogue [data-ajout='attendre']")
        types = lambda: pg.evaluate("[...document.querySelectorAll('#ed-etapes .etape')].map(e => e.dataset.type)")
        debut = types()
        pg.focus("[aria-label='Monter l\\'étape 2']")
        pg.keyboard.press("Enter")
        monte, focus1 = types(), pg.evaluate("document.activeElement.getAttribute('aria-label')")
        pg.keyboard.press(" ")
        descend, focus2 = types(), pg.evaluate("document.activeElement.getAttribute('aria-label')")
        pg.focus("[aria-label='Monter l\\'étape 2']")
        pg.keyboard.press("Enter")
        numeros = pg.evaluate("[...document.querySelectorAll('#ed-etapes .num')].map(e => e.textContent)")
        pg.click("#ed-enregistrer")
        pg.wait_for_timeout(300)
        return debut, monte, focus1, descend, focus2, numeros, ecrits, pg.inner_text("#ed-msg")
    (debut, monte, focus1, descend, focus2, numeros, ecrits, msg), erreurs, natifs, _ = _nav(sc, api=api)
    assert debut == ["action", "attendre"] and monte == ["attendre", "action"] and descend == ["action", "attendre"]
    assert focus1 == "Descendre l'étape 1" and focus2 == "Monter l'étape 2" and numeros == ["1", "2"]
    assert ecrits == [("POST", "/macros", {"nom": "Ordre test", "cibles": [], "programmation": None,
                                           "etapes": [{"type": "attendre", "delai_s": 300},
                                                      {"type": "action", "action": "maj-paquets", "args": {}, "delai_s": 900}]})]
    assert "enregistrée" in msg and erreurs == [] and natifs == []


def test_echap_ferme_d_abord_le_dialogue():
    api = _api_simulee(macros=MACROS + [MACRO_REBOOT], ecritures={"/macros/m2": (200, {"id": "m2"})})

    def sc(pg, _):
        ecrits = _ecrits(pg)
        pg.click("#macros-liste button[aria-label='Ouvrir Redémarrage contrôlé']")
        pg.check("#ed-cibles input[data-cle='maillage:gk7']")
        nom = pg.input_value("[aria-label='Nom de la macro']")
        pg.click("#ed-enregistrer-lancer")
        pg.wait_for_selector("#lancement:not([hidden])")
        vus = [(pg.is_visible("#lancement"), pg.is_visible("#editeur"))]
        pg.keyboard.press("Escape")
        vus.append((pg.is_visible("#lancement"), pg.is_visible("#editeur")))
        pg.keyboard.press("Escape")
        vus.append((pg.is_visible("#lancement"), pg.is_visible("#editeur"), pg.is_visible("#pan-macros")))
        return nom, vus, [(m, c) for m, c, _ in ecrits]
    (nom, vus, ecrits), erreurs, natifs, _ = _nav(sc, api=api)
    assert nom == "Redémarrage contrôlé"
    assert vus == [(True, True), (False, True), (False, False, True)]
    assert ecrits[0] == ("PUT", "/macros/m2") and not any(c.endswith("/lancer") for _, c in ecrits) and erreurs == [] and natifs == []


def test_erreur_400_affichee():
    msg = "étape 1 : le relevé « avant » doit être produit par une étape antérieure"
    api = _api_simulee(ecritures={"/macros": (400, {"detail": msg})})

    def sc(pg, _):
        pg.click("#macro-nouvelle")
        pg.fill("[aria-label='Nom de la macro']", "Condition seule")
        pg.click("#ed-catalogue [data-ajout='condition']")
        pg.click("#ed-enregistrer")
        pg.wait_for_timeout(300)
        return pg.inner_text("#ed-msg"), pg.is_visible("#editeur")
    (texte, ouvert), erreurs, natifs, _ = _nav(sc, api=api)
    assert texte.strip() == msg and ouvert and erreurs == [] and natifs == []


def test_livree_lecture_seule_puis_copier():
    api = _api_simulee(ecritures={"/copier": (201, {"id": "m5"})})

    def sc(pg, _):
        ecrits = _ecrits(pg)
        pg.click("#macros-liste button[aria-label='Ouvrir Mise à jour sûre']")
        lecture = (pg.is_disabled("[aria-label='Nom de la macro']"), pg.locator("#ed-etapes [aria-label^='Monter']").count(),
                   pg.is_visible("#ed-enregistrer"), pg.is_visible("#ed-copier"))
        pg.click("#ed-copier")
        pg.wait_for_timeout(300)
        return lecture, [(m, c) for m, c, _ in ecrits]
    ((nom_bloque, monter, enregistrer, copier), ecrits), erreurs, natifs, _ = _nav(sc, api=api)
    assert nom_bloque and monter == 0 and not enregistrer and copier
    assert ecrits == [("POST", "/macros/livree%3Amise-a-jour-sure/copier")] and erreurs == [] and natifs == []


def _taille_et_debordants(pg):
    return pg.evaluate("""[document.documentElement.scrollWidth, innerWidth,
        [...document.querySelectorAll('#editeur *, #lancement *')].filter(e => e.offsetParent !== null && !e.closest('.plan-defile')
          && e.getBoundingClientRect().right > innerWidth + 1).map(e => e.tagName + '.' + e.className).slice(0, 5)]""")


def test_editeur_420_sans_debordement():
    def sc(pg, _):
        pg.click("#panneaux [data-panneau='pan-macros']")
        pg.click("#macros-liste button[aria-label='Ouvrir Mise à jour + redémarrage']")
        livree = _taille_et_debordants(pg)
        pg.click("#ed-retour")
        pg.click("#macro-nouvelle")
        for a in ("releve", "action:service-redemarrer", "condition", "comparer", "attendre"):
            pg.click(f"#ed-catalogue [data-ajout='{a}']")
        nouvelle = _taille_et_debordants(pg)
        return livree, nouvelle, pg.is_visible("#editeur")
    ((sw1, iw1, deb1), (sw2, iw2, deb2), ouvert), erreurs, natifs, _ = _nav(sc, largeur=420)
    assert sw1 <= iw1 and sw2 <= iw2 and deb1 == [] and deb2 == [] and ouvert and erreurs == [] and natifs == []


def test_editeur_ajout_et_ordre_par_glisser():
    def sc(pg, _):
        pg.click("#macro-nouvelle")
        types = lambda: pg.evaluate("[...document.querySelectorAll('#ed-etapes .etape')].map(e => e.dataset.type)")
        pg.locator("#ed-catalogue [data-ajout='action:maj-paquets']").drag_to(pg.locator("#ed-depot"))
        un = types()
        pg.locator("#ed-catalogue [data-ajout='releve']").drag_to(pg.locator("#ed-etapes .etape >> nth=0"))
        deux = types()
        pg.locator("#ed-etapes .etape >> nth=1 >> .num").drag_to(pg.locator("#ed-etapes .etape >> nth=0"))
        trois = types()
        renommer = pg.is_disabled("#ed-catalogue [data-ajout='action:renommer']")
        return un, deux, trois, renommer
    (un, deux, trois, renommer), erreurs, natifs, _ = _nav(sc)
    assert un == ["action"] and deux == ["releve", "action"] and trois == ["action", "releve"]
    assert renommer and erreurs == [] and natifs == []


# ---- #3702 tâche 8, correction 1 : « Enregistrer et lancer » ne vise que les cibles de la macro ----
MACRO_MUETTE = {"id": "m3", "nom": "Veille gk12", "livree": False, "cibles": ["maillage:gk12"], "programmation": None, "cree_le": 1,
                "maj_le": 1, "auteur": "admin", "etapes": [{"type": "releve", "duree_s": 60, "nom": "diag"}]}


def test_enregistrer_et_lancer_jamais_hors_cibles():
    api = _api_simulee(macros=MACROS + [MACRO_MUETTE], ecritures={"/lancer": (202, {"execution": 3}), "/macros/m3": (200, {"id": "m3"})})

    def sc(pg, _):
        ecrits = _ecrits(pg)
        pg.check("#flotte-liste label:has-text('gk7') input")
        pg.click("#macros-liste button[aria-label='Ouvrir Veille gk12']")
        pg.click("#ed-enregistrer-lancer")
        pg.wait_for_timeout(300)
        muette = (pg.inner_text("#ed-msg"), pg.is_visible("#editeur"), pg.is_visible("#lancement"))
        pg.click("#ed-groupes [data-vider]")
        pg.click("#ed-enregistrer-lancer")
        pg.wait_for_timeout(300)
        vide = (pg.inner_text("#ed-msg"), pg.is_visible("#editeur"))
        return muette, vide, [(m, c) for m, c, _ in ecrits]
    ((msg1, ouvert1, dlg), (msg2, ouvert2), ecrits), erreurs, natifs, _ = _nav(sc, api=api)
    assert "gk12" in msg1 and "hors ligne" in msg1 and ouvert1 and not dlg
    assert "aucune cible" in msg2.lower() and ouvert2
    assert not any(c.endswith("/lancer") for _, c in ecrits) and ecrits[0] == ("PUT", "/macros/m3") and erreurs == [] and natifs == []


def test_lancement_depuis_l_editeur_ferme_l_editeur():
    api = _api_simulee(flux=_sse("etat", {"execution": 9, "connecte": True, "etat": "en_cours"}),
                       ecritures={"/macros/m1/lancer": (202, {"execution": 9}), "/macros/m1": (200, {"id": "m1"})})

    def sc(pg, _):
        ecrits = _ecrits(pg)
        pg.check("#flotte-liste label:has-text('gk7') input")
        pg.click("#macros-liste button[aria-label='Ouvrir Nuit tranquille']")
        pg.click("#ed-enregistrer-lancer")
        pg.wait_for_timeout(400)
        return pg.is_visible("#editeur"), pg.is_visible("#pan-journal"), ecrits
    (ouvert, journal, ecrits), erreurs, natifs, _ = _nav(sc, api=api)
    assert ecrits[-1] == ("POST", "/macros/m1/lancer", {"cibles": ["maillage:gk6"], "confirmations": {}, "support": {}})
    assert not ouvert and journal and erreurs == [] and natifs == []


def test_copier_avertit_des_modifications_non_enregistrees():
    api = _api_simulee(ecritures={"/copier": (201, {"id": "m5"})})

    def sc(pg, _):
        ecrits = _ecrits(pg)
        pg.click("#macros-liste button[aria-label='Ouvrir Nuit tranquille']")
        pg.fill("[aria-label='Nom de la macro']", "Nuit modifiée")
        pg.click("#ed-copier")
        pg.wait_for_timeout(200)
        avant = ([c for _, c, _ in ecrits], pg.inner_text("#ed-msg"))
        pg.click("#ed-copier")
        pg.wait_for_timeout(300)
        return avant, [c for _, c, _ in ecrits]
    ((avant, msg), apres), erreurs, natifs, _ = _nav(sc, api=api)
    assert avant == [] and "non enregistrées" in msg and apres == ["/macros/m1/copier"] and erreurs == [] and natifs == []
