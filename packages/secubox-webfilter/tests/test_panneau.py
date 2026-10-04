# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Panneau d'observation de secubox-webfilter dans un vrai navigateur, API simulée (#1962)."""
import json
import re
from pathlib import Path
from urllib.parse import unquote

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "webfilter" / "index.html"

ETAT = {"mode_global": "observe", "categories": [
    {"id": "adulte", "libelle": "Contenu adulte", "mode": "observe", "requetes_7j": 4,
     "sources": [{"nom": "hagezi-nsfw", "licence": "GPL-3.0", "n": 84284, "ts": 1791090000}]},
    {"id": "jeux", "libelle": "Jeux d'argent", "mode": "observe", "requetes_7j": 0,
     "sources": [{"nom": "hagezi-gambling-medium", "licence": "GPL-3.0", "n": None, "ts": None}]}]}
STATS = {"jours": 7, "par_categorie": {"adulte": 4}, "par_client": {"192.168.1.95": {"adulte": 3}, "192.168.1.5": {"adulte": 1}}}
DOMAINES = {"categorie": "adulte", "jours": 7, "domaines": [{"domaine": "a.evil.example.com", "n": 3}, {"domaine": "b.evil.example.com", "n": 1}]}


PROFILS = {"version": 4, "profils": {
    "defaut": {"categories": {"adulte": "observe", "jeux": "observe"}, "autorise": []},
    "enfants": {"categories": {"adulte": "block", "jeux": "observe"}, "autorise": ["education.example.org"]}},
    "modeles": {"enfants": {"categories": {"adulte": "block", "jeux": "block"}, "autorise": []}, "adultes": {"categories": {}, "autorise": []}}}
APPAREILS = {"assignes": [
    {"mac": "aa:bb:cc:dd:ee:01", "nom": "Tablette", "profil": "enfants", "exceptions": {"jeux": "block"}, "adresses": ["192.168.1.50"], "exclu": None},
    {"mac": "aa:bb:cc:dd:ee:02", "nom": "TV salon", "profil": "defaut", "exceptions": {}, "adresses": ["192.168.1.95"], "exclu": "geree par ad-guard"}],
    "connus": [{"mac": "aa:bb:cc:dd:ee:09", "adresses": ["192.168.1.77"], "vu": 1791090000, "exclu": None}]}
APPLIQUER = {"en_attente": True, "version": 4, "appliquee": 2, "dernier": {"statut": "applique", "version": 2, "zones": 311000, "vues": 2, "duree_s": 9.4, "message": "ok"},
             "estimation": {"zones": 311001, "memoire_mo": 106, "rechargement_s": 9.4}}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _page(navigateur, rep=None, token="jeton-admin"):
    """`rep` : {(méthode, chemin): (statut, corps)} ; défaut = tout répond normalement."""
    rep = {("GET", "/profils"): (200, PROFILS), ("GET", "/appareils"): (200, APPAREILS), ("GET", "/appliquer"): (200, APPLIQUER),
           ("POST", "/profils"): (200, {"version": 5}), ("POST", "/appareils/aa:bb:cc:dd:ee:01"): (200, {"version": 6}), ("POST", "/appareils/aa:bb:cc:dd:ee:09"): (200, {"version": 7}),
           ("DELETE", "/profils/enfants"): (200, {"version": 8}), ("DELETE", "/appareils/aa:bb:cc:dd:ee:01"): (200, {"version": 9}), ("POST", "/appliquer"): (202, {"statut": "demandee"}),
           ("GET", "/etat"): (200, ETAT), ("GET", "/stats"): (200, STATS), ("GET", "/categories/adulte/domaines"): (200, DOMAINES),
           ("GET", "/categories/jeux/domaines"): (200, {"categorie": "jeux", "jours": 7, "domaines": []}), ("POST", "/sync"): (202, {"statut": "demandee"}),
           **(rep or {})}
    ctx = navigateur.new_context()
    if token:
        ctx.add_init_script(f"localStorage.setItem('sbx_token', '{token}')")
    p = ctx.new_page()
    erreurs, requetes = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    p.corps = {}

    def api(route):
        chemin = unquote(re.sub(r"^.*?/api/v1/webfilter", "", route.request.url).split("?")[0])          # le serveur décode %3A en « : »
        requetes.append((route.request.method, chemin, route.request.headers.get("authorization")))
        if route.request.post_data:
            p.corps[(route.request.method, chemin)] = json.loads(route.request.post_data)
        statut, corps = rep.get((route.request.method, chemin), (404, {"detail": "inconnu"}))
        route.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/**", lambda r: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://sbx.test/api/v1/webfilter/**", api)
    p.route("http://sbx.test/", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.goto("http://sbx.test/")
    return ctx, p, erreurs, requetes


def _chiffres(texte):
    return re.sub(r"\s| ", "", texte)


def test_affiche_cartes_listes_et_avertissement_observe(navigateur):
    ctx, p, erreurs, _ = _page(navigateur)
    p.wait_for_selector("[data-cat='adulte']")
    assert "observe" in p.inner_text("#bandeau-observe").lower() and "rien n'est bloqué" in p.inner_text("#bandeau-observe")
    for limite in ("DoH", "VPN"):
        assert limite in p.inner_text("#bandeau-observe")
    assert p.inner_text("[data-cat='adulte'] .value") == "4" and "Contenu adulte" in p.text_content("[data-cat='adulte']")
    ligne = p.inner_text("[data-source='hagezi-nsfw']")
    assert "GPL-3.0" in ligne and _chiffres(ligne).count("84284") == 1 and "2026-10-04" in ligne
    assert not erreurs
    ctx.close()


def test_valeur_manquante_donne_un_tiret_jamais_zero(navigateur):
    ctx, p, _, _ = _page(navigateur)
    p.wait_for_selector("[data-source='hagezi-gambling-medium']")
    ligne = p.inner_text("[data-source='hagezi-gambling-medium']")
    assert "—" in ligne and "0" not in re.sub(r"GPL-3\.0|hagezi-gambling-medium", "", ligne)
    ctx.close()


def test_detail_par_appareil_et_domaines_pour_l_administrateur(navigateur):
    ctx, p, _, requetes = _page(navigateur)
    p.wait_for_selector("[data-client='192.168.1.95']")
    assert "3" in p.inner_text("[data-client='192.168.1.95']") and "1" in p.inner_text("[data-client='192.168.1.5']")
    p.wait_for_selector("#top-domaines li")
    assert "a.evil.example.com" in p.inner_text("#top-domaines")
    assert any(m == "GET" and c == "/stats" and a == "Bearer jeton-admin" for m, c, a in requetes)
    ctx.close()


def test_sans_jeton_message_clair_et_aucun_nom_d_appareil(navigateur):
    ctx, p, erreurs, requetes = _page(navigateur, rep={("GET", "/stats"): (401, {"detail": "Token manquant"}),
                                                       ("GET", "/categories/adulte/domaines"): (401, {"detail": "x"})}, token=None)
    p.wait_for_selector("[data-cat='adulte']")
    p.wait_for_selector("#note-admin")
    assert "administrateur" in p.inner_text("#note-admin").lower()
    assert p.locator("[data-client]").count() == 0
    assert not erreurs
    ctx.close()


def test_aucun_html_venu_de_l_api_n_est_execute(navigateur):
    mal = "<img src=x onerror=window.__pwned=1>"
    etat = json.loads(json.dumps(ETAT))
    etat["categories"][0]["libelle"] = mal
    etat["categories"][0]["sources"][0]["nom"] = mal
    etat["categories"][0]["sources"][0]["licence"] = mal
    stats = {"jours": 7, "par_categorie": {}, "par_client": {mal: {"adulte": 1}}}
    ctx, p, erreurs, _ = _page(navigateur, rep={("GET", "/etat"): (200, etat), ("GET", "/stats"): (200, stats),
                                                ("GET", "/categories/adulte/domaines"): (200, {"categorie": "adulte", "jours": 7, "domaines": [{"domaine": mal, "n": 1}]})})
    p.wait_for_selector("#top-domaines li")
    p.wait_for_timeout(300)
    assert p.evaluate("window.__pwned") is None
    assert mal in p.text_content("#cartes") and mal in p.text_content("#top-domaines")      # affiché comme TEXTE, tel quel
    assert p.locator("img").count() == 0
    ctx.close()


def test_synchroniser_succes_transitoire_et_conflit_persistant(navigateur):
    ctx, p, _, requetes = _page(navigateur)
    p.wait_for_selector("[data-cat='adulte']")
    p.click("#btn-sync")
    p.wait_for_selector("#toast.show")
    assert "Synchronisation demandée" in p.inner_text("#toast")
    assert any(m == "POST" and c == "/sync" and a == "Bearer jeton-admin" for m, c, a in requetes)
    ctx.close()
    ctx, p, _, _ = _page(navigateur, rep={("POST", "/sync"): (409, {"detail": "une synchronisation est déjà en cours"})})
    p.wait_for_selector("[data-cat='adulte']")
    p.click("#btn-sync")
    p.wait_for_selector("#errtoast.show")
    assert "déjà en cours" in p.inner_text("#errtoast")
    p.wait_for_timeout(3500)
    assert p.is_visible("#errtoast")                                    # un message fatal reste jusqu'à ce qu'on le ferme
    p.click("#errtoast .fermer")
    assert not p.is_visible("#errtoast")
    ctx.close()


def test_catalogue_illisible_message_persistant(navigateur):
    ctx, p, _, _ = _page(navigateur, rep={("GET", "/etat"): (503, {"detail": "catalogue illisible : x"})})
    p.wait_for_selector("#errtoast.show")
    assert "catalogue illisible" in p.inner_text("#errtoast")
    ctx.close()


# ── phase 2 : onglets Profils, Appareils, Appliquer ────────────────────────────────────────────────────────────────────────────────
def onglet(p, nom):
    p.click(f"[data-onglet='{nom}']")


def test_onglet_profils_affiche_les_modes_et_les_autorisations(navigateur):
    ctx, p, erreurs, _ = _page(navigateur)
    onglet(p, "profils")
    p.wait_for_selector("[data-profil='enfants']")
    assert p.input_value("select[data-profil='enfants'][data-cat='adulte']") == "block" and p.input_value("select[data-profil='enfants'][data-cat='jeux']") == "observe"
    assert "education.example.org" in p.text_content("[data-profil='enfants']") and not erreurs
    assert p.locator("[data-action='supprimer-profil'][data-profil='defaut']").count() == 0         # « defaut » ne se supprime pas
    ctx.close()


def test_passer_en_block_demande_confirmation_et_envoie_le_bon_profil(navigateur):
    ctx, p, _, _ = _page(navigateur)
    messages = []
    p.on("dialog", lambda d: (messages.append(d.message), d.accept()))
    onglet(p, "profils")
    p.wait_for_selector("[data-profil='enfants']")
    p.select_option("select[data-profil='enfants'][data-cat='jeux']", "block")
    p.click("[data-action='enregistrer-profil'][data-profil='enfants']")
    p.wait_for_selector("#toast.show")
    assert messages and "BLOCAGE" in messages[0] and "jeux" in messages[0].lower()
    assert p.corps[("POST", "/profils")] == {"nom": "enfants", "categories": {"adulte": "block", "jeux": "block"}, "autorise": ["education.example.org"]}
    ctx.close()


def test_refuser_la_confirmation_n_envoie_rien(navigateur):
    ctx, p, _, requetes = _page(navigateur)
    p.on("dialog", lambda d: d.dismiss())
    onglet(p, "profils")
    p.wait_for_selector("[data-profil='enfants']")
    p.select_option("select[data-profil='enfants'][data-cat='jeux']", "block")
    p.click("[data-action='enregistrer-profil'][data-profil='enfants']")
    p.wait_for_timeout(400)
    assert not [r for r in requetes if r[0] == "POST" and r[1] == "/profils"]
    ctx.close()


def test_creer_un_profil_depuis_un_modele(navigateur):
    ctx, p, _, _ = _page(navigateur)
    p.on("dialog", lambda d: d.accept())
    onglet(p, "profils")
    p.wait_for_selector("#nouveau-nom")
    p.fill("#nouveau-nom", "ados")
    p.select_option("#nouveau-modele", "enfants")
    p.click("#btn-creer-profil")
    p.wait_for_selector("#toast.show")
    assert p.corps[("POST", "/profils")] == {"nom": "ados", "categories": {"adulte": "block", "jeux": "block"}, "autorise": []}
    ctx.close()


def test_onglet_appareils_assigne_et_signale_ad_guard(navigateur):
    ctx, p, _, _ = _page(navigateur)
    onglet(p, "appareils")
    p.wait_for_selector("[data-mac='aa:bb:cc:dd:ee:01']")
    assert p.input_value("select[data-mac='aa:bb:cc:dd:ee:01'][data-champ='profil']") == "enfants"
    assert p.input_value("select[data-mac='aa:bb:cc:dd:ee:01'][data-exc='jeux']") == "block"
    tv = "[data-mac='aa:bb:cc:dd:ee:02']"
    assert "ad-guard" in p.text_content(tv) and p.locator("select[data-mac='aa:bb:cc:dd:ee:02']").count() == 0     # aucune assignation possible
    ctx.close()


def test_enregistrer_un_appareil_envoie_profil_et_exceptions(navigateur):
    ctx, p, _, _ = _page(navigateur)
    p.on("dialog", lambda d: d.accept())
    onglet(p, "appareils")
    p.wait_for_selector("[data-mac='aa:bb:cc:dd:ee:01']")
    p.select_option("select[data-mac='aa:bb:cc:dd:ee:01'][data-exc='jeux']", "")                  # retire l'exception
    p.select_option("select[data-mac='aa:bb:cc:dd:ee:01'][data-exc='adulte']", "observe")
    p.click("[data-action='enregistrer-appareil'][data-mac='aa:bb:cc:dd:ee:01']")
    p.wait_for_selector("#toast.show")
    assert p.corps[("POST", "/appareils/aa:bb:cc:dd:ee:01")] == {"nom": "Tablette", "profil": "enfants", "exceptions": {"adulte": "observe"}}
    ctx.close()


def test_assigner_un_appareil_connu(navigateur):
    ctx, p, _, _ = _page(navigateur)
    p.on("dialog", lambda d: d.accept())
    onglet(p, "appareils")
    p.wait_for_selector("[data-connu='aa:bb:cc:dd:ee:09']")
    p.fill("[data-connu='aa:bb:cc:dd:ee:09'] input", "Console")
    p.select_option("[data-connu='aa:bb:cc:dd:ee:09'] select", "enfants")
    p.click("[data-action='assigner'][data-mac='aa:bb:cc:dd:ee:09']")
    p.wait_for_selector("#toast.show")
    assert p.corps[("POST", "/appareils/aa:bb:cc:dd:ee:09")] == {"nom": "Console", "profil": "enfants", "exceptions": {}}
    ctx.close()


def test_onglet_appliquer_montre_l_attente_l_estimation_et_demande(navigateur):
    ctx, p, _, requetes = _page(navigateur)
    messages = []
    p.on("dialog", lambda d: (messages.append(d.message), d.accept()))
    onglet(p, "appliquer")
    p.wait_for_function("document.getElementById('appli-estimation').textContent.includes('106')")          # les données de l'API sont arrivées
    assert "en attente" in p.text_content("#appli-etat").lower() and "106" in p.text_content("#appli-estimation") and "9,4" in p.text_content("#appli-estimation").replace(".", ",")
    p.click("#btn-appliquer")
    p.wait_for_selector("#toast.show")
    assert messages and "DNS" in messages[0] and any(m == "POST" and c == "/appliquer" and a == "Bearer jeton-admin" for m, c, a in requetes)
    ctx.close()


def test_application_deja_en_cours_reste_affichee(navigateur):
    ctx, p, _, _ = _page(navigateur, rep={("POST", "/appliquer"): (409, {"detail": "une application est déjà demandée ou en cours"})})
    p.on("dialog", lambda d: d.accept())
    onglet(p, "appliquer")
    p.wait_for_selector("#btn-appliquer")
    p.click("#btn-appliquer")
    p.wait_for_selector("#errtoast.show")
    p.wait_for_timeout(3500)
    assert p.is_visible("#errtoast") and "déjà" in p.inner_text("#errtoast")
    ctx.close()


def test_observation_distingue_bloque_et_aurait_bloque(navigateur):
    stats = {"jours": 7, "par_categorie": {"adulte": 7}, "par_client": {"192.168.1.95": {"adulte": 3}},
             "par_categorie_decision": {"adulte": {"bloque": 2, "observe": 5}}, "par_client_decision": {"192.168.1.95": {"adulte": {"bloque": 2, "observe": 1}}}}
    etat = json.loads(json.dumps(ETAT))
    etat["categories"][0]["bloque_7j"] = 2
    etat["categories"][0]["requetes_7j"] = 7
    ctx, p, _, _ = _page(navigateur, rep={("GET", "/stats"): (200, stats), ("GET", "/etat"): (200, etat)})
    p.wait_for_selector("[data-client='192.168.1.95']")
    assert "2" in p.text_content("[data-cat='adulte'] .bloque") and "bloqué" in p.text_content("[data-cat='adulte']").lower()
    assert "2" in p.text_content("[data-client='192.168.1.95'] .bloque")
    ctx.close()


def test_aucun_html_venu_de_l_api_dans_les_nouveaux_onglets(navigateur):
    mal = "<img src=x onerror=window.__pwned=1>"
    profils = json.loads(json.dumps(PROFILS))
    profils["profils"][mal.replace("<", "").replace(">", "")] = {"categories": {"adulte": "observe", "jeux": "observe"}, "autorise": [mal]}
    apps = json.loads(json.dumps(APPAREILS))
    apps["assignes"][0]["nom"] = mal
    apps["connus"][0]["adresses"] = [mal]
    ctx, p, _, _ = _page(navigateur, rep={("GET", "/profils"): (200, profils), ("GET", "/appareils"): (200, apps)})
    onglet(p, "profils")
    p.wait_for_selector("[data-profil='enfants']")
    onglet(p, "appareils")
    p.wait_for_selector("[data-mac='aa:bb:cc:dd:ee:01']")
    p.wait_for_timeout(300)
    assert p.evaluate("window.__pwned") is None and p.locator("img").count() == 0
    assert mal in p.text_content("#onglet-profils") or mal in p.text_content("#onglet-appareils")
    ctx.close()


def test_sans_jeton_les_nouveaux_onglets_demandent_la_connexion(navigateur):
    non = (401, {"detail": "Token manquant"})
    ctx, p, erreurs, _ = _page(navigateur, rep={("GET", "/profils"): non, ("GET", "/appareils"): non, ("GET", "/appliquer"): non, ("GET", "/stats"): non}, token=None)
    for o in ("profils", "appareils", "appliquer"):
        onglet(p, o)
        p.wait_for_selector(f"#note-admin-{o}")
        assert "administrateur" in p.inner_text(f"#note-admin-{o}").lower()
    assert p.locator("[data-mac]").count() == 0 and p.locator("[data-profil]").count() == 0 and not erreurs
    ctx.close()


def test_motif_d_exclusion_reel_et_retirer_toujours_possible(navigateur):
    apps = json.loads(json.dumps(APPAREILS))
    apps["assignes"].append({"mac": "aa:bb:cc:dd:ee:03", "nom": "Tel", "profil": "enfants", "exceptions": {}, "adresses": [], "exclu": "adresse inconnue"})
    ctx, p, _, requetes = _page(navigateur, rep={("GET", "/appareils"): (200, apps), ("DELETE", "/appareils/aa:bb:cc:dd:ee:03"): (200, {"version": 11})})
    p.on("dialog", lambda d: d.accept())
    onglet(p, "appareils")
    p.wait_for_selector("[data-mac='aa:bb:cc:dd:ee:03']")
    ligne = p.text_content("[data-mac='aa:bb:cc:dd:ee:03']")
    assert "adresse inconnue" in ligne and "ad-guard" not in ligne                           # le motif RÉEL, pas « gérée par ad-guard »
    assert p.locator("[data-action='retirer-appareil'][data-mac='aa:bb:cc:dd:ee:03']").count() == 1
    assert p.locator("select[data-mac='aa:bb:cc:dd:ee:03']").count() == 0 or p.locator("[data-action='retirer-appareil'][data-mac='aa:bb:cc:dd:ee:03']").count() == 1
    p.click("[data-action='retirer-appareil'][data-mac='aa:bb:cc:dd:ee:03']")
    p.wait_for_selector("#toast.show")
    assert ("DELETE", "/appareils/aa:bb:cc:dd:ee:03", "Bearer jeton-admin") in requetes
    tv = p.text_content("[data-mac='aa:bb:cc:dd:ee:02']")
    assert "ad-guard" in tv                                                                  # l'exclusion d'ad-guard garde son message
    ctx.close()


def test_exception_en_block_demande_confirmation(navigateur):
    ctx, p, _, requetes = _page(navigateur)
    messages = []
    p.on("dialog", lambda d: (messages.append(d.message), d.dismiss()))
    onglet(p, "appareils")
    p.wait_for_selector("[data-mac='aa:bb:cc:dd:ee:01']")
    p.select_option("select[data-mac='aa:bb:cc:dd:ee:01'][data-exc='adulte']", "block")        # le profil « enfants » bloque déjà adulte : pas nouveau
    p.select_option("select[data-mac='aa:bb:cc:dd:ee:01'][data-champ='profil']", "defaut")       # defaut observe : jeux (exception block) reste block
    p.select_option("select[data-mac='aa:bb:cc:dd:ee:01'][data-exc='adulte']", "observe")
    p.select_option("select[data-mac='aa:bb:cc:dd:ee:01'][data-exc='jeux']", "block")
    p.click("[data-action='enregistrer-appareil'][data-mac='aa:bb:cc:dd:ee:01']")
    p.wait_for_timeout(300)
    assert messages == []                                                                    # jeux est DÉJÀ en block pour cet appareil (exception actuelle) : rien de nouveau
    ctx.close()
    apps = json.loads(json.dumps(APPAREILS))
    apps["assignes"][0].update({"profil": "defaut", "exceptions": {}})                          # aucun blocage actuellement
    ctx, p, _, requetes = _page(navigateur, rep={("GET", "/appareils"): (200, apps)})
    messages.clear()
    p.on("dialog", lambda d: (messages.append(d.message), d.dismiss()))
    onglet(p, "appareils")
    p.wait_for_selector("[data-mac='aa:bb:cc:dd:ee:01']")
    p.select_option("select[data-mac='aa:bb:cc:dd:ee:01'][data-exc='adulte']", "block")          # NOUVEAU blocage
    p.click("[data-action='enregistrer-appareil'][data-mac='aa:bb:cc:dd:ee:01']")
    p.wait_for_timeout(300)
    assert messages and "BLOCAGE" in messages[0] and "adulte" in messages[0].lower()
    assert not [r for r in requetes if r[0] == "POST" and r[1].startswith("/appareils/")]       # refusé : rien envoyé
    ctx.close()


def test_assigner_a_un_profil_qui_bloque_demande_confirmation(navigateur):
    ctx, p, _, requetes = _page(navigateur)
    messages = []
    p.on("dialog", lambda d: (messages.append(d.message), d.dismiss()))
    onglet(p, "appareils")
    p.wait_for_selector("[data-connu='aa:bb:cc:dd:ee:09']")
    p.select_option("[data-connu='aa:bb:cc:dd:ee:09'] select", "enfants")
    p.click("[data-action='assigner'][data-mac='aa:bb:cc:dd:ee:09']")
    p.wait_for_timeout(300)
    assert messages and "BLOCAGE" in messages[0] and "adulte" in messages[0].lower()
    assert not [r for r in requetes if r[0] == "POST" and r[1].startswith("/appareils/")]
    ctx.close()
