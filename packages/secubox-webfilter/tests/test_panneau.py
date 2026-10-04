# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Panneau d'observation de secubox-webfilter dans un vrai navigateur, API simulée (#1962)."""
import json
import re
from pathlib import Path

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


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _page(navigateur, rep=None, token="jeton-admin"):
    """`rep` : {(méthode, chemin): (statut, corps)} ; défaut = tout répond normalement."""
    rep = {("GET", "/etat"): (200, ETAT), ("GET", "/stats"): (200, STATS), ("GET", "/categories/adulte/domaines"): (200, DOMAINES),
           ("GET", "/categories/jeux/domaines"): (200, {"categorie": "jeux", "jours": 7, "domaines": []}), ("POST", "/sync"): (202, {"statut": "demandee"}),
           **(rep or {})}
    ctx = navigateur.new_context()
    if token:
        ctx.add_init_script(f"localStorage.setItem('sbx_token', '{token}')")
    p = ctx.new_page()
    erreurs, requetes = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(route):
        chemin = re.sub(r"^.*?/api/v1/webfilter", "", route.request.url).split("?")[0]
        requetes.append((route.request.method, chemin, route.request.headers.get("authorization")))
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
