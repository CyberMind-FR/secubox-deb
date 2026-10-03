# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Onglet « DNS AdBlock TV » (POC #1943) dans un vrai navigateur, API simulée : rendu, bascule de mode, ajout de domaine, texte échappé."""
import json
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "ad-guard" / "index.html"


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _page(navigateur, appels, etat):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(route):
        req = route.request
        chemin = re.sub(r"^.*?/api/v1/ad-guard", "", req.url).split("?")[0]
        corps = req.post_data
        appels.append((req.method, chemin, json.loads(corps) if corps else None))
        if chemin == "/adblock-tv/status" and "status_brut" in etat:
            r = etat["status_brut"]                                                 # réponse inattendue (ex. {"detail": "Not Found"})
        elif chemin == "/adblock-tv/status":
            r = {"actif": etat["actif"], "clients": etat["clients"], "erreur": None, "dropin_present": etat["actif"],
                 "listes": {"domaines": 32, "problemes": [], "par_categorie": {}}, "compteurs": {"requetes": 10, "domaines_uniques": 4, "bloques": 3}}
        elif chemin == "/adblock-tv/stats":
            r = {"requetes": 10, "domaines_uniques": 4, "classes_resolus": {"tracking": 2}, "classes_bloques": {"advertising": 3},
                 "par_decision": {"BLOCKED": 3, "ALLOWED": 7},
                 "top_bloques": [{"domaine": "<img src=x onerror=window.__pwn=1>.example", "categorie": "advertising", "hits": 3}]}
        elif chemin == "/adblock-tv/auto/regles":
            r = etat.get("auto_regles", {"regles": [], "compteurs": {}})
        elif chemin == "/adblock-tv/auto/reglage":
            r = etat.get("auto_reglage", {})
        elif chemin == "/adblock-tv/custom":
            r = {"domaines": ["mon-tracker.example"]}
        elif chemin == "/adblock-tv/sonde":
            r = {"nom": "tabc123.sbx-dnspath.invalid"}
        elif chemin == "/adblock-tv/path-test":
            r = {"recue": True, "lecture": "la box a reçu cette requête", "evenements": [{"client": "192.168.1.50", "decision": "ALLOWED"}]}
        else:
            r = {}
        route.fulfill(status=200, content_type="application/json", body=json.dumps(r))
    # Playwright n'intercepte pas file:// : la page est servie, par interception, sous un nom http fictif.
    p.route("http://sbx.test/api/v1/ad-guard/**", api)
    p.route("http://sbx.test/shared/**", lambda r: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://sbx.test/", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.goto("http://sbx.test/")
    return ctx, p, erreurs


def test_onglet_affiche_statistiques_top_et_appareils_sans_executer_de_html(navigateur):
    appels = []
    etat = {"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "Freebox TV salon", "mode": "block"}]}
    ctx, p, erreurs = _page(navigateur, appels, etat)
    p.click("button[data-tab=adblocktv]")
    p.wait_for_selector("#tv-stats .stat-card")
    assert p.is_checked("#tv-actif") and p.is_checked("input[name=tv-mode][value=block]")
    assert "Requêtes DNS" in p.inner_text("#tv-stats") and "Bloqués" in p.inner_text("#tv-stats")
    assert "Freebox TV salon" in p.inner_text("#tv-clients") and "mon-tracker.example" in p.inner_text("#tv-custom")
    assert p.evaluate("window.__pwn === undefined") and p.evaluate("document.querySelectorAll('#tv-top img').length") == 0     # nom piégé : affiché en texte
    assert "suppression de publicités" in p.inner_text("#adblocktv")                                                        # formulation honnête présente
    assert not erreurs
    ctx.close()


def test_bascule_de_mode_et_ajout_de_domaine_appellent_l_api(navigateur):
    appels = []
    etat = {"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV", "mode": "observe"}]}
    ctx, p, _ = _page(navigateur, appels, etat)
    p.click("button[data-tab=adblocktv]")
    p.wait_for_selector("#tv-stats .stat-card")
    p.check("input[name=tv-mode][value=block]")
    p.fill("#tv-new-domaine", "pub.example.org")
    p.click("text=Ajouter >> nth=-1")
    p.uncheck("#tv-actif")
    p.wait_for_timeout(300)
    assert ("POST", "/adblock-tv/mode", {"mode": "block"}) in appels
    assert ("POST", "/adblock-tv/custom", {"domaine": "pub.example.org"}) in appels
    assert ("POST", "/adblock-tv/etat", {"actif": False}) in appels
    ctx.close()


def test_dns_path_test_depuis_l_interface(navigateur):
    appels = []
    ctx, p, _ = _page(navigateur, appels, {"actif": True, "clients": []})
    p.click("button[data-tab=adblocktv]")
    p.click("text=Nouvelle sonde")
    p.wait_for_function("document.getElementById('tv-sonde-nom').textContent.includes('sbx-dnspath.invalid')")
    p.click("text=La box l'a-t-elle reçue ?")
    p.wait_for_function("document.getElementById('tv-path').textContent.includes('✅')")
    assert "192.168.1.50" in p.inner_text("#tv-path")
    ctx.close()


def test_visualisation_flux_sources_services_et_serie_sans_executer_de_html(navigateur):
    appels = []
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    piege = "<img src=x onerror=window.__pwn=1>.example"

    def api(route):
        chemin = re.sub(r"^.*?/api/v1/ad-guard", "", route.request.url).split("?")[0]
        appels.append(route.request.url)
        r = {}
        if chemin == "/adblock-tv/status":
            r = {"actif": True, "clients": [], "erreur": None, "listes": {"domaines": 32}, "compteurs": {}}
        elif chemin == "/adblock-tv/stats":
            r = {"requetes": 0, "domaines_uniques": 0, "classes_resolus": {}, "classes_bloques": {}, "par_decision": {}, "top_bloques": []}
        elif chemin == "/adblock-tv/sources":
            r = {"sources": [{"source": "38:07:16:93:4e:95", "nom": "Freebox TV <b>salon</b>", "adresses": ["192.168.1.95", "2a01:e0a:dec:c4e0:c147:c3cf:6dd7:3429"],
                              "requetes": 288, "bloquees": 222, "taux_blocage": 0.771, "domaines_uniques": 26, "par_type": {"publicite": 200, "contenu": 88}, "derniere": 1}]}
        elif chemin == "/adblock-tv/live":
            r = {"evenements": [{"ts": 1791030000, "client": "192.168.1.95", "domaine": piege, "qtype": "A", "decision": "BLOCKED", "categorie": "advertising",
                                 "service": "FreeWheel", "type": "publicite"}]}
        elif chemin == "/adblock-tv/serie":
            r = {"pas_s": 300, "points": [{"ts": 1791029700, "requetes": 40, "bloquees": 30, "classees": 30}, {"ts": 1791030000, "requetes": 10, "bloquees": 2, "classees": 2}]}
        elif chemin == "/adblock-tv/flux":
            r = {"domaines": [], "services": [{"service": "FreeWheel", "type": "publicite", "requetes": 200, "bloquees": 200, "domaines": 3}]}
        elif chemin == "/adblock-tv/custom":
            r = {"domaines": []}
        route.fulfill(status=200, content_type="application/json", body=json.dumps(r))
    p.route("http://sbx.test/api/v1/ad-guard/**", api)
    p.route("http://sbx.test/shared/**", lambda r: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://sbx.test/", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.goto("http://sbx.test/")
    p.click("button[data-tab=adblocktv]")
    p.wait_for_selector("#tv-live tr td")
    assert "FreeWheel" in p.inner_text("#tv-live") and "BLOCKED" in p.inner_text("#tv-live") and "publicite" in p.inner_text("#tv-live")
    assert p.evaluate("window.__pwn === undefined") and p.evaluate("document.querySelectorAll('#tv-live img, #tv-sources b').length") == 0     # texte, jamais du HTML
    assert "77 %" in p.inner_text("#tv-sources") and "publicite 200" in p.inner_text("#tv-sources")
    assert p.evaluate("document.querySelectorAll('#tv-serie svg rect').length") == 4
    assert "FreeWheel" in p.inner_text("#tv-services")
    assert any("serie?" in u for u in appels) and any("live?" in u for u in appels)
    p.select_option("#tv-source", "38:07:16:93:4e:95")
    p.wait_for_timeout(400)
    assert any("source=38%3A07%3A16%3A93%3A4e%3A95" in u for u in appels)               # le filtre par source est transmis
    assert "pas les volumes" in p.inner_text("#adblocktv")
    assert not erreurs
    ctx.close()


# ── mode automatique (#1954) ───────────────────────────────────────────────────────────────────────────────────────────────
PIEGE = "<img src=x onerror=window.__pwn=1>.example"


def _regle(rid, etat, domaine="ad.example.com", risque="faible", fin=0, hist=()):
    return {"id": rid, "appareil": "tv-banc", "domaine": domaine, "etat": etat, "score": 70, "risque": risque, "motif": "vu dans 2 coupures",
            "fin_essai": fin, "historique": list(hist), "origine": "auto"}


def _etat_auto():
    import time
    t = int(time.time())
    return {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"}],
            "auto_reglage": {"auto_essai": False, "appareils_auto": ["tv-banc"], "essai_h": 24},
            "auto_regles": {"regles": [
                _regle("aaaaaaaaaaaa", "candidat", PIEGE, "partage"),
                _regle("bbbbbbbbbbbb", "essai", "pub.example.com", fin=t + 7200, hist=[{"ts": t - 60, "de": "candidat", "vers": "essai", "origine": "admin", "motif": "action essayer"}]),
                _regle("cccccccccccc", "confirme", "ok.example.com"),
                _regle("dddddddddddd", "rejete", "non.example.com")], "compteurs": {}}}


def test_panneau_auto_rendu_sans_executer_de_html_et_boutons_selon_l_etat(navigateur):
    ctx, p, erreurs = _page(navigateur, [], _etat_auto())
    p.click("button[data-tab=adblocktv]")
    p.wait_for_selector("#auto-candidats tr")
    p.evaluate("document.querySelector('#auto-carte details').open = true")             # section repliée par défaut
    assert PIEGE in p.inner_text("#auto-candidats")                                    # affiché en TEXTE
    assert p.evaluate("window.__pwn === undefined") and p.evaluate("document.querySelectorAll('#auto-carte img').length") == 0
    assert "peut servir aussi le contenu" in p.inner_text("#auto-candidats")           # libellé local du risque « partagé »
    assert p.inner_text("#auto-candidats").count("Essayer") == 1 and "Confirmer" not in p.inner_text("#auto-candidats")
    assert "Confirmer" in p.inner_text("#auto-essai") and "Retirer" in p.inner_text("#auto-essai") and "Essayer" not in p.inner_text("#auto-essai")
    assert "Confirmer" not in p.inner_text("#auto-confirmees") and "ok.example.com" in p.inner_text("#auto-confirmees")
    assert "non.example.com" in p.inner_text("#auto-ecartees") and "Rouvrir" in p.inner_text("#auto-ecartees")
    assert "action essayer" in p.inner_text("#auto-journal") and "vous" in p.inner_text("#auto-journal")
    assert p.locator("button.ca-ne-marche-plus").count() == 1
    assert not erreurs
    ctx.close()


def test_panneau_auto_reponse_vide_ne_leve_aucune_exception(navigateur):
    ctx, p, erreurs = _page(navigateur, [], {"actif": True, "clients": []})            # l'API ne renvoie que {} pour les routes auto
    p.click("button[data-tab=adblocktv]")
    p.wait_for_selector("#auto-candidats tr")
    assert "Aucun candidat" in p.inner_text("#auto-candidats") and "Aucun appareil en mode auto" in p.inner_text("#auto-appareils")
    assert p.locator("button.ca-ne-marche-plus").count() == 0                           # rien à retirer : pas de bouton
    assert not erreurs
    ctx.close()


def test_actions_du_panneau_appellent_les_bonnes_routes(navigateur):
    appels = []
    ctx, p, _ = _page(navigateur, appels, _etat_auto())
    p.click("button[data-tab=adblocktv]")
    p.wait_for_selector("#auto-essai tr")
    p.evaluate("document.querySelector('#auto-carte details').open = true")
    p.once("dialog", lambda d: d.accept())
    p.click("#auto-candidats button:has-text('Essayer')")
    p.click("#auto-essai button:has-text('Confirmer')")
    p.click("#auto-essai button:has-text('Retirer')")
    p.click("#auto-ecartees button:has-text('Rouvrir')")
    p.wait_for_timeout(300)
    posts = [c for (m, c, _) in appels if m == "POST"]
    assert "/adblock-tv/auto/regles/aaaaaaaaaaaa/essayer" in posts and "/adblock-tv/auto/regles/bbbbbbbbbbbb/confirmer" in posts
    assert "/adblock-tv/auto/regles/bbbbbbbbbbbb/retirer" in posts and "/adblock-tv/auto/regles/dddddddddddd/rouvrir" in posts
    ctx.close()


def test_ca_ne_marche_plus_demande_confirmation_puis_appelle_la_route(navigateur):
    appels = []
    ctx, p, _ = _page(navigateur, appels, _etat_auto())
    p.click("button[data-tab=adblocktv]")
    p.wait_for_selector("button.ca-ne-marche-plus")
    p.once("dialog", lambda d: d.dismiss())                                             # refus : rien n'est envoyé
    p.click("button.ca-ne-marche-plus")
    p.wait_for_timeout(200)
    assert not [c for (m, c, _) in appels if m == "POST" and c.endswith("/ca-ne-marche-plus")]
    p.once("dialog", lambda d: d.accept())
    p.click("button.ca-ne-marche-plus")
    p.wait_for_timeout(300)
    assert [c for (m, c, _) in appels if m == "POST" and c == "/adblock-tv/auto/appareils/tv-banc/ca-ne-marche-plus"]
    ctx.close()


def test_onglet_ne_plante_pas_quand_l_api_repond_une_erreur(navigateur):
    """Constaté sur gk2 (#1954) : l'agrégateur servait l'ancien code, /adblock-tv/status rendait {"detail": "Not Found"} et la page levait
    « st.listes is undefined » au lieu d'afficher un message."""
    ctx, p, erreurs = _page(navigateur, [], {"actif": True, "clients": [], "status_brut": {"detail": "Not Found"}})
    p.click("button[data-tab=adblocktv]")
    p.wait_for_timeout(500)
    assert "indisponible" in p.inner_text("#tv-etat").lower()
    assert not erreurs
    ctx.close()
