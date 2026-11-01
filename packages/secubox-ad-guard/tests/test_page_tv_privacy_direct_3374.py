# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 5b (#3374) : vue « En direct » de /tv-privacy/ (Playwright) — rafraîchissement à curseur, choix différés, file, annulation,
aucun rafraîchissement pendant une confirmation ouverte (défaut subi dans la Flotte), panneaux alignés en haut, IPv6 brute masquée."""
import concurrent.futures
import json
import pathlib
import re

import pytest

RACINE = pathlib.Path(__file__).resolve().parents[1]
SRC = (RACINE / "www" / "tv-privacy" / "index.html").read_text(encoding="utf-8")
CODE = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", SRC, flags=re.S))
MAC = "02:00:5e:00:00:01"
HOSTILE = "<img src=x onerror=window.xss=1>"


def test_onglet_en_direct_reserve_a_l_admin_et_sans_confirm_natif():
    assert 'id="t-direct" aria-controls="v-direct"' in SRC and 'id="v-direct" role="tabpanel"' in SRC
    assert "el('t-direct').hidden=!etat.admin" in CODE
    assert not re.search(r"\b(confirm|alert|prompt)\(", CODE)
    assert "'/protection/direct?depuis='" in CODE and "ecrire('/protection/assistant/choix'" in CODE
    assert "ecrire('/protection/assistant/annuler'" in CODE and "ecrire('/protection/assistant/guide'" in CODE
    assert "if(!document.hidden&&!el('v-direct').hidden&&!etat.ouvert&&!DEMO)chargerDirect();" in CODE


sync_api = pytest.importorskip("playwright.sync_api")


def _dec(i, domaine, **k):
    d = {"id": i, "ts": 1761954000 + i, "type": "repli", "mac": MAC, "appareil": "TV salon", "domaine": domaine, "categorie": "PUBLICITE",
         "protegee": False, "confiance": 70, "raison": f"apparu {i} s après le blocage de pagead2", "etat": "nouvelle", "actionnable": True,
         "action": None}
    d.update(k)
    return d


def _page(scenario, n_ev=1, client_ev=None, proteger=False, applique=None, sans_domaine=False, etats=None, diag=None):
    """Page réelle, API simulée avec état : la file suit les POST (choix, annuler) ; `depuis` > 0 rend UNE nouvelle découverte, une fois."""
    premier = [_dec(2, "relais-pub.example.net"), _dec(1, "x.example.org", appareil=HOSTILE)]
    if applique:
        premier[0]["action"] = {"id": "a" * 16, "choix": "bloquer", "etat": "applique", "applique": applique, "raison": "", "force": False}
    if sans_domaine:
        premier.insert(0, _dec(4, "203.0.113.9:443", type="sans-dns", actionnable=False, vu_possible=True, vu=False, categorie="INCONNU"))
    nouveau = [_dec(3, "nouveau-pub.example.net", raison="apparu 3 s après le blocage de ads.example.com")]
    analyse = {"cache": True, "admin": True, "genere": 1761955200, "total": 0, "categories": ["PUBLICITE"], "protegees": [], "sources": [],
               "metriques": {"domaines": 1, "requetes": 5, "bloquees": 0, "part_bloquee": 0, "par_categorie": {"PUBLICITE": {"domaines": 1, "requetes": 5}}},
               "agregats": [], "lignes": []}
    g = {"appareil": client_ev or "TV salon", "client": client_ev or "192.0.2.1", "domaine": "pub.example.com", "occurrences": 7,
         "premier": 1761955000, "dernier": 1761955100, "decision": "BLOCKED", "bloquees": 7, "erreurs": 0, "nouveau": False}
    evenements = {"heures": 1, "total": n_ev, "groupes": [dict(g, domaine=f"d{i}.example.com") for i in range(n_ev)]}
    appareils = {"appareils": [{"mac": MAC, "nom": "TV salon", "ips": ["192.0.2.1"], "mode": "auto"}], "profils": []}

    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e))
            pg = nav.new_page()
            erreurs, posts, gets = [], [], []
            file, vu = [], {"nouveau": False}
            pg.on("pageerror", lambda e: erreurs.append(str(e)))

            def api(route):
                u = route.request.url
                if route.request.method == "POST":
                    corps = json.loads(route.request.post_data or "{}")
                    posts.append((u.split("/adblock-tv", 1)[1], corps))
                    if u.endswith("/assistant/choix"):
                        if proteger and corps.get("choix") == "bloquer" and not corps.get("force"):
                            return route.fulfill(status=409, content_type="application/json",
                                                 body=json.dumps({"detail": "catégorie STREAMING protégée (lecture des vidéos, DRM…) : confirmer le blocage (force)"}))
                        x = {"id": f"{len(posts):016x}", "mac": corps["mac"], "domaine": corps["domaine"], "choix": corps["choix"],
                             "force": corps.get("force", False), "etat": "en-attente", "applique": None, "raison": "", "cree": 1761955300}
                        file.append(x)
                        return route.fulfill(status=200, content_type="application/json", body=json.dumps(x))
                    if u.endswith("/assistant/vu"):
                        return route.fulfill(status=200, content_type="application/json", body=json.dumps({"decouverte": corps["decouverte"], "vu": True}))
                    if u.endswith("/assistant/annuler"):
                        file[:] = [x for x in file if x["id"] != corps["id"]]
                        return route.fulfill(status=200, content_type="application/json", body=json.dumps({"annule": corps["id"]}))
                    return route.fulfill(status=200, content_type="application/json", body=json.dumps({"mac": MAC, "guide": True}))
                gets.append(u)
                if "/protection/direct" in u:
                    depuis = int(re.search(r"depuis=(\d+)", u).group(1))
                    dec = premier if depuis == 0 else ([] if vu["nouveau"] else nouveau)
                    if depuis:
                        vu["nouveau"] = True
                    corps = {"decouvertes": dec, "dernier_id": max([d["id"] for d in dec] or [depuis]), "file": list(file), "candidats": [],
                             "etats": (etats or {}) if depuis else {},
                             "appareils": [{"mac": MAC, "nom": "TV salon", "guide": False}], "genere": 1761955300}
                elif "/protection/analyse" in u:
                    corps = analyse
                elif "/protection/evenements" in u:
                    corps = evenements
                elif "/protection/diagnostic" in u and diag:
                    corps = diag
                elif "/protection/" in u:
                    corps = {}
                else:
                    corps = appareils
                route.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
            pg.route("http://t.test/api/**", api)
            pg.route("http://t.test/shared/**", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
            pg.route("http://t.test/tv-privacy/**", lambda r: r.fulfill(status=200, content_type="text/html", body=SRC))
            pg.clock.install()
            pg.goto("http://t.test/tv-privacy/")
            pg.wait_for_timeout(500)
            r = scenario(pg, gets, posts)
            nav.close()
            return ("ok", r, erreurs, posts, gets)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=120)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1:]


def _ouvrir(pg):
    pg.click("#t-direct")
    pg.wait_for_timeout(300)


def _directs(gets):
    return [u for u in gets if "/protection/direct" in u]


def test_rafraichissement_a_curseur_choix_file_et_annulation():
    def sc(pg, gets, posts):
        _ouvrir(pg)
        t1 = pg.inner_text("#di-liste")
        pg.clock.run_for(16000)
        pg.wait_for_timeout(300)
        t2 = pg.inner_text("#di-liste")
        pg.click("#di-liste tr[data-id='3'] >> text=Plus tard")
        pg.wait_for_timeout(300)
        t3 = pg.inner_text("#di-liste tr[data-id='3']")
        pg.click("#di-liste tr[data-id='3'] >> text=Annuler")
        pg.wait_for_timeout(300)
        t4 = pg.inner_text("#di-liste tr[data-id='3']")
        pg.click("#di-liste tr[data-id='2'] >> text=Confirmer le blocage")
        pg.wait_for_timeout(200)
        pg.click("#di-liste tr[data-id='2'] .confirm button.danger")
        pg.wait_for_timeout(300)
        return t1, t2, t3, t4, pg.inner_text("#di-liste tr[data-id='2']"), pg.evaluate("window.xss")
    (t1, t2, t3, t4, t5, xss), erreurs, posts, gets = _page(sc)
    assert not erreurs and xss is None
    assert "relais-pub.example.net" in t1 and "TV salon" in t1 and "apparu 2 s après le blocage de pagead2" in t1 and HOSTILE in t1
    assert "PUBLICITE" in t1 and "70" in t1
    d = _directs(gets)
    assert "depuis=0" in d[0] and any("depuis=2" in u for u in d[1:])                       # curseur
    assert all(re.search(r"limite=\d+", u) for u in d)
    assert "nouveau-pub.example.net" in t2 and "relais-pub.example.net" in t2                 # ajout, rien d'effacé
    assert "en attente" in t3 and "Annuler" in t3
    assert "Plus tard" in t4 and "en attente" not in t4                                      # annulée : les choix reviennent
    assert posts[0] == ("/protection/assistant/choix", {"mac": MAC, "domaine": "nouveau-pub.example.net", "choix": "plus-tard",
                                                        "force": False, "decouverte": 3})
    assert posts[1][0] == "/protection/assistant/annuler" and posts[1][1]["id"]
    assert posts[2] == ("/protection/assistant/choix", {"mac": MAC, "domaine": "relais-pub.example.net", "choix": "bloquer", "force": False,
                                                        "decouverte": 2})
    assert "en attente" in t5


def test_aucun_rafraichissement_pendant_une_confirmation_ouverte():
    def sc(pg, gets, posts):
        _ouvrir(pg)
        pg.click("#di-liste tr[data-id='2'] >> text=C’est légitime")
        pg.wait_for_timeout(200)
        avant = len(_directs(gets))
        pg.clock.run_for(120000)                                       # huit périodes de 15 s, plus celle de la page (60 s)
        pg.wait_for_timeout(300)
        pendant = len(_directs(gets))
        toujours = pg.locator("#di-liste .confirm").count()
        pg.click("#di-liste .confirm >> text=Annuler")
        pg.clock.run_for(16000)
        pg.wait_for_timeout(300)
        return avant, pendant, toujours, len(_directs(gets))
    (avant, pendant, toujours, apres), erreurs, posts, _g = _page(sc)
    assert not erreurs and not posts
    assert pendant == avant and toujours == 1
    assert apres > pendant


def test_categorie_protegee_demande_force_dans_la_page():
    def sc(pg, gets, posts):
        _ouvrir(pg)
        pg.click("#di-liste tr[data-id='2'] >> text=Confirmer le blocage")
        pg.click("#di-liste tr[data-id='2'] .confirm button.danger")
        pg.wait_for_timeout(300)
        texte = pg.inner_text("#di-liste tr[data-id='2']")
        pg.click("#di-liste tr[data-id='2'] .confirm button.danger")
        pg.wait_for_timeout(300)
        return texte
    texte, erreurs, posts, _g = _page(sc, proteger=True)
    assert "protégée" in texte and not erreurs
    assert [p[1].get("force") for p in posts] == [False, True]


def test_action_appliquee_affiche_l_heure():
    (t,), erreurs, _p, _g = _page(lambda pg, g, p: (_ouvrir(pg), pg.inner_text("#di-liste tr[data-id='2']"))[1:], applique=1761955440)
    assert re.search(r"appliqué à \d\d:\d\d", t) and "Annuler" not in t and not erreurs


def test_apprentissage_guide_par_appareil():
    def sc(pg, gets, posts):
        _ouvrir(pg)
        pg.check("#di-guides input[type=checkbox]")
        pg.wait_for_timeout(300)
        return pg.inner_text("#di-guides")
    texte, erreurs, posts, _g = _page(sc)
    assert "TV salon" in texte and not erreurs
    assert posts == [("/protection/assistant/guide", {"mac": MAC, "actif": True})]


# ── défauts relevés par le propriétaire ──
def test_panneaux_de_la_vue_generale_alignes_en_haut_sans_etirement():
    def sc(pg, gets, posts):
        return pg.evaluate("() => [...document.querySelectorAll('#v-generale .grille > .pan')].map(p => p.getBoundingClientRect().height)")
    hauteurs, erreurs, _p, _g = _page(sc, n_ev=30)
    assert not erreurs
    assert hauteurs[0] < hauteurs[1] / 2, hauteurs                         # « Domaines par catégorie » ne s'étire plus


def test_evenement_d_une_ipv6_brute_affiche_appareil_inconnu():
    def sc(pg, gets, posts):
        c = pg.locator("#evenements tr >> nth=0 >> td >> nth=0")
        return c.inner_text(), c.get_attribute("title")
    (texte, titre), erreurs, _p, _g = _page(sc, client_ev="2a01:e0a:abc:1::1234")
    assert texte == "appareil inconnu (IPv6)" and titre == "2a01:e0a:abc:1::1234" and not erreurs


# ── passe 2 ──
def test_i2_vu_plus_tard_pour_une_decouverte_sans_domaine():
    def sc(pg, gets, posts):
        _ouvrir(pg)
        avant = pg.inner_text("#di-liste tr[data-id='4']")
        pg.click("#di-liste tr[data-id='4'] >> text=Vu / plus tard")
        pg.wait_for_timeout(300)
        return avant, pg.inner_text("#di-liste tr[data-id='4']")
    (avant, apres), erreurs, posts, _g = _page(sc, sans_domaine=True)
    assert "Confirmer le blocage" not in avant and not erreurs
    assert posts == [("/protection/assistant/vu", {"mac": MAC, "decouverte": 4})]
    assert "vu" in apres and "Vu / plus tard" not in apres


def test_m3_etat_d_une_decouverte_deja_affichee_mis_a_jour():
    def sc(pg, gets, posts):
        _ouvrir(pg)
        pg.clock.run_for(16000)
        pg.wait_for_timeout(300)
        return pg.inner_text("#di-liste tr[data-id='1']")
    t, erreurs, _p, _g = _page(sc, etats={"1": "legitime"})
    assert "légitime" in t and "Confirmer le blocage" not in t and not erreurs


def test_m7_erreurs_dns_du_diagnostic_sans_ipv6_brute():
    def sc(pg, gets, posts):
        pg.click("#t-diagnostic")
        pg.wait_for_timeout(300)
        c = pg.locator("#d-erreurs tr >> nth=0 >> td >> nth=0")
        return c.inner_text(), c.get_attribute("title")
    diag = {"erreurs_dns": [{"appareil": "2a01:e0a:abc:1::1234", "domaine": "api.example.net", "erreurs": 3, "dernier": 1761955000}],
            "pauses": [], "exceptions": [], "retours_arriere": []}
    (texte, titre), erreurs, _p, _g = _page(sc, diag=diag)
    assert texte == "appareil inconnu (IPv6)" and titre == "2a01:e0a:abc:1::1234" and not erreurs
