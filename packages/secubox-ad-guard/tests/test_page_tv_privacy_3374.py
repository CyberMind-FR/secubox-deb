# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3374 — page SBX TV Privacy : cinq vues (lot 3), coque de l'administration, routes existantes seulement, données par textContent,
confirmations intégrées, analyseur côté serveur, bouton « Ça ne marche plus ? Je débloque »."""
import concurrent.futures
import json
import pathlib
import re

import pytest

RACINE = pathlib.Path(__file__).resolve().parents[1]
PAGE = RACINE / "www" / "tv-privacy" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
CODE = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", SRC, flags=re.S))


def test_en_tete_spdx_et_titre():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC[:400]
    assert "<title>SBX TV Privacy</title>" in SRC


def test_cinq_vues_en_onglets_accessibles():
    for v in ("generale", "equipements", "analyseur", "protection", "diagnostic"):
        assert f'id="v-{v}" role="tabpanel"' in SRC and f'id="t-{v}" aria-controls="v-{v}"' in SRC
    assert SRC.count('role="tab"') == 5 and "aria-selected" in SRC and 'role="tablist"' in SRC


def test_coque_de_l_administration_menu_lateral():
    """Lot 3 : la page s'affiche DANS l'admin (menu latéral commun), hors ?embed=1 et hors démonstration."""
    assert '<nav class="sidebar" id="sidebar"' in SRC and '<link rel="stylesheet" href="/shared/sidebar-light.css">' in SRC
    assert "sb.src='/shared/sidebar.js'" in CODE and "if(EMB||DEMO)document.body.classList.add('emb');" in CODE
    assert '<main class="principal">' in SRC and "body:not(.emb) .principal{margin-left:220px" in SRC
    assert "@media (max-width:768px){body:not(.emb) .principal{margin-left:0" in SRC          # téléphone : pas de colonne vide
    assert "#sidebar .nav-section-title" in CODE                                              # repli des sections malgré la CSP


def test_message_honnete_et_bouton_debloque():
    assert "bloque les pubs que la TV va chercher, pas celles qu'un service insère dans sa propre vidéo" in SRC
    assert "Ça ne marche plus ? Je débloque" in SRC
    assert "ecrire('/protection/usager/debloquer',corps)" in CODE and "source('/protection/usager/tv')" in CODE
    for m in ("15", "60", "240"):
        assert f'data-minutes="{m}"' in SRC


def test_routes_appelees_existantes_seulement():
    from api import dnstv_routes as r
    from api import dnstv_lot3_routes as l3
    existantes = {x.path.replace("/adblock-tv", "", 1) for x in [*r.router.routes, *l3.router.routes]}
    citees = {c for c in re.findall(r"(?:lire|ecrire|source|telecharger|geste)\('(/[a-z/.-]+?)(?:\?|')", CODE) if not c.endswith("/")} | {"/appareils/{mac}/profil"}
    assert {"/appareils", "/classification", "/protection/analyse", "/protection/evenements", "/protection/usager/tv", "/protection/usager/debloquer",
            "/protection/pause", "/protection/observe", "/protection/reprendre", "/protection/exceptions", "/protection/journal",
            "/protection/journal.csv", "/protection/analyse.csv", "/protection/diagnostic", "/mode"} <= citees
    assert "'/appareils/'+encodeURIComponent(a.mac)+'/profil'" in CODE
    assert citees <= existantes, citees - existantes
    assert "BASE='/api/v1/ad-guard/adblock-tv'" in CODE


def test_ecritures_a_l_identique_et_confirmees():
    assert CODE.count("method:'POST'") == 1                           # une seule fonction d'écriture
    assert "ecrire('/classification',{domaine:d.domaine,categorie:" in CODE
    assert "{type:sel.value||null}" in CODE
    assert CODE.count("'Confirmer'") == 3 and "Corriger le profil" in CODE
    assert not re.search(r"\b(confirm|alert|prompt)\(", CODE)
    assert "if(DEMO)return Promise.reject" in CODE                   # aucune écriture en démonstration


def test_aucun_innerhtml_ni_ressource_externe():
    assert "innerHTML" not in CODE and "outerHTML" not in CODE and "insertAdjacentHTML" not in CODE and "document.write" not in CODE
    assert "<script src" not in SRC and "http://" not in CODE and "https://" not in CODE      # le menu est chargé par le script, hors démo
    assert "textContent" in CODE


def test_jeton_sbx_token_et_hauteur_postee():
    assert "localStorage.getItem('sbx_token')" in CODE and "Authorization='Bearer '" in CODE and "credentials:'same-origin'" in CODE
    assert "sbxVue" in CODE and "onglet:'tv-privacy'" in CODE and "min-height:100vh" not in SRC
    assert "@container a" in SRC


def test_menu_et_installation():
    m = json.loads((RACINE / "menu.d" / "161-tv-privacy.json").read_text(encoding="utf-8"))
    assert m["name"] == "SBX TV Privacy" and m["path"] == "/tv-privacy/" and m["category"] == "wall"
    regles = (RACINE / "debian" / "rules").read_text(encoding="utf-8")
    assert "cp -r www/tv-privacy/. debian/secubox-ad-guard/usr/share/secubox/www/tv-privacy/" in regles


sync_api = pytest.importorskip("playwright.sync_api")
HOSTILE = "<img src=x onerror=window.xss=1>"


def _page(scenario, statut=200, chemin="/tv-privacy/", n_ev=1):
    appareils = {"appareils": [{"mac": "02:00:5e:00:00:01", "nom": HOSTILE, "ips": ["2001:db8::1", "192.0.2.1"], "mode": "auto",
                                "modes_divergents": True, "profil": "LG_WEBOS", "profil_source": "nac", "profil_confiance": 90}],
                 "profils": ["LG_WEBOS", "INCONNU"]}
    ligne = {"domaine": "ads.example.com", "mac": "02:00:5e:00:00:01", "nom": HOSTILE, "categorie": "PUBLICITE", "source": "liste", "confiance": 90,
             "requetes": 12, "bloquees": 12, "derniere_observation": 1761955000, "protegee": False}
    analyse = {"cache": True, "admin": True, "genere": 1761955200, "total": 57698, "decalage": 0, "limite": 25, "agreger": "racine",
               "categories": ["PUBLICITE", "STREAMING"], "protegees": ["STREAMING"], "sources": ["liste", "aucune"],
               "metriques": {"domaines": 2, "requetes": 42, "bloquees": 12, "part_bloquee": 0.2857, "nouveaux": 1,
                             "par_categorie": {"PUBLICITE": {"domaines": 1, "requetes": 12}, "STREAMING": {"domaines": 1, "requetes": 30}},
                             "top_domaines": [{"cle": "video.example.org", "requetes": 30, "bloquees": 0, "part_bloquee": 0}],
                             "top_appareils": [{"cle": "02:00:5e:00:00:01", "nom": HOSTILE, "requetes": 42, "bloquees": 12, "part_bloquee": 0.28}]},
               "agregats": [{"cle": "example.com", "domaines": 1, "requetes": 12, "bloquees": 12, "part_bloquee": 1}],
               "lignes": [dict(ligne), dict(ligne, domaine="video.example.org", categorie="STREAMING", protegee=True, bloquees=0, requetes=30)]}
    evenements = {"heures": 1, "total": 1, "groupes": [{"appareil": HOSTILE, "client": "192.0.2.1", "domaine": "pub.example.com", "occurrences": 7,
                                                         "premier": 1761955000, "dernier": 1761955100, "decision": "BLOCKED", "bloquees": 7, "erreurs": 0, "nouveau": True}]}
    if n_ev > 1:                                                          # liste longue : la page n'en montre qu'une partie
        g0 = evenements["groupes"][0]
        evenements = {"heures": 1, "total": n_ev, "groupes": [dict(g0, domaine=f"d{i}.example.com") for i in range(n_ev)]}
    usager = {"tv": [{"id": "tv-salon", "nom": "TV salon", "protege": True, "pause_jusqu_a": None}]}
    vide = {"exceptions": [], "hors_champ": [], "agregats": [], "pauses": [], "erreurs_dns": [], "retours_arriere": []}

    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e))
            pg = nav.new_page()
            erreurs, posts, gets, coque = [], [], [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))

            def api(route):
                u = route.request.url
                if route.request.method == "POST":
                    posts.append((u, route.request.post_data))
                    rep = {"message": "protection en pause pour toutes les TV pendant 1 h"} if "debloquer" in u else {}
                    return route.fulfill(status=200, content_type="application/json", body=json.dumps(rep))
                gets.append(u)
                corps = (analyse if "/protection/analyse" in u else evenements if "/protection/evenements" in u else usager if "/usager/tv" in u
                         else vide if "/protection/" in u else appareils)
                route.fulfill(status=statut, content_type="application/json", body=json.dumps(corps if statut == 200 else {"detail": "x"}))
            pg.route("http://t.test/api/**", api)
            pg.route("http://t.test/shared/**", lambda r: coque.append(r.request.url) or r.fulfill(status=200, content_type="text/javascript" if r.request.url.endswith(".js") else "text/css",
                                                                                                    body="document.getElementById('sidebar').textContent='MENU';" if r.request.url.endswith(".js") else ""))
            pg.route("http://t.test/tv-privacy/**", lambda r: r.fulfill(status=200, content_type="text/html", body=SRC))
            pg.goto("http://t.test" + chemin)
            pg.wait_for_timeout(600)
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, posts, gets, coque)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=90)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1:]


def test_donnees_affichees_comme_texte_et_correction_confirmee():
    def sc(pg):
        t1 = pg.inner_text("body")
        pg.click("#t-equipements")
        t2 = pg.inner_text("#v-equipements")
        pg.click("text=Corriger le profil")
        pg.select_option("#v-equipements select", "INCONNU")
        pg.click("#v-equipements >> text=Confirmer")
        pg.wait_for_timeout(300)
        pg.click("#t-analyseur")
        pg.wait_for_timeout(300)
        t3 = pg.inner_text("#v-analyseur")
        return t1, t2, t3, pg.evaluate("window.xss")
    (t1, t2, t3, xss), erreurs, posts, _g, _c = _page(sc)
    assert xss is None and HOSTILE in t1 and HOSTILE in t2 and not erreurs
    assert "modes divergents" in t2 and "192.0.2.1" in t2 and "IPv6" in t2 and "AUTO" in t2
    assert "protégé" in t3 and "ads.example.com" in t3 and "2 sur 57" in t3
    assert posts and posts[0][0].endswith("/adblock-tv/appareils/02%3A00%3A5e%3A00%3A00%3A01/profil") and json.loads(posts[0][1]) == {"type": "INCONNU"}


def test_coque_chargee_dans_l_admin_seulement():
    (texte,), erreurs, _p, _g, coque = _page(lambda pg: (pg.inner_text("#sidebar"),))
    assert any(u.endswith("/shared/sidebar.js") for u in coque) and texte == "MENU" and not erreurs
    for ch in ("/tv-privacy/?demo=1", "/tv-privacy/?embed=1"):
        (_t,), erreurs, _p, _g, coque = _page(lambda pg: (pg.inner_text("body"),), chemin=ch)
        assert not any(u.endswith("/shared/sidebar.js") for u in coque) and not erreurs


def test_evenements_agreges_affiches():
    (t,), erreurs, _p, gets, _c = _page(lambda pg: (pg.inner_text("#evenements"),))
    assert "pub.example.com" in t and "nouveau" in t and "bloqué" in t and not erreurs
    assert any("/protection/evenements?heures=1" in u for u in gets)


def test_evenements_longs_affiches_par_dix_puis_voir_plus():
    def sc(pg):
        avant = pg.eval_on_selector_all("#evenements tr:not(.plus)", "t => t.length")
        pg.click("#evenements tr.plus button")
        pg.wait_for_timeout(200)
        return avant, pg.eval_on_selector_all("#evenements tr:not(.plus)", "t => t.length"), pg.inner_text("#evenements tr.plus")
    (avant, apres, reste), erreurs, _p, _g, _c = _page(sc, n_ev=45)
    assert (avant, apres) == (10, 30) and "15 restants" in reste and not erreurs


def test_bouton_je_debloque():
    def sc(pg):
        pg.click("#debloque-ouvrir")
        pg.wait_for_timeout(200)
        opts = pg.eval_on_selector_all("#debloque-tv option", "o => o.map(x => x.textContent)")
        pg.click("#debloque-panneau >> text=Pause 1 h")
        pg.wait_for_timeout(300)
        return opts, pg.inner_text("#debloque-retour")
    (opts, retour), erreurs, posts, _g, _c = _page(sc)
    assert opts == ["Toutes les TV", "TV salon"] and not erreurs
    assert posts[0][0].endswith("/protection/usager/debloquer") and json.loads(posts[0][1]) == {"tv": "toutes", "geste": "pause", "minutes": 60}
    assert retour == "protection en pause pour toutes les TV pendant 1 h"


def test_analyseur_filtres_retirables_et_pagination_serveur():
    def sc(pg):
        pg.click("#t-analyseur")
        pg.wait_for_timeout(300)
        pg.fill("#f-q", "doubleclick")
        pg.check("#f-decision input[value=bloque]")
        pg.click("#f-appliquer")
        pg.wait_for_timeout(300)
        puces = pg.inner_text("#f-actifs")
        pg.click("#f-actifs button >> nth=0")
        pg.wait_for_timeout(300)
        pg.click("#plus")
        pg.wait_for_timeout(300)
        return puces, pg.inner_text("#f-actifs")
    (puces, apres), erreurs, _p, gets, _c = _page(sc)
    assert "contient « doubleclick »" in puces and "décision bloque" in puces and not erreurs
    assert "décision bloque" not in apres
    an = [u for u in gets if "/protection/analyse?" in u]
    assert any("q=doubleclick" in u and "decision=bloque" in u for u in an)
    assert any("decalage=25" in u and "limite=25" in u for u in an)


def test_sans_session_la_page_le_dit():
    (texte, *_), erreurs, posts, _g, _c = _page(lambda pg: (pg.inner_text("body"),), statut=403)
    assert "session requise" in texte and not erreurs and not posts


def _hash(contenu):
    import base64
    import hashlib
    return "'sha256-" + base64.b64encode(hashlib.sha256(contenu.encode("utf-8")).digest()).decode() + "'"


def test_csp_stricte_par_hash_a_jour():
    m = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', SRC)
    assert m, "CSP absente"
    csp = {d.split()[0]: d.split()[1:] for d in (x.strip() for x in m.group(1).split(";")) if d}
    assert csp["default-src"] == ["'self'"]
    styles = re.findall(r"<style>(.*?)</style>", SRC, flags=re.S)
    scripts = re.findall(r"<script>(.*?)</script>", SRC, flags=re.S)
    assert len(styles) == 1 and len(scripts) == 1
    # 'self' : le menu latéral et sa feuille de style servis par l'admin ; rien d'externe ; les blocs en ligne par hachage.
    assert csp["script-src"] == ["'self'", _hash(scripts[0])], "script modifié sans mise à jour de la CSP"
    assert csp["style-src"] == ["'self'", _hash(styles[0])], "style modifié sans mise à jour de la CSP"
    # Le menu latéral partagé (/shared/sidebar.js) pose des gestionnaires et des styles en ATTRIBUT : seuls les attributs sont
    # permis en ligne (CSP3 *-src-attr) ; un <script> ou <style> en ligne reste refusé sans son hachage.
    assert csp["script-src-attr"] == ["'unsafe-inline'"] and csp["style-src-attr"] == ["'unsafe-inline'"]
    sans_attr = ";".join(d for d in m.group(1).split(";") if "-src-attr" not in d)
    assert "unsafe-eval" not in m.group(1) and "unsafe-inline" not in sans_attr and "http" not in m.group(1)
    assert ' style="' not in SRC and "<script " not in SRC                    # aucun style ni script hors des blocs hachés


# ── Mise en page Aurora : aucun débordement horizontal (démonstration, puis avec le vrai menu latéral partagé) ──
COQUE = RACINE.parent / "secubox-hub" / "www" / "shared"
ONGLETS = ("generale", "equipements", "analyseur", "protection", "diagnostic")
MENU = json.dumps({"categories": [{"name": "Sécurité", "icon": "S", "items": [{"path": "/tv-privacy/", "name": "SBX TV Privacy", "icon": "T"}]}]})
MESURE = "() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]"


def _debordements(largeur, coque_reelle):
    """Largeur de la page et du document, onglet par onglet. `coque_reelle` : le vrai /shared/sidebar.js du dépôt sur la page en démonstration."""
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e))
            pg = nav.new_page(viewport={"width": largeur, "height": 900})
            erreurs = []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))

            def partage(route):
                f = COQUE / route.request.url.split("/shared/", 1)[1].split("?")[0]
                if not f.is_file():
                    return route.fulfill(status=404, body="")
                route.fulfill(status=200, body=f.read_bytes(), content_type="text/javascript" if f.suffix == ".js" else "text/css")
            pg.route("http://t.test/shared/**", partage)
            pg.route("http://t.test/api/**", lambda r: r.fulfill(status=200, content_type="application/json", body=MENU if "/hub/public/menu" in r.request.url else "{}"))
            pg.route("http://t.test/tv-privacy/**", lambda r: r.fulfill(status=200, content_type="text/html", body=SRC))
            pg.goto(("http://t.test/tv-privacy/?demo=1") if coque_reelle else PAGE.as_uri() + "?demo=1")
            if coque_reelle:                                   # la démonstration n'ouvre pas le menu : on le monte comme l'admin le fait
                pg.evaluate("() => {document.body.classList.remove('emb');var s=document.createElement('script');s.src='/shared/sidebar.js';document.body.appendChild(s);}")
            pg.wait_for_timeout(900)
            mesures = {}
            for o in ONGLETS:
                pg.click(f"#t-{o}")
                pg.wait_for_timeout(150)
                mesures[o] = pg.evaluate(MESURE)
            if coque_reelle:                                   # habillage Aurora du menu, sans le bloc d'état ni les LED de l'ancienne barre
                mesures["coque"] = pg.evaluate("() => [document.documentElement.classList.contains('sbx-aurora'), !!document.querySelector('link[href=\"/shared/cadre-aurora.css\"]'),"
                                               " [...document.querySelectorAll('.header-leds-metrics')].every(e => e.offsetParent === null)]")
            nav.close()
            return ("ok", mesures, erreurs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=90)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1:]


@pytest.mark.parametrize("largeur", [1400, 420])
@pytest.mark.parametrize("coque_reelle", [False, True], ids=["demo", "menu-lateral"])
def test_aucun_debordement_horizontal(largeur, coque_reelle):
    mesures, erreurs = _debordements(largeur, coque_reelle)
    coque = mesures.pop("coque", None)
    assert coque in (None, [True, True, True]), f"menu sans l'habillage Aurora : {coque}"
    trop = {o: m for o, m in mesures.items() if m[0] > m[1]}
    assert not trop, f"débordement horizontal à {largeur} px : {trop}"
    assert not erreurs
