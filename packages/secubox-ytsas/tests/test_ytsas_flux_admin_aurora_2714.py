# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2714 — onglet « Administration du flux » de la page YouTube SAS (profil Aurora).

Statique + vrai navigateur, API simulée sur http://sbx.test (aucune box, aucun YouTube : les cookies réels sont périmés,
rien n'est vérifiable en réel)."""
import json
import os
import re
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
PAGE = PKG / "www" / "ytsas" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
HOTE = "http://sbx.test"
CAPTURES = os.environ.get("YTSAS_CAPTURES")          # dossier où écrire des captures (facultatif)
NOW = int(time.time())


# ───────────────────────── statique ─────────────────────────
def test_onglet_administration_a_cote_de_l_onglet_flux_existant():
    assert 'id="oFlux"' in SRC and 'id="pFlux"' in SRC and 'id="zoneFlux"' in SRC          # la carte encadrée est gardée
    assert 'id="oAdmin"' in SRC and 'id="pAdmin"' in SRC and "Administration du flux" in SRC
    assert "[['oBiblio', 'pBiblio'], ['oFlux', 'pFlux'], ['oAdmin', 'pAdmin']]" in SRC


def test_page_sans_dialogue_natif_ni_innerhtml_et_jeton_en_try_catch():
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "onclick="):
        assert interdit not in SRC, interdit
    assert "try { var tok = localStorage.getItem('sbx_token');" in SRC and "'Bearer ' + tok" in SRC


def test_appels_d_api_d_administration_et_aucun_contenu_de_cookie_demande():
    for chemin in ("API + '/flux/etat'", "API + '/flux/actualiser/' + encodeURIComponent(t)", "API + '/flux/vider/' + encodeURIComponent(t)"):
        assert chemin in SRC, chemin
    assert "X-Sbx-Flux" not in SRC and "X-Sbx-Garde-Admin" not in SRC            # ni l'en-tête du Hall, ni le jeton de garde (posé par nginx)
    assert SRC.count("/cookies'") == 1                                           # le dépôt, déjà présent ; jamais de relecture


def test_mode_d_emploi_exact():
    texte = re.sub(r"<[^>]+>", "", SRC[SRC.index('id="aMode"'):SRC.index("</details>", SRC.index('id="aMode"'))])
    for attendu in ("fait tourner les cookies", "profil de navigateur dédié", "navigation privée", "robots.txt", "youtube.com", "google.com",
                    "seulement", "sans te déconnecter", "panneau Authentification"):
        assert attendu in texte, attendu


def test_tuiles_avec_infobulles_de_definition():
    for k in ("kCookies", "kListes", "kJs"):
        assert re.search(r'id="%s" title="[^"]{30,}"' % k, SRC), k
    assert re.search(r'<div class="tuile vi" title="[^"]{20,}"><span class="l">yt-dlp', SRC)


# ───────────────────────── vrai navigateur ─────────────────────────
playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def liste(t, videos=24, age=300, perime=False, cause=None, duree=3.4, rel=0):
    vide = videos is None
    return {"type": t, "date": None if vide else NOW - age, "age_s": None if vide else age, "videos": videos,
            "perime": None if vide else perime, "cause": cause, "derniere_tentative": None if vide else NOW - age,
            "duree_s": None if vide else duree, "relance_dans_s": rel}


def etat(verdict="acceptes", js=None, echecs=None, listes=None):
    return {
        "ttl_s": 900, "anti_rafale_s": 30,
        "cookies": {"present": verdict != "absents", "mtime": NOW - 86400, "stale": verdict == "refuses", "verdict": verdict},
        "listes": listes or [liste("envie"), liste("propositions", 18, 5400, True, "cookies", 1.9), liste("abonnements", 24, 700),
                              liste("historique", 24, 7200, True, "youtube", 90.0), liste("chaines", None), liste("playlists", 12, 300, rel=12)],
        "diagnostic": {"ytdlp": "2026.08.19", "js": js or {"present": True, "moteurs": ["deno"], "par_defaut": True},
                       "cache": {"fichiers": 9, "octets": 183296},
                       "echecs": echecs if echecs is not None else [{"liste": "historique", "date": NOW - 3000, "cause": "youtube", "texte": "délai dépassé"}]},
    }


BASE = {("GET", "/status"): (200, {"active": 0, "disk_free": 5 * 1024 ** 3, "kept": 1, "peertube": 0}),
        ("GET", "/cookies/status"): (200, {"present": True, "mtime": NOW, "stale": False}),
        ("GET", "/list"): (200, [])}


def ouvre(navigateur, url, routes, taille=None, jeton=True):
    ctx = navigateur.new_context(viewport=taille or {"width": 1400, "height": 900})
    p = ctx.new_page()
    erreurs, appels, requetes, tenus = [], [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif : " + d.message), d.dismiss()))
    if jeton:
        p.add_init_script("try{localStorage.setItem('sbx_token','tok123')}catch(e){}")

    def fichier(r, *_):
        u = r.request.url
        requetes.append(u)
        chemin = re.sub(r"^https?://[^/]+/", "", u).split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "ytsas":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        elif chemin.startswith("api/v1/ytsas/"):
            sous = "/" + chemin[len("api/v1/ytsas/"):]
            appels.append((r.request.method, sous, r.request.post_data, r.request.headers))
            reponse = routes.get((r.request.method, sous), (200, {"ok": True}) if r.request.method == "POST" else (404, {}))
            if reponse == "tenir":
                tenus.append(r)
                return
            st, corps = reponse
            r.fulfill(status=st, content_type="application/json", body=json.dumps(corps))
        else:
            r.fulfill(status=404, body="")
    p.route(re.compile(r"^http://sbx\.test/.*"), fichier)
    p.goto(url)
    return ctx, p, erreurs, appels, requetes, tenus


def admin(navigateur, routes_admin, **kw):
    routes = {**BASE, **routes_admin}
    ctx, p, err, appels, req, tenus = ouvre(navigateur, HOTE + "/ytsas/", routes, **kw)
    p.wait_for_selector("#etat:not(:has-text('Chargement'))")
    p.click("#oAdmin")
    return ctx, p, err, appels, req, tenus


def lignes(p):
    return p.locator("#aListesEtat .item")


def capture(p, nom):
    if CAPTURES:
        p.wait_for_timeout(200)
        p.screenshot(path=str(Path(CAPTURES) / nom), full_page=True)


def pas_de_debordement(p):
    return p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")


def test_etat_de_chaque_liste_cookies_et_diagnostic(navigateur):
    ctx, p, err, appels, _, _ = admin(navigateur, {("GET", "/flux/etat"): (200, etat("refuses", js={"present": False, "moteurs": [], "par_defaut": False}))})
    p.wait_for_selector("#aListesEtat .item")
    assert lignes(p).count() == 6
    t = [lignes(p).nth(i).inner_text() for i in range(6)]
    assert "À regarder plus tard" in t[0] and "à jour" in t[0] and "vidéos en cache : 24" in t[0] and "3,4 s" in t[0]
    assert "périmé" in t[1] and "Cause : YouTube ne reconnaît pas le compte" in t[1] and "1,9 s" in t[1]
    assert "Cause : YouTube n’a pas répondu" in t[3] and "90,0 s" in t[3]
    assert "pas de cache" in t[4] and "vidéos en cache : —" in t[4] and "durée de lecture : —" in t[4] and "lue —" in t[4]     # mesure absente = tiret
    assert "Prochaine relance possible dans 12 s" in t[5]
    assert p.inner_text("#aListes") == "3" and p.inner_text("#aYtdlp") == "2026.08.19"
    assert p.inner_text("#aJs") == "aucun" and "aucun moteur trouvé" in p.inner_text("#dJs") and "9 fichiers" in p.inner_text("#dCache")
    assert "délai dépassé" in p.inner_text("#dEchecs") and "Historique" in p.inner_text("#dEchecs")
    assert "refusés" in p.inner_text("#aCkPill") and p.inner_text("#aCookies") == "refusés"
    # la lecture part avec le jeton, et RIEN n'est écrit à l'ouverture
    gets = [a for a in appels if a[1] == "/flux/etat"]
    assert gets and all(a[0] == "GET" and a[3].get("authorization") == "Bearer tok123" for a in gets)
    assert not [a for a in appels if a[0] == "POST"]
    # jamais de contenu de cookie demandé
    assert not [a for a in appels if a[1] == "/cookies" and a[0] == "GET"]
    assert err == []
    capture(p, "admin-1400.png")
    ctx.close()


def test_cookies_perimes_le_mode_d_emploi_est_visible(navigateur):
    ctx, p, err, *_ = admin(navigateur, {("GET", "/flux/etat"): (200, etat("refuses"))})
    p.wait_for_selector("#aListesEtat .item")
    assert p.is_visible("#aMode ol") and "navigation privée" in p.inner_text("#aMode") and "sans te déconnecter" in p.inner_text("#aMode")
    assert "cookies" in p.inner_text("#aCkMeta") or "déposé" in p.inner_text("#aCkMeta")
    assert err == []
    ctx.close()


@pytest.mark.parametrize("verdict, ouvert", [("acceptes", False), ("inconnu", False), ("refuses", True), ("anciens", True), ("absents", True)])
def test_mode_d_emploi_ouvert_seulement_quand_il_y_a_un_probleme(navigateur, verdict, ouvert):
    ctx, p, err, *_ = admin(navigateur, {("GET", "/flux/etat"): (200, etat(verdict))})
    p.wait_for_selector("#aListesEtat .item")
    assert p.is_visible("#aMode ol") == ouvert
    assert p.is_visible("#aMode summary")                     # toujours consultable
    assert err == []
    ctx.close()


def test_le_lien_vers_le_depot_de_cookies_ne_le_duplique_pas(navigateur):
    ctx, p, err, *_ = admin(navigateur, {("GET", "/flux/etat"): (200, etat("refuses"))})
    p.wait_for_selector("#aListesEtat .item")
    assert p.locator("#pAdmin input[type=file]").count() == 0                       # aucun second dépôt
    p.click("#aVersDepot")
    assert p.is_visible("#pBiblio") and p.is_hidden("#pAdmin")
    assert p.evaluate("document.activeElement.id") == "cookieFile"
    assert err == []
    ctx.close()


def test_actualiser_attente_puis_resultat(navigateur):
    routes = {("GET", "/flux/etat"): (200, etat("acceptes")), ("POST", "/flux/actualiser/envie"): "tenir"}
    ctx, p, err, appels, _, tenus = admin(navigateur, routes)
    p.wait_for_selector("#aListesEtat .item")
    p.locator("#aListesEtat .item").nth(0).locator("[data-act=actualiser]").click()
    p.wait_for_function("document.querySelector('#aListesEtat .item [data-act=actualiser]').textContent.includes('Lecture en cours')")
    # une à la fois : tous les boutons d'action sont bloqués pendant l'attente
    assert p.locator("#aListesEtat [data-act=actualiser]:not([disabled])").count() == 0
    assert p.locator("#aListesEtat [data-act=vider]:not([disabled])").count() == 0
    assert len([a for a in appels if a[0] == "POST"]) == 1
    p.locator("#aListesEtat .item").nth(1).locator("[data-act=actualiser]").click(force=True)
    assert len([a for a in appels if a[0] == "POST"]) == 1
    capture(p, "admin-attente-1400.png")
    tenus[0].fulfill(status=200, content_type="application/json", body=json.dumps({"ok": True, "type": "envie", "videos": 24, "date": NOW, "perime": False, "cause": None, "duree_s": 3.4}))
    p.wait_for_function("document.querySelector('#aListesEtat .retour')")
    assert "Lue : 24 vidéos en 3,4 s" in p.inner_text("#aListesEtat .retour")
    p.wait_for_selector("#aListesEtat [data-act=actualiser]:not([disabled])")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/flux/actualiser/envie" and post[3].get("authorization") == "Bearer tok123"
    assert len([a for a in appels if a[1] == "/flux/etat"]) >= 2                    # l'état est relu après l'action
    assert err == []
    ctx.close()


def test_actualiser_repli_perime_dit_la_cause(navigateur):
    routes = {("GET", "/flux/etat"): (200, etat()), ("POST", "/flux/actualiser/envie"):
              (200, {"ok": False, "type": "envie", "videos": 24, "date": NOW - 99, "perime": True, "cause": "cookies", "duree_s": 1.0})}
    ctx, p, err, *_ = admin(navigateur, routes)
    p.wait_for_selector("#aListesEtat .item")
    p.locator("#aListesEtat .item").nth(0).locator("[data-act=actualiser]").click()
    p.wait_for_selector("#aListesEtat .retour.ko")
    t = p.inner_text("#aListesEtat .retour")
    assert "ancienne lecture conservée" in t and "cookies périmés" in t and "24 vidéos" in t
    assert err == []
    ctx.close()


@pytest.mark.parametrize("statut, corps, attendu", [
    (429, {"error": "x", "cause": "rafale", "reessayer_dans": 21}, "réessaie dans 21 s"),
    (502, {"error": "x", "cause": "youtube", "detail": "délai dépassé"}, "YouTube n’a pas répondu — délai dépassé"),
    (502, {"error": "x", "cause": "cookies"}, "cookies périmés"),
    (409, {"error": "x", "cause": "absent"}, "pas de cookies déposés"),
    (409, {"error": "x", "cause": "occupe"}, "occupe"),
    (500, {"error": "panne interne"}, "Échec : panne interne"),
])
def test_actualiser_erreurs_affichees_dans_la_ligne(navigateur, statut, corps, attendu):
    routes = {("GET", "/flux/etat"): (200, etat()), ("POST", "/flux/actualiser/abonnements"): (statut, corps)}
    ctx, p, err, *_ = admin(navigateur, routes)
    p.wait_for_selector("#aListesEtat .item")
    p.locator("#aListesEtat .item").nth(2).locator("[data-act=actualiser]").click()
    p.wait_for_selector("#aListesEtat .retour.ko")
    assert attendu in p.inner_text("#aListesEtat .retour.ko")
    assert p.is_visible("#aListesEtat .item >> nth=2") and err == []
    ctx.close()


def test_vider_demande_une_confirmation_dans_la_page(navigateur):
    routes = {("GET", "/flux/etat"): (200, etat()), ("POST", "/flux/vider/envie"): (200, {"ok": True, "type": "envie", "vide": True})}
    ctx, p, err, appels, *_ = admin(navigateur, routes)
    p.wait_for_selector("#aListesEtat .item")
    ligne = lambda: p.locator("#aListesEtat .item").nth(0)    # noqa: E731
    ligne().locator("[data-act=vider]").click()
    assert "Vider le cache de cette liste ?" in ligne().inner_text()
    assert not [a for a in appels if a[1].startswith("/flux/vider")]
    ligne().get_by_text("Annuler").click()
    assert "Vider le cache de cette liste ?" not in ligne().inner_text() and not [a for a in appels if a[1].startswith("/flux/vider")]
    ligne().locator("[data-act=vider]").click()
    capture(p, "admin-confirmation-1400.png")
    ligne().locator("[data-act=confirmer]").click()
    p.wait_for_function("document.querySelector('#aListesEtat .retour')")
    assert "Cache vidé" in p.inner_text("#aListesEtat .retour")
    post = [a for a in appels if a[0] == "POST"]
    assert [a[1] for a in post] == ["/flux/vider/envie"] and post[0][3].get("authorization") == "Bearer tok123"
    assert err == []                                           # aucun dialogue natif
    ctx.close()


def test_vider_est_inactif_sans_cache(navigateur):
    ctx, p, err, *_ = admin(navigateur, {("GET", "/flux/etat"): (200, etat())})
    p.wait_for_selector("#aListesEtat .item")
    assert p.locator("#aListesEtat .item").nth(4).locator("[data-act=vider]").is_disabled()
    ctx.close()


@pytest.mark.parametrize("statut, texte", [(403, "réservée à l’administrateur"), (401, "session requise"), (500, "indisponible")])
def test_acces_refuse_bandeau_et_tirets(navigateur, statut, texte):
    ctx, p, err, *_ = admin(navigateur, {("GET", "/flux/etat"): (statut, {"error": "refus"})})
    p.wait_for_selector("#adminAcces:not([hidden])")
    assert texte in p.inner_text("#adminAcces")
    assert [p.inner_text(i) for i in ("#aCookies", "#aListes", "#aYtdlp", "#aJs")] == ["—"] * 4
    assert p.inner_text("#aListesEtat") == "—" and err == []
    ctx.close()


def test_l_onglet_flux_existant_est_intact(navigateur):
    ctx, p, err, appels, requetes, _ = admin(navigateur, {("GET", "/flux/etat"): (200, etat())})
    p.click("#oFlux")
    assert p.is_visible("#pFlux") and p.is_hidden("#pAdmin") and p.is_visible("#fluxIndispo")        # sbx.test : pas de Hall déduit
    p.click("#oAdmin")
    assert p.is_visible("#pAdmin") and p.is_hidden("#pFlux")
    assert not [a for a in appels if a[1] == "/flux" or a[1].startswith("/flux?")]                 # jamais la lecture du Hall
    ctx.close()


def test_demonstration_annoncee_aucune_requete_ni_ecriture(navigateur):
    ctx, p, err, appels, requetes, _ = ouvre(navigateur, HOTE + "/ytsas/?demo=1", {})
    p.wait_for_selector("#list .item", state="attached")
    p.click("#oAdmin")
    p.wait_for_selector("#aListesEtat .item")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert lignes(p).count() == 6 and p.is_visible("#aMode ol")
    p.locator("#aListesEtat .item").nth(0).locator("[data-act=actualiser]").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    p.locator("#aListesEtat .item").nth(0).locator("[data-act=vider]").click()
    p.locator("#aListesEtat .item").nth(0).locator("[data-act=confirmer]").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    assert appels == [] and err == []
    assert not [u for u in requetes if "/api/" in u]
    assert not [u for u in requetes if "/shared/sidebar.js" in u]
    capture(p, "admin-demo-1400.png")
    ctx.close()


@pytest.mark.parametrize("q", ["", "?embed=1", "?demo=1"])
def test_telephone_420_sans_debordement(navigateur, q):
    routes = {} if "demo" in q else {**BASE, ("GET", "/flux/etat"): (200, etat("refuses", echecs=[
        {"liste": "propositions", "date": NOW - 60, "cause": "cookies", "texte": "Sign in to confirm you’re not a bot " + "x" * 90}]))}
    ctx, p, err, *_ = ouvre(navigateur, HOTE + "/ytsas/" + q, routes, taille={"width": 420, "height": 800})
    p.wait_for_selector("#etat:not(:has-text('Chargement'))")
    p.click("#oAdmin")
    p.wait_for_selector("#aListesEtat .item")
    assert pas_de_debordement(p), q
    p.locator("#aListesEtat .item").nth(0).locator("[data-act=vider]").click()
    assert pas_de_debordement(p), q
    capture(p, "admin-420%s.png" % (q.replace("?", "-").replace("=", "") or ""))
    assert err == []
    ctx.close()
