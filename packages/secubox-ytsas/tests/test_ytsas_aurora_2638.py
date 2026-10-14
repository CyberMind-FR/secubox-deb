# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2638 — page d'administration YouTube SAS au profil Aurora, avec l'onglet « Flux » qui encadre la carte du Hall.

Statique + vrai navigateur (API simulée, sur http://admin.gk2.secubox.in ; le Hall est un faux https://hall.gk2.secubox.in).
"""
import json
import re
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
CARTE = (PKG.parent / "secubox-webos" / "www" / "hall" / "cardlets" / "ytflux.html").read_text(encoding="utf-8")
PAGE = PKG / "www" / "ytsas" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
ROUTES = (PKG / "nginx" / "ytsas-routes.conf").read_text(encoding="utf-8")


# ───────────────────────── statique ─────────────────────────

def test_page_autonome_sans_dialogue_natif_ni_ancienne_peau():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == []                 # le menu commun est injecté, hors démo et hors cadre
    assert "'/shared/sidebar.js'" in SRC
    assert "hybrid-skin" not in SRC and "hybrid-dark" not in SRC and "Courier" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "onclick="):
        assert interdit not in SRC, interdit
    assert "lorem" not in SRC.lower()
    assert "--fond:#060d1b" in SRC and "container-type:inline-size" in SRC
    assert "demo" in SRC and "embed" in SRC


def test_les_appels_d_api_sont_ceux_de_l_ancienne_page():
    """Mêmes routes, méthodes, corps et en-têtes que l'ancienne page : on refait la peau, pas le contrat."""
    assert "var API = '/api/v1/ytsas';" in SRC
    for chemin in ("'/status'", "'/cookies/status'", "'/list'", "'/keep/'", "'/conserve/'", "'/remove/'", "'/retry/'", "'/ephemeral/'", "'/add'",
                   "'/cookies'", "'/stream/'"):
        assert chemin in SRC, chemin
    assert "{ seconds: secs }" in SRC and "{ url: val }" in SRC
    assert "'Content-Type': 'text/plain'" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer ' + tok" in SRC
    assert "encodeURIComponent(id)" in SRC


def test_le_cadre_du_flux_vise_le_hall_deduit_du_nom_de_l_hote():
    assert "/cardlets/ytflux.html?embed=1" in SRC
    assert "'https://hall.'" in SRC and "location.hostname" in SRC
    assert "e.origin" in SRC and "e.source" in SRC and "sbxVue" in SRC and "'ytflux'" in SRC
    assert "300" in SRC and "4000" in SRC


def s_flux(texte):
    return sorted(set(re.findall(r"/api/v1/ytsas/flux/(?:etat|\(actualiser\|vider\)/)", texte)))


def test_aucune_route_flux_du_hall_sur_le_vhost_admin():
    # #2714 : l'administration du flux ajoute SES trois routes (etat, actualiser, vider), gardées par auth_request administrateur ;
    # les routes de lecture du Hall (liste, vignette, chaîne, playlist) et son en-tête restent absents de l'hôte admin.
    for hall in ("X-Sbx-Flux", "flux/vignette", "flux/chaine", "flux/playlist", "ytsas/flux?", "ytsas/flux)", "ytsas/flux/(vignette"):
        assert hall not in ROUTES, hall
    assert s_flux(ROUTES) == ["/api/v1/ytsas/flux/(actualiser|vider)/", "/api/v1/ytsas/flux/etat"]
    assert "location /api/v1/ytsas/ {" in ROUTES


# ───────────────────────── vrai navigateur ─────────────────────────

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
HOTE = "http://admin.gk2.secubox.in"
HALL = "https://hall.gk2.secubox.in"
FAUX_HALL = "<!doctype html><title>faux hall</title><script>parent.postMessage({sbxVue: 700, onglet: 'ytflux'}, '*')</script>"
STATUS = {"active": 1, "disk_free": 5 * 1024 ** 3, "kept": 3, "peertube": 2}
COOKIES = {"status": "present", "updated_at": "2026-10-13", "count": 42, "domains": 7}
LISTE = [
    {"id": "a1", "title": "Vidéo gardée", "complete": True, "ephemeral_until": None, "size": 1048576, "duration": "3:12"},
    {"id": "b2", "title": "Vidéo éphémère", "complete": True, "ephemeral_until": NOW + 7200, "size": 2048},
    {"id": "c3", "title": "Vidéo en cours", "progress": 0.42, "eta": "00:30", "speed": 2097152},
    {"id": "d4", "title": "Vidéo en échec", "status": "error", "error": "Sign in to confirm", "needs_cookies": True},
    {"id": "e5", "title": "Vidéo à PeerTube", "complete": True, "peertube_status": "done", "peertube_url": "https://pt.example.org/w/xyz"},
]
API = {("GET", "/status"): (200, STATUS), ("GET", "/cookies/status"): (200, COOKIES), ("GET", "/list"): (200, LISTE)}


def ouvre(navigateur, url, routes=None, taille=None, jeton=True, hall=True):
    routes = API if routes is None else routes
    ctx = navigateur.new_context(viewport=taille or {"width": 1400, "height": 900})
    p = ctx.new_page()
    erreurs, appels, requetes = [], [], []
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
            if sous.startswith("/stream/"):
                r.fulfill(status=200, content_type="video/mp4", body=b"")
                return
            st, corps = routes.get((r.request.method, sous), (200, {"ok": True}) if r.request.method == "POST" else (404, {}))
            r.fulfill(status=st, content_type="application/json", body=json.dumps(corps))
        else:
            r.fulfill(status=404, body="")
    p.route(re.compile(r"^https?://(admin\.gk2\.secubox\.in|sbx\.test|192\.168\.1\.200|localhost)/.*"), fichier)
    if hall:
        p.route(HALL + "/**", lambda r, *_: (requetes.append(r.request.url), r.fulfill(status=200, content_type="text/html", body=FAUX_HALL)))
    p.goto(url)
    return ctx, p, erreurs, appels, requetes


def attend(p):
    p.wait_for_selector("#list .item", state="attached")


def test_tuiles_cookies_et_mediatheque_viennent_de_l_api(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, HOTE + "/ytsas/")
    attend(p)
    assert [p.inner_text(i) for i in ("#tActive", "#tDisk", "#tKept", "#tPeertube")] == ["1", "5.0 GB", "3", "2"]
    assert p.inner_text("#etat") == "1 EN COURS"
    assert "présent" in p.inner_text("#cookieState") and "42 cookies" in p.inner_text("#cookieMeta") and "7 domaines" in p.inner_text("#cookieMeta")
    items = p.locator("#list .item")
    assert items.count() == 5
    assert "Vidéo gardée" in items.nth(0).inner_text() and "gardé" in items.nth(0).inner_text() and "1.0 MB" in items.nth(0).inner_text()
    assert "purge dans" in items.nth(1).inner_text() and "Reprendre garde" in items.nth(1).inner_text()
    assert "42%" in items.nth(2).inner_text() and "ETA 00:30" in items.nth(2).inner_text() and "2.0 MB/s" in items.nth(2).inner_text()
    assert "Sign in to confirm" in items.nth(3).inner_text() and "dépose tes cookies" in items.nth(3).inner_text()
    assert p.get_attribute("#list .item:nth-child(5) a", "href") == "https://pt.example.org/w/xyz"
    # les lectures partent avec le jeton, comme avant
    lectures = {a[1]: a[3] for a in appels if a[0] == "GET"}
    assert set(lectures) == {"/status", "/cookies/status", "/list"} and all(h.get("authorization") == "Bearer tok123" for h in lectures.values())
    assert err == []
    ctx.close()


def test_actions_de_la_mediatheque_envoient_les_memes_requetes(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, HOTE + "/ytsas/")
    attend(p)
    posts = lambda: [(a[0], a[1], a[2]) for a in appels if a[0] == "POST"]  # noqa: E731
    items = p.locator("#list .item")
    items.nth(1).get_by_text("Reprendre garde").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('Garde reprise')")
    items.nth(0).get_by_text("Garder").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('file d’attente')")
    items.nth(3).get_by_text("Réessayer").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('Nouvelle tentative')")
    items.nth(0).locator("select").select_option("86400")
    p.wait_for_function("document.getElementById('toast').textContent.includes('Purge programmée')")
    assert ("POST", "/keep/b2", None) in posts() and ("POST", "/conserve/a1", None) in posts() and ("POST", "/retry/d4", None) in posts()
    assert ("POST", "/ephemeral/a1", '{"seconds":86400}') in posts()
    corps = {a[1]: a[3] for a in appels if a[0] == "POST"}
    assert corps["/ephemeral/a1"].get("content-type") == "application/json" and corps["/ephemeral/a1"].get("authorization") == "Bearer tok123"
    assert err == []
    ctx.close()


def test_ajouter_un_lien_et_deposer_les_cookies(navigateur, tmp_path):
    ctx, p, err, appels, _ = ouvre(navigateur, HOTE + "/ytsas/", {**API, ("POST", "/add"): (200, {"title": "Titre ajouté"})})
    attend(p)
    p.click("#btnAdd")                                                      # vide : refus dans la page, aucun appel
    p.wait_for_function("document.getElementById('toast').textContent.includes('Lien requis')")
    assert not [a for a in appels if a[1] == "/add"]
    p.fill("#urlInput", " https://www.youtube.com/watch?v=dQw4w9WgXcQ ")
    p.press("#urlInput", "Enter")
    p.wait_for_function("document.getElementById('toast').textContent.includes('Titre ajouté')")
    add = [a for a in appels if a[1] == "/add"][0]
    assert add[0] == "POST" and json.loads(add[2]) == {"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"}
    assert add[3].get("content-type") == "application/json"
    f = tmp_path / "cookies.txt"
    f.write_text("# Netscape HTTP Cookie File\n.youtube.com\tTRUE\t/\tTRUE\t0\tSID\tabc\n")
    p.set_input_files("#cookieFile", str(f))
    p.click("#btnCookie")
    p.wait_for_function("document.getElementById('toast').textContent.includes('Cookies enregistrés')")
    ck = [a for a in appels if a[0] == "POST" and a[1] == "/cookies"][0]
    assert ck[2] == f.read_text() and ck[3].get("content-type") == "text/plain" and ck[3].get("authorization") == "Bearer tok123"
    assert err == []
    ctx.close()


def test_suppression_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels, _ = ouvre(navigateur, HOTE + "/ytsas/")
    attend(p)
    item = p.locator("#list .item").first
    item.get_by_label("Supprimer").click()
    assert "sans retour" in p.inner_text("#list .item >> nth=0") or "Supprimer cette vidéo" in p.inner_text("#list .item >> nth=0")
    assert not [a for a in appels if a[1].startswith("/remove/")]
    p.locator("#list .item").first.get_by_text("Annuler").click()
    assert not [a for a in appels if a[1].startswith("/remove/")]
    p.locator("#list .item").first.get_by_label("Supprimer").click()
    p.locator("#list .item").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('Supprimé')")
    assert ("POST", "/remove/a1", None) in [(a[0], a[1], a[2]) for a in appels]
    assert err == []                                                        # et aucun dialogue natif
    ctx.close()


def test_lecteur_integre_pointe_vers_stream(navigateur):
    ctx, p, _, _, _ = ouvre(navigateur, HOTE + "/ytsas/")
    attend(p)
    p.locator("#list .item").first.get_by_text("Lire").click()
    p.wait_for_selector("#list .item video", state="attached")
    assert p.get_attribute("#list .item video", "src") == "/api/v1/ytsas/stream/a1"
    p.locator("#list .item").first.get_by_text("Fermer").click()
    assert p.locator("#list .item video").count() == 0
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"error": "auth"}) for k in API}
    ctx, p, err, _, _ = ouvre(navigateur, HOTE + "/ytsas/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tActive", "#tDisk", "#tKept", "#tPeertube")] == ["—"] * 4
    assert err == []
    ctx.close()


def test_demonstration_annoncee_actions_inertes_et_sans_menu(navigateur):
    ctx, p, err, appels, requetes = ouvre(navigateur, HOTE + "/ytsas/?demo=1", {})
    attend(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    items = p.locator("#list .item")
    assert items.count() >= 4
    p.fill("#urlInput", "https://exemple.invalid/v")
    p.click("#btnAdd")
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    p.locator("#list .item").first.get_by_label("Supprimer").click()
    p.locator("#list .item").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    assert appels == [] and err == []
    assert not [u for u in requetes if "/shared/sidebar.js" in u]
    ctx.close()


def test_menu_commun_hors_demo_et_hors_cadre(navigateur):
    ctx, p, _, _, requetes = ouvre(navigateur, HOTE + "/ytsas/")
    attend(p)
    p.wait_for_timeout(150)
    assert [u for u in requetes if u.endswith("/shared/sidebar.js")]
    ctx.close()
    ctx, p, err, _, requetes = ouvre(navigateur, HOTE + "/ytsas/?embed=1")
    attend(p)
    p.wait_for_timeout(150)
    assert not [u for u in requetes if "/shared/sidebar.js" in u] and not p.is_visible("#sidebar") and err == []
    ctx.close()


def test_onglet_flux_encadre_la_carte_du_hall(navigateur):
    ctx, p, err, appels, requetes = ouvre(navigateur, HOTE + "/ytsas/")
    attend(p)
    assert p.get_attribute("#oBiblio", "aria-selected") == "true" and p.get_attribute("#oFlux", "role") == "tab"
    assert p.locator("#cFlux").count() == 0 and not [u for u in requetes if u.startswith(HALL)]     # rien n'est chargé tant qu'on ne l'ouvre pas
    p.click("#oFlux")
    p.wait_for_selector("#cFlux", state="attached")
    assert p.get_attribute("#oFlux", "aria-selected") == "true" and p.get_attribute("#oBiblio", "aria-selected") == "false"
    assert p.get_attribute("#cFlux", "src") == HALL + "/cardlets/ytflux.html?embed=1"
    assert p.is_hidden("#pBiblio") and p.is_visible("#pFlux") and p.is_hidden("#fluxIndispo")
    # hauteur annoncée par la carte : bornée 300–4000, +4 px
    p.wait_for_function("document.getElementById('cFlux').offsetHeight === 704")
    # un message d'une autre origine (cette page elle-même) ou hors bornes est ignoré
    p.evaluate("postMessage({sbxVue: 1234, onglet: 'ytflux'}, '*')")
    p.wait_for_timeout(200)
    assert p.evaluate("document.getElementById('cFlux').offsetHeight") == 704
    p.click("#oBiblio")
    assert p.is_visible("#pBiblio") and p.is_hidden("#pFlux")
    # le flux n'a JAMAIS été demandé à l'hôte admin
    assert not [a for a in appels if "flux" in a[1]] and not [u for u in requetes if "ytsas/flux" in u and u.startswith(HOTE)]
    assert err == []
    ctx.close()


@pytest.mark.parametrize("message, attendu", [
    ("{sbxVue: 99999, onglet: 'ytflux'}", 4004),       # borné à 4000 px, plus 4
    ("{sbxVue: 100, onglet: 'ytflux'}", 304),          # borné à 300 px, plus 4
    ("{sbxVue: 900, onglet: 'autre'}", 520),           # autre onglet : ignoré, hauteur par défaut
    ("{sbxVue: '900', onglet: 'ytflux'}", 520),        # pas un nombre : ignoré
])
def test_hauteur_annoncee_est_bornee_ou_ignoree(navigateur, message, attendu):
    page = "<!doctype html><script>parent.postMessage(" + message + ", '*')</script>"
    ctx, p, _, _, _ = ouvre(navigateur, HOTE + "/ytsas/", hall=False)
    p.route(HALL + "/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=page))
    attend(p)
    p.click("#oFlux")
    p.wait_for_selector("#cFlux", state="attached")
    p.wait_for_timeout(300)
    assert p.evaluate("document.getElementById('cFlux').offsetHeight") == attendu
    ctx.close()


@pytest.mark.parametrize("hote", ["http://sbx.test", "http://192.168.1.200", "http://localhost"])
def test_hote_sans_forme_admin_dit_flux_indisponible(navigateur, hote):
    ctx, p, err, _, requetes = ouvre(navigateur, hote + "/ytsas/")
    attend(p)
    p.click("#oFlux")
    assert p.is_visible("#fluxIndispo") and "Flux indisponible depuis cet hôte" in p.inner_text("#fluxIndispo") and "ouvrir dans le Hall" in p.inner_text("#fluxIndispo")
    assert p.locator("#cFlux").count() == 0 and not [u for u in requetes if "hall." in u]
    assert err == []
    ctx.close()


def test_demonstration_propage_a_la_carte(navigateur):
    ctx, p, _, _, _ = ouvre(navigateur, HOTE + "/ytsas/?demo=1", {})
    attend(p)
    p.click("#oFlux")
    p.wait_for_selector("#cFlux", state="attached")
    assert p.get_attribute("#cFlux", "src") == HALL + "/cardlets/ytflux.html?embed=1&demo=1"
    ctx.close()


def test_telephone_420_sans_debordement(navigateur):
    for q in ("", "?embed=1", "?demo=1"):
        ctx, p, err, _, _ = ouvre(navigateur, HOTE + "/ytsas/" + q, API if "demo" not in q else {}, taille={"width": 420, "height": 800})
        attend(p)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), q
        p.click("#oFlux")
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), q
        assert err == []
        ctx.close()


def test_la_vraie_carte_encadree_annonce_sa_hauteur_a_l_administration(navigateur):
    """La carte (réelle) poste sa hauteur à l'origine admin déduite de celle du Hall : sans cela le navigateur jette le message."""
    ctx, p, err, _, _ = ouvre(navigateur, HOTE.replace("http:", "https:") + "/ytsas/?demo=1", {}, hall=False)
    p.route(HALL + "/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=CARTE) if "/cardlets/ytflux.html" in r.request.url else r.fulfill(status=404, body=""))
    attend(p)
    p.click("#oFlux")
    p.wait_for_selector("#cFlux", state="attached")
    p.wait_for_function("document.getElementById('cFlux').offsetHeight !== 520")
    h = p.evaluate("document.getElementById('cFlux').offsetHeight")
    cadre = p.frame_locator("#cFlux").locator(".cadre")
    cadre.wait_for()
    bas = p.frame_locator("#cFlux").locator("body").evaluate("() => Math.ceil(document.querySelector('.cadre').getBoundingClientRect().bottom + scrollY)")
    assert 300 <= h <= 4004 and abs(h - (bas + 4)) <= 6, (h, bas)
    assert p.frame_locator("#cFlux").locator("#grille .video").count() >= 4 and err == []
    ctx.close()
