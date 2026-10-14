# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2708 — carte « Flux YouTube » : mes chaînes, playlists, navigation, favoris des trois types, diffusion dans le Hall.

Statique (carte, nginx) + vrai navigateur sur http://sbx.test avec une API SIMULÉE : les cookies YouTube de la box sont périmés,
rien ici n'a été lu chez YouTube. Le message de diffusion est celui du protocole existant du Hall ({sbx:'diffuser', url, titre})."""
import json
import os
import re
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
SRC = (PKG / "www" / "hall" / "cardlets" / "ytflux.html").read_text(encoding="utf-8")
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")
HALL = (PKG / "www" / "hall" / "index.html").read_text(encoding="utf-8")

UC1 = "UC" + "a" * 22
UC2 = "UC" + "b" * 22
PL1 = "PL" + "x" * 16
PL2 = "PL" + "y" * 16


# ───────────────────────── statique : nginx ─────────────────────────

def _motif_flux():
    m = re.search(r'location ~ "(\^/api/v1/ytsas/flux[^"\n]*)"\s*\{', VHOST)
    assert m
    assert m.group(1).endswith(r"\z")          # fin ABSOLUE (PCRE \z) : « $ » accepterait un retour à la ligne final
    return re.compile(m.group(1)[:-2] + r"\Z")


def _corps_flux():
    i = VHOST.index('location ~ "^/api/v1/ytsas/flux')
    return VHOST[i:VHOST.index("\n    }", i)]


def test_nginx_une_seule_route_flux_etendue_aux_motifs_stricts():
    assert len(re.findall(r'location\s+[~=^*\s]*"?\^?/api/v1/ytsas/flux', VHOST)) == 1
    corps = _corps_flux()
    assert "auth_request /__sbx_verifie_secubox;" in corps and "limit_except GET { deny all; }" in corps
    assert "proxy_set_header X-Sbx-Flux      1;" in corps
    assert "UC[A-Za-z0-9_-]{22}" in corps and "@[A-Za-z0-9._-]{1,64}" in corps
    assert "(PL|UU|LL|FL|OL)[A-Za-z0-9_-]{10,40}" in corps
    # expression à accolades : entre guillemets (sinon nginx -t échoue)
    assert re.search(r'location ~ "\^/api/v1/ytsas/flux[^"\n]*\{22\}[^"\n]*"\s*\{', VHOST)
    assert VHOST.index('location ~ "^/api/v1/ytsas/flux') < VHOST.index("location /api/v1/ytsas/ {")


@pytest.mark.parametrize("chemin", [
    "/api/v1/ytsas/flux", "/api/v1/ytsas/flux/vignette/dQw4w9WgXcQ",
    f"/api/v1/ytsas/flux/chaine/{UC1}", "/api/v1/ytsas/flux/chaine/@atelier.reseau_1-x", "/api/v1/ytsas/flux/chaine/@" + "a" * 64,
    f"/api/v1/ytsas/flux/playlist/{PL1}", "/api/v1/ytsas/flux/playlist/UU" + "z" * 22, "/api/v1/ytsas/flux/playlist/OLAK5uy_" + "k" * 10,
])
def test_nginx_chemins_admis(chemin):
    assert _motif_flux().match(chemin)


@pytest.mark.parametrize("chemin", [
    "/api/v1/ytsas/flux/", "/api/v1/ytsas/flux/chaine", "/api/v1/ytsas/flux/chaine/", f"/api/v1/ytsas/flux/chaine/{UC1}/videos",
    "/api/v1/ytsas/flux/chaine/UC" + "a" * 21, "/api/v1/ytsas/flux/chaine/UC" + "a" * 23, "/api/v1/ytsas/flux/chaine/@",
    "/api/v1/ytsas/flux/chaine/@" + "a" * 65, "/api/v1/ytsas/flux/chaine/@a b", "/api/v1/ytsas/flux/chaine/@a/b",
    "/api/v1/ytsas/flux/chaine/..", "/api/v1/ytsas/flux/chaine/../../add", f"/api/v1/ytsas/flux/chaine/{UC1}\n",
    "/api/v1/ytsas/flux/playlist/WL", "/api/v1/ytsas/flux/playlist/PL", "/api/v1/ytsas/flux/playlist/PL" + "x" * 9,
    "/api/v1/ytsas/flux/playlist/PL" + "x" * 41, f"/api/v1/ytsas/flux/playlist/{PL1}/x", f"/api/v1/ytsas/flux/playlist/{UC1}",
    f"/api/v1/ytsas/flux/vignette/{UC1}", "/api/v1/ytsas/flux/video/dQw4w9WgXcQ", "/api/v1/ytsas/flux/../add",
    "/api/v1/ytsas/fluxx", "/api/v1/ytsas/flux/chaine/https://evil.example/",
])
def test_nginx_chemins_refuses_par_la_route_stricte(chemin):
    assert not _motif_flux().match(chemin)


def test_nginx_vrai_moteur_admet_et_refuse_les_memes_chemins(tmp_path):
    """Le motif est évalué par le VRAI nginx quand il est installé (PCRE réel, pas seulement le module re de Python)."""
    import shutil
    import socket
    import subprocess
    import urllib.error
    import urllib.request
    nginx = shutil.which("nginx") or ("/usr/sbin/nginx" if os.path.exists("/usr/sbin/nginx") else None)
    if not nginx:
        pytest.skip("nginx absent")
    motif = re.search(r'location ~ ("\^/api/v1/ytsas/flux[^"\n]*")\s*\{', VHOST).group(1)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    d = str(tmp_path)
    (tmp_path / "nginx.conf").write_text(
        f"pid {d}/n.pid;\nerror_log {d}/err.log;\nevents {{ }}\nhttp {{\n access_log off;\n client_body_temp_path {d}/b;\n proxy_temp_path {d}/p;\n"
        f" fastcgi_temp_path {d}/f;\n uwsgi_temp_path {d}/u;\n scgi_temp_path {d}/s;\n server {{\n  listen 127.0.0.1:{port};\n"
        f"  location ~ {motif} {{ return 200 flux; }}\n  location / {{ return 404 autre; }}\n }}\n}}\n")
    conf = str(tmp_path / "nginx.conf")
    assert subprocess.run([nginx, "-t", "-c", conf], capture_output=True).returncode == 0
    subprocess.run([nginx, "-c", conf], check=True, capture_output=True)
    try:
        def rep(chemin):
            for _ in range(20):
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}{chemin}", timeout=3) as r:
                        return r.read().decode()
                except urllib.error.HTTPError as e:
                    return e.read().decode()
                except urllib.error.URLError:
                    time.sleep(0.1)
            raise AssertionError("nginx injoignable")
        for ok in (f"/api/v1/ytsas/flux/chaine/{UC1}", "/api/v1/ytsas/flux/chaine/%40atelier", f"/api/v1/ytsas/flux/playlist/{PL1}",
                   "/api/v1/ytsas/flux", "/api/v1/ytsas/flux/vignette/dQw4w9WgXcQ"):
            assert rep(ok) == "flux", ok
        for ko in (f"/api/v1/ytsas/flux/chaine/{UC1}%0A", f"/api/v1/ytsas/flux/chaine/{UC1}/videos", "/api/v1/ytsas/flux/chaine/UCcourt",
                   "/api/v1/ytsas/flux/playlist/WL", f"/api/v1/ytsas/flux/playlist/{PL1}%0A", "/api/v1/ytsas/flux/chaine/%40a%2Fb",
                   f"/api/v1/ytsas/flux/vignette/{UC1}", "/api/v1/ytsas/flux/chaine/..%2Fadd"):
            assert rep(ko) == "autre", ko
    finally:
        subprocess.run([nginx, "-c", conf, "-s", "stop"], capture_output=True)


def test_nginx_le_prefixe_ouvert_ne_pose_toujours_pas_l_en_tete():
    i = VHOST.index("location /api/v1/ytsas/ {")
    assert "X-Sbx-Flux" not in VHOST[i:VHOST.index("\n    }", i)]


# ───────────────────────── statique : la carte ─────────────────────────

def test_carte_reste_une_page_autonome_sans_html_injecte_ni_dialogue():
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["../sonde.js"]
    for interdit in ("innerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "confirm(", "alert(", "prompt(", "onclick="):
        assert interdit not in SRC, interdit
    assert "fetch('http" not in SRC and 'fetch("http' not in SRC
    assert "sbxVue" in SRC and "onglet: 'ytflux'" in SRC


def test_carte_trois_onglets_de_plus_et_aucune_ecriture_de_compte():
    for t in ("chaines", "playlists", "favoris"):
        assert f"['{t}'," in SRC
    assert "method:'POST'" in SRC and SRC.count("method:'POST'") == 1          # seul « ⬇ SAS » écrit (bibliothèque de la box), pas le compte YouTube
    assert "API + 'add'" in SRC


def test_carte_diffusion_reutilise_le_protocole_du_hall_tel_quel():
    assert "parent.postMessage({ sbx: 'diffuser', url: v.url, titre: v.titre || '' }, location.origin)" in SRC
    assert "'diffuser-resultat'" in SRC and "ev.source !== parent" in SRC and "ev.origin !== location.origin" in SRC
    # côté Hall : le même message est déjà accepté d'une carte posée, et le résultat renvoyé à l'origine exacte
    assert "d.sbx==='diffuser' && d.url" in HALL and "sbx:'diffuser-resultat'" in HALL
    assert not re.search(r"postMessage\([^;]*,\s*['\"]\*['\"]\s*\)", SRC)          # jamais de cible '*'


def test_carte_favoris_format_du_hall_conserve():
    assert "localStorage.getItem('sbx_favoris')" in SRC and "localStorage.setItem('sbx_favoris'," in SRC
    assert "sbx_favoris_meta" in SRC


def test_carte_demo_garde_les_ecritures():
    assert re.search(r"function basculerFavori\([^)]*\)\{\s*if\(DEMO\)", SRC)
    assert re.search(r"function diffuser\([^)]*\)\{\s*if\(DEMO\)", SRC)
    assert re.search(r"function diffuserListe\([^)]*\)\{\s*if\(DEMO\)", SRC)
    assert re.search(r"function ajouter\([^)]*\)\{\s*if\(DEMO\)", SRC)


# ───────────────────────── vrai navigateur (API simulée) ─────────────────────────

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
PNG = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360000002000001e221bc330000000049454e44ae426082")
U_VID = "https://www.youtube.com/watch?v=abcdefghi00"
U_CH = f"https://www.youtube.com/channel/{UC1}"
U_PL = f"https://www.youtube.com/playlist?list={PL1}"


def video(i, titre=None, chaine="Atelier Réseau", duree=213):
    vid = "abcdefghi%02d" % i
    return {"id": vid, "titre": titre or f"Vidéo numéro {i}", "chaine": chaine, "duree": duree,
            "url": f"https://www.youtube.com/watch?v={vid}", "vignette": f"/api/v1/ytsas/flux/vignette/{vid}"}


def liste(type_, items, **kw):
    return {"type": type_, "items": items, "en_cache": False, "perime": False, "date": NOW - 120, **kw}


CHAINES = [
    {"id": UC1, "nom": "Atelier Réseau", "handle": "@atelier-reseau", "abonnes": 48200, "videos": 312, "url": U_CH,
     "vignette": "/api/v1/ytsas/flux/vignette/kkkkkkkkkk1"},
    {"id": UC2, "nom": "Sans chiffres", "handle": None, "abonnes": None, "videos": None,
     "url": f"https://www.youtube.com/channel/{UC2}", "vignette": None},
]
PLAYLISTS = [
    {"id": PL1, "titre": "Réseaux, de la prise au routeur", "chaine": "Atelier Réseau", "videos": None, "url": U_PL,
     "vignette": "/api/v1/ytsas/flux/vignette/kkkkkkkkkk2"},
    {"id": PL2, "titre": "Musique", "chaine": "Atelier Sonore", "videos": 7, "url": f"https://www.youtube.com/playlist?list={PL2}", "vignette": None},
]
FLUX = {
    "envie": (200, liste("envie", [video(i) for i in range(3)])),
    "propositions": (200, liste("propositions", [video(i) for i in range(3)])),
    "abonnements": (200, liste("abonnements", [video(i) for i in range(3)])),
    "historique": (200, liste("historique", [video(i) for i in range(2)])),
    "chaines": (200, liste("chaines", CHAINES)),
    "playlists": (200, liste("playlists", PLAYLISTS)),
}
DETAILS = {
    ("chaine", UC1): (200, {"type": "chaine", "id": UC1, "titre": "Atelier Réseau", "items": [video(i) for i in range(4)],
                            "en_cache": False, "perime": False, "date": NOW - 60}),
    ("playlist", PL1): (200, {"type": "playlist", "id": PL1, "titre": "Réseaux, de la prise au routeur",
                              "items": [video(i, chaine="Atelier Réseau") for i in range(5, 8)], "en_cache": True, "perime": False, "date": NOW - 60}),
}


def ouvre(navigateur, query, flux=None, details=None, taille=None, init=None):
    flux = FLUX if flux is None else flux
    details = DETAILS if details is None else details
    ctx = navigateur.new_context(viewport=taille or {"width": 1400, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif : " + d.message), d.dismiss()))
    # témoins : messages reçus par la page ET adresses cibles de postMessage (parent === window hors iframe)
    p.add_init_script("""window.__msgs=[];window.__po=[];addEventListener('message',e=>__msgs.push(e.data));
      (function(){var o=window.postMessage.bind(window);window.postMessage=function(m,t){window.__po.push([m,t]);return o(m,t);};})();
      Object.defineProperty(navigator,'clipboard',{value:{writeText:t=>{window.__copie=t;return Promise.resolve();}}});""" + (init or ""))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin == "cardlets/ytflux.html":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        elif chemin == "sonde.js":
            r.fulfill(status=200, content_type="application/javascript", body="")
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/ytsas/", 1)[1]
        appels.append((r.request.method, chemin, r.request.post_data))
        m = re.match(r"flux/(chaine|playlist)/([^?]+)\?limite=24$", chemin)
        if chemin.startswith("flux/vignette/"):
            r.fulfill(status=200, content_type="image/png", body=PNG)
        elif chemin.startswith("flux?"):
            t = re.search(r"type=([a-z]+)", chemin).group(1)
            st, corps = flux.get(t, (404, {}))
            r.fulfill(status=st, content_type="application/json", body=json.dumps(corps))
        elif m:
            from urllib.parse import unquote
            st, corps = details.get((m.group(1), unquote(m.group(2))), (404, {"error": "identifiant invalide"}))
            r.fulfill(status=st, content_type="application/json", body=json.dumps(corps))
        else:
            r.fulfill(status=200, content_type="application/json", body="{}")
    p.route("http://sbx.test/api/v1/ytsas/**", api)
    p.goto("http://sbx.test/cardlets/ytflux.html" + query)
    return ctx, p, erreurs, appels


def onglet(p, t):
    p.click(f"#onglets [data-type={t}]")
    p.wait_for_function(f"document.querySelector('#onglets [data-type={t}]').getAttribute('aria-selected') === 'true'")


def attend(p, sel="#grille .video, #grille .fiche"):
    p.wait_for_selector(sel, state="attached")


def favoris(p):
    return json.loads(p.evaluate("localStorage.getItem('sbx_favoris')") or "[]")


def meta(p):
    return json.loads(p.evaluate("localStorage.getItem('sbx_favoris_meta')") or "{}")


def captures(p, nom):
    d = os.environ.get("YTFLUX_CAPTURES")
    if d:
        p.screenshot(path=os.path.join(d, nom), full_page=True)


# ── mes chaînes ──
def test_mes_chaines_nom_abonnes_videos_avatar_et_rien_d_invente(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "")
    attend(p, "#grille .video")
    onglet(p, "chaines")
    attend(p, "#grille .fiche")
    f = p.locator("#grille .fiche")
    assert f.count() == 2
    a = f.nth(0)
    assert "Atelier Réseau" in a.inner_text() and "@atelier-reseau" in a.inner_text()
    assert "48" in a.inner_text() and "abonnés" in a.inner_text() and "312 vidéos" in a.inner_text()
    assert a.locator(".avat img").get_attribute("src") == "/api/v1/ytsas/flux/vignette/kkkkkkkkkk1"
    b = f.nth(1)                                       # chaîne sans chiffres ni avatar : « — » et une initiale, pas de nombre inventé
    assert "Sans chiffres" in b.inner_text() and "abonnés" not in b.inner_text() and "vidéos" not in b.inner_text()
    assert b.locator(".stat").inner_text() == "—" and b.locator(".avat img").count() == 0 and b.locator(".avat").inner_text() == "S"
    assert p.inner_text("#lVideos") == "Chaînes" and p.inner_text("#tVideos") == "2" and "2 chaînes" in p.inner_text("#lecture")
    assert [x.inner_text() for x in a.locator(".act").all()] == ["Ouvrir ›", "☆", "📡", "↗"]
    assert ("GET", "flux?type=chaines&limite=24", None) in appels and err == []
    captures(p, "chaines-1400.png")
    ctx.close()


def test_playlists_titre_chaine_et_nombre_seulement_s_il_est_fourni(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "")
    onglet(p, "playlists")
    attend(p, "#grille .video")
    c = p.locator("#grille .video")
    assert c.count() == 2 and "PLAYLIST" in c.nth(0).inner_text()
    assert "Réseaux, de la prise au routeur" in c.nth(0).inner_text() and "vidéos" not in c.nth(0).inner_text()
    assert "7 vidéos" in c.nth(1).inner_text() and "Atelier Sonore" in c.nth(1).inner_text()
    assert p.inner_text("#lVideos") == "Playlists" and err == []
    ctx.close()


# ── navigation ──
def test_ouvrir_une_chaine_fil_d_ariane_focus_retour_et_etat_conserve(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "")
    onglet(p, "chaines")
    attend(p, "#grille .fiche")
    p.evaluate("window.scrollTo(0, 0)")
    ouvre_btn = p.locator("#grille .fiche").nth(0).get_by_text("Ouvrir ›")
    ouvre_btn.click()
    p.wait_for_selector("#fil:not([hidden])")
    p.wait_for_selector("#grille .video", state="attached")
    assert ("GET", f"flux/chaine/{UC1}?limite=24", None) in appels
    assert p.locator("#fil li").all_inner_texts() == ["Mes chaînes", "Atelier Réseau"]
    assert p.get_attribute("#fNom", "aria-current") == "page"
    assert p.evaluate("document.activeElement.id") == "fNom"                      # le focus suit la navigation
    assert p.locator("#grille .video").count() == 4 and "4 vidéos" in p.inner_text("#lecture")
    assert p.get_attribute("#onglets [data-type=chaines]", "aria-selected") == "true"
    assert [b.inner_text() for b in p.locator("#fActs .act").all()] == ["☆", "📡", "↗"]
    captures(p, "chaine-detail-1400.png")
    n_avant = len([a for a in appels if a[1].startswith("flux?type=chaines")])
    p.click("#fRetour")
    p.wait_for_selector("#fil", state="hidden")
    assert p.locator("#grille .fiche").count() == 2
    assert p.evaluate("document.activeElement.dataset.cle") == f"chaine:{UC1}"      # le focus revient sur le bouton qui avait ouvert
    assert len([a for a in appels if a[1].startswith("flux?type=chaines")]) == n_avant     # état conservé : aucune relecture
    # le fil d'Ariane (premier maillon) et Échap font la même chose
    p.locator("#grille .fiche").nth(0).get_by_text("Ouvrir ›").click()
    p.wait_for_selector("#fil:not([hidden])")
    p.click("#fListe")
    p.wait_for_selector("#fil", state="hidden")
    p.locator("#grille .fiche").nth(0).get_by_text("Ouvrir ›").click()
    p.wait_for_selector("#fil:not([hidden])")
    p.keyboard.press("Escape")
    p.wait_for_selector("#fil", state="hidden")
    assert p.locator("#grille .fiche").count() == 2 and err == []
    ctx.close()


def test_ouvrir_une_playlist_et_ses_videos_gardent_les_actions_de_video(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "")
    onglet(p, "playlists")
    attend(p, "#grille .video")
    p.locator("#grille .video").nth(0).get_by_text("Ouvrir ›").click()
    p.wait_for_selector("#fil:not([hidden])")
    p.wait_for_function("document.querySelectorAll('#grille .video').length === 3")
    assert ("GET", f"flux/playlist/{PL1}?limite=24", None) in appels
    assert p.locator("#fil li").all_inner_texts() == ["Playlists", "Réseaux, de la prise au routeur"]
    v = p.locator("#grille .video").first
    assert [b.inner_text() for b in v.locator(".act").all()] == ["▶ YouTube", "⬇ SAS", "⧉", "☆", "🧭", "📡"]
    p.click("#fRetour")
    p.wait_for_selector("#fil", state="hidden")
    assert p.get_attribute("#onglets [data-type=playlists]", "aria-selected") == "true" and p.locator("#grille .video").count() == 2
    assert p.evaluate("document.activeElement.dataset.cle") == f"playlist:{PL1}" and err == []
    ctx.close()


def test_detail_pannes_dites_comme_pour_les_listes(navigateur):
    cas = [
        ((401, {"error": "cookies périmés", "cookies_perimes": True}), "cookies sont périmés"),
        ((401, {"detail": "jeton requis"}), "Connexion requise"),
        ((502, {"error": "x", "detail": "délai"}), "n’a pas répondu (délai)"),
        ((404, {"error": "identifiant invalide"}), "n’existe pas ou n’est pas lisible"),
    ]
    for rep, texte in cas:
        ctx, p, err, _ = ouvre(navigateur, "", details={("chaine", UC1): rep})
        onglet(p, "chaines")
        attend(p, "#grille .fiche")
        p.locator("#grille .fiche").nth(0).get_by_text("Ouvrir ›").click()
        p.wait_for_selector("#msg:not([hidden])")
        assert texte in p.inner_text("#msg") and p.inner_text("#tVideos") == "—", texte
        assert p.is_visible("#fRetour")                       # on peut toujours revenir
        ctx.close()
    # données anciennes : la cause cookies est dite, comme pour les listes
    det = {("chaine", UC1): (200, {**DETAILS[("chaine", UC1)][1], "perime": True, "cause": "cookies", "en_cache": True})}
    ctx, p, err, _ = ouvre(navigateur, "", details=det)
    onglet(p, "chaines")
    attend(p, "#grille .fiche")
    p.locator("#grille .fiche").nth(0).get_by_text("Ouvrir ›").click()
    p.wait_for_selector("#grille .video", state="attached")
    assert "cookies YouTube périmés" in p.inner_text("#lecture") and "PÉRIMÉES" in p.inner_text("#etat") and err == []
    ctx.close()


def test_cookies_perimes_sur_la_liste_des_chaines_message_inchange(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "", flux={"chaines": (401, {"error": "auth requise", "cookies_perimes": True})})
    onglet(p, "chaines")
    p.wait_for_selector("#msg:not([hidden])")
    assert "YouTube ne reconnaît plus ton compte : tes cookies sont périmés" in p.inner_text("#msg")
    assert p.inner_text("#etat") == "COOKIES PÉRIMÉS" and p.inner_text("#tVideos") == "—" and err == []
    ctx.close()


# ── favoris ──
def test_favoris_des_trois_types_ecrits_au_format_du_hall_avec_leur_type(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "", init="localStorage.getItem('amorce')||(localStorage.setItem('amorce','1'),localStorage.setItem('sbx_favoris',JSON.stringify(['https://exemple.test/a','https://www.youtube.com/watch?v=zzzzzzzzzzz'])));")
    attend(p, "#grille .video")
    assert favoris(p) == ["https://exemple.test/a", "https://www.youtube.com/watch?v=zzzzzzzzzzz"]      # amorce : ancien format, adresses seules
    p.locator("#grille .video").first.locator("button[aria-label=Favori]").click()
    onglet(p, "chaines")
    attend(p, "#grille .fiche")
    p.locator("#grille .fiche").first.locator("button[aria-label=Favori]").click()
    onglet(p, "playlists")
    attend(p, "#grille .video")
    p.locator("#grille .video").first.locator("button[aria-label=Favori]").click()
    # sbx_favoris reste une liste d'ADRESSES (rien d'autre qu'une chaîne dedans) : le Hall et Surf & Viewer continuent de la lire
    assert favoris(p) == ["https://exemple.test/a", "https://www.youtube.com/watch?v=zzzzzzzzzzz", U_VID, U_CH, U_PL]
    assert all(isinstance(u, str) for u in favoris(p))
    m = meta(p)
    assert m[U_VID]["type"] == "video" and m[U_VID]["titre"] == "Vidéo numéro 0" and m[U_VID]["chaine"] == "Atelier Réseau"
    assert m[U_CH]["type"] == "chaine" and m[U_CH]["titre"] == "Atelier Réseau" and m[U_CH]["abonnes"] == 48200 and m[U_CH]["handle"] == "@atelier-reseau"
    assert m[U_PL]["type"] == "playlist" and m[U_PL]["titre"] == "Réseaux, de la prise au routeur" and "videos" not in m[U_PL]
    assert set(m) == {U_VID, U_CH, U_PL}
    assert p.locator("#grille .video").first.locator("button[aria-label=Favori]").inner_text() == "★"
    # retirer : l'adresse ET sa fiche disparaissent, les autres favoris du Hall restent à leur place
    p.locator("#grille .video").first.locator("button[aria-label=Favori]").click()
    assert favoris(p) == ["https://exemple.test/a", "https://www.youtube.com/watch?v=zzzzzzzzzzz", U_VID, U_CH] and U_PL not in meta(p)
    assert err == []
    ctx.close()


def test_onglet_favoris_rassemble_les_trois_types_filtre_et_retire(navigateur):
    pre = ("localStorage.getItem('amorce')||(localStorage.setItem('amorce','1'),"
           f"localStorage.setItem('sbx_favoris',JSON.stringify(['https://exemple.test/a','{U_VID}','{U_CH}','{U_PL}','https://www.youtube.com/watch?v=ancienne000'])),"
           f"localStorage.setItem('sbx_favoris_meta',JSON.stringify({{'{U_VID}':{{type:'video',titre:'Ma vidéo',chaine:'Une chaîne',duree:75}},"
           f"'{U_CH}':{{type:'chaine',titre:'Ma chaîne',abonnes:1200}},'{U_PL}':{{type:'playlist',titre:'Ma liste',chaine:'Une chaîne'}}}})));")
    ctx, p, err, appels = ouvre(navigateur, "", init=pre)
    attend(p, "#grille .video")
    def sans_images():
        return [a for a in appels if not a[1].startswith("flux/vignette/")]
    n0 = len(sans_images())
    onglet(p, "favoris")
    p.wait_for_selector("#filtres:not([hidden])")
    assert len(sans_images()) == n0                              # l'onglet Favoris ne lit que le navigateur, aucune requête
    assert p.locator("#grille h4").all_inner_texts() == ["Vidéos (2)", "Chaînes (1)", "Playlists (1)"]
    assert "Ma vidéo" in p.inner_text("#grille") and "1:15" in p.inner_text("#grille")
    assert "Ma chaîne" in p.inner_text("#grille") and "Ma liste" in p.inner_text("#grille")
    assert "4 favoris" in p.inner_text("#lecture") and "1 autre adresse du Hall non listée" in p.inner_text("#lecture")
    assert p.inner_text("#lVideos") == "Favoris" and p.inner_text("#tVideos") == "4"
    # une ancienne vidéo favorite sans fiche : affichée sans titre inventé
    assert p.locator("#grille .video").filter(has_text="ancienne000").count() == 0
    assert p.locator("#grille .video .titre").all_inner_texts().count("—") == 1
    captures(p, "favoris-1400.png")
    p.click("#filtres [data-filtre=chaine]")
    assert p.locator("#grille h4").all_inner_texts() == ["Chaînes (1)"] and p.get_attribute("#filtres [data-filtre=chaine]", "aria-pressed") == "true"
    assert p.evaluate("document.activeElement.dataset.filtre") == "chaine"
    p.click("#filtres [data-filtre=tout]")
    # on ouvre la chaîne favorite depuis l'onglet, et Retour revient aux favoris
    p.locator("#grille .fiche").get_by_text("Ouvrir ›").click()
    p.wait_for_selector("#fil:not([hidden])")
    assert p.locator("#fil li").all_inner_texts() == ["Favoris", "Ma chaîne"]
    p.click("#fRetour")
    p.wait_for_selector("#grille h4", state="attached")
    assert p.get_attribute("#onglets [data-type=favoris]", "aria-selected") == "true"
    # retirer un favori depuis l'onglet
    p.locator("#grille .fiche").first.locator("button[aria-label=Favori]").click()
    p.wait_for_function("document.querySelectorAll('#grille h4').length === 2")
    assert U_CH not in favoris(p) and "https://exemple.test/a" in favoris(p) and U_CH not in meta(p)
    assert err == []
    ctx.close()


def test_favoris_vide_dit_comment_en_ajouter(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "")
    onglet(p, "favoris")
    p.wait_for_selector("#msg:not([hidden])")
    assert "Aucun favori pour l’instant" in p.inner_text("#msg") and p.inner_text("#etat") == "AUCUN FAVORI" and p.inner_text("#tVideos") == "0"
    ctx.close()


def test_une_fiche_corrompue_ne_casse_ni_ne_s_affiche_comme_html(navigateur):
    pre = (f"localStorage.setItem('sbx_favoris','[\"{U_VID}\",\"{U_CH}\"]');"
           f"localStorage.setItem('sbx_favoris_meta',JSON.stringify({{'{U_VID}':{{titre:'<img src=x onerror=window.__pwn=1>',duree:'abc',vignette:'javascript:1'}},'{U_CH}':[1,2]}}));")
    ctx, p, err, _ = ouvre(navigateur, "", init=pre)
    onglet(p, "favoris")
    p.wait_for_selector("#grille h4", state="attached")
    assert "<img src=x" in p.inner_text("#grille") and p.evaluate("window.__pwn") is None
    assert p.locator("#grille img[src^='javascript']").count() == 0 and err == []
    ctx.close()


# ── diffusion ──
def test_diffuser_une_video_envoie_le_message_exact_du_protocole_du_hall(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "")
    attend(p, "#grille .video")
    b = p.locator("#grille .video").first.get_by_label("Diffuser dans le Hall")
    b.click()
    p.wait_for_function("__msgs.some(m => m.sbx === 'diffuser')")
    envoyes = [m for m in p.evaluate("__po") if m[0].get("sbx") == "diffuser"]
    assert envoyes == [[{"sbx": "diffuser", "url": U_VID, "titre": "Vidéo numéro 0"}, "http://sbx.test"]]    # location.origin, jamais '*'
    assert p.is_disabled("#grille .video >> nth=0 >> button[aria-label='Diffuser dans le Hall']")           # en attente de la réponse du Hall
    # le Hall répond (même origine, depuis le parent) : la carte dit le sort de la diffusion
    p.evaluate(f"window.postMessage({{sbx:'diffuser-resultat', url:'{U_VID}', ok:true, statut:200}}, location.origin)")
    p.wait_for_function("document.querySelector('#retour').textContent.includes('Diffusé dans le Hall')")
    assert "Vidéo numéro 0" in p.inner_text("#retour") and not b.is_disabled() and b.inner_text() == "📡"
    assert err == []
    ctx.close()


def test_diffusion_refusee_ou_sans_session_est_dite_et_une_reponse_etrangere_est_ignoree(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "")
    attend(p, "#grille .video")
    b = p.locator("#grille .video").first.get_by_label("Diffuser dans le Hall")
    b.click()
    p.evaluate("window.postMessage({sbx:'diffuser-resultat', url:'https://autre.test/', ok:true, statut:200}, location.origin)")   # autre adresse
    p.wait_for_timeout(150)
    assert b.is_disabled() and p.is_hidden("#retour")
    p.evaluate(f"window.postMessage({{sbx:'diffuser-resultat', url:'{U_VID}', ok:false, statut:401}}, location.origin)")
    p.wait_for_function("document.querySelector('#retour').textContent.includes('réservée aux personnes connectées')")
    b.click()
    p.evaluate(f"window.postMessage({{sbx:'diffuser-resultat', url:'{U_VID}', ok:false, statut:422}}, location.origin)")
    p.wait_for_function("document.querySelector('#retour').textContent.includes('HTTP 422')")
    assert err == []
    ctx.close()


def test_diffuser_une_chaine_ou_une_playlist_diffuse_sa_premiere_video_et_le_dit(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "")
    onglet(p, "chaines")
    attend(p, "#grille .fiche")
    p.locator("#grille .fiche").first.get_by_label("Diffuser dans le Hall").click()
    p.wait_for_function("__po.some(m => m[0].sbx === 'diffuser')")
    assert ("GET", f"flux/chaine/{UC1}?limite=24", None) in appels
    envoyes = [m for m in p.evaluate("__po") if m[0].get("sbx") == "diffuser"]
    assert envoyes == [[{"sbx": "diffuser", "url": U_VID, "titre": "Vidéo numéro 0"}, "http://sbx.test"]]       # une adresse, comme le protocole le veut
    p.evaluate(f"window.postMessage({{sbx:'diffuser-resultat', url:'{U_VID}', ok:true, statut:200}}, location.origin)")
    p.wait_for_function("document.querySelector('#retour').textContent.includes('première vidéo de « Atelier Réseau »')")
    # depuis la vue ouverte : pas de relecture, la liste est déjà en mémoire
    p.locator("#grille .fiche").first.get_by_text("Ouvrir ›").click()
    p.wait_for_selector("#grille .video", state="attached")
    n = len([a for a in appels if a[1].startswith("flux/chaine/")])
    p.locator("#fActs").get_by_label("Diffuser dans le Hall").click()
    p.wait_for_function("__po.filter(m => m[0].sbx === 'diffuser').length === 2")
    assert len([a for a in appels if a[1].startswith("flux/chaine/")]) == n
    # playlist
    onglet(p, "playlists")
    attend(p, "#grille .video")
    p.locator("#grille .video").first.get_by_label("Diffuser dans le Hall").click()
    p.wait_for_function("__po.filter(m => m[0].sbx === 'diffuser').length === 3")
    dernier = [m for m in p.evaluate("__po") if m[0].get("sbx") == "diffuser"][-1]
    assert dernier[0]["url"] == "https://www.youtube.com/watch?v=abcdefghi05" and dernier[1] == "http://sbx.test"
    assert err == []
    ctx.close()


def test_diffuser_une_liste_illisible_ou_vide_n_envoie_rien(navigateur):
    vide = {("chaine", UC1): (200, {"type": "chaine", "id": UC1, "titre": "x", "items": [], "en_cache": False, "perime": False, "date": NOW}),
            ("playlist", PL1): (401, {"error": "cookies périmés", "cookies_perimes": True})}
    ctx, p, err, _ = ouvre(navigateur, "", details=vide)
    onglet(p, "chaines")
    attend(p, "#grille .fiche")
    p.locator("#grille .fiche").first.get_by_label("Diffuser dans le Hall").click()
    p.wait_for_function("document.querySelector('#retour').textContent.includes('Rien à diffuser')")
    onglet(p, "playlists")
    attend(p, "#grille .video")
    p.locator("#grille .video").first.get_by_label("Diffuser dans le Hall").click()
    p.wait_for_function("document.querySelector('#retour').textContent.includes('rien n’est diffusé')")
    assert [m for m in p.evaluate("__po") if m[0].get("sbx") == "diffuser"] == [] and err == []
    ctx.close()


def test_embed_masque_ce_qui_n_a_de_sens_que_dans_le_hall(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "?embed=1", taille={"width": 700, "height": 700})
    attend(p, "#grille .video")
    v = p.locator("#grille .video").first
    assert not v.get_by_label("Diffuser dans le Hall").is_visible() and not v.get_by_label("Voir dans Surf").is_visible()
    assert v.get_by_label("Favori").is_visible() and v.get_by_label("Copier le lien").is_visible()
    onglet(p, "chaines")
    attend(p, "#grille .fiche")
    f = p.locator("#grille .fiche").first
    assert not f.get_by_label("Diffuser dans le Hall").is_visible() and f.get_by_text("Ouvrir ›").is_visible()
    f.get_by_text("Ouvrir ›").click()
    p.wait_for_selector("#fil:not([hidden])")
    assert not p.locator("#fActs").get_by_label("Diffuser dans le Hall").is_visible() and p.locator("#fActs").get_by_label("Favori").is_visible()
    p.wait_for_function("__msgs.some(m => m.sbxVue)")
    m = [x for x in p.evaluate("__msgs") if x.get("sbxVue")][-1]
    h = p.evaluate("Math.ceil(document.querySelector('.cadre').getBoundingClientRect().bottom + scrollY)")
    assert m["onglet"] == "ytflux" and abs(m["sbxVue"] - h) <= 2 and err == []
    ctx.close()


# ── démonstration ──
def test_demo_chaines_playlists_favoris_et_diffusion_inerte_sans_aucune_requete(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "?demo=1", flux={}, details={})
    attend(p, "#grille .video")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and "inertes" in p.inner_text("#demo")
    onglet(p, "chaines")
    attend(p, "#grille .fiche")
    assert p.locator("#grille .fiche").count() == 4 and "Atelier Réseau" in p.inner_text("#grille")
    assert p.locator("#grille .fiche").nth(3).locator(".stat").inner_text() == "—"                # chaîne fictive sans chiffres
    p.locator("#grille .fiche").first.get_by_text("Ouvrir ›").click()                              # naviguer reste possible en démo
    p.wait_for_selector("#fil:not([hidden])")
    p.wait_for_selector("#grille .video", state="attached")
    assert p.locator("#fil li").all_inner_texts() == ["Mes chaînes", "Atelier Réseau"] and p.locator("#grille .video").count() == 4
    p.locator("#grille .video").first.get_by_label("Diffuser dans le Hall").click()
    assert "inerte" in p.inner_text("#retour")
    p.locator("#fActs").get_by_label("Diffuser dans le Hall").click()
    p.locator("#fActs").get_by_label("Favori").click()
    p.click("#fRetour")
    onglet(p, "playlists")
    attend(p, "#grille .video")
    p.locator("#grille .video").first.get_by_label("Favori").click()
    p.locator("#grille .video").first.get_by_label("Diffuser dans le Hall").click()
    onglet(p, "favoris")
    p.wait_for_selector("#grille h4", state="attached")
    assert p.locator("#grille h4").all_inner_texts() == ["Vidéos (2)", "Chaînes (1)", "Playlists (1)"]
    assert p.locator("#grille .fiche button[aria-label=Favori]").first.inner_text() == "★"
    p.locator("#grille .fiche button[aria-label=Favori]").first.click()
    assert "inerte" in p.inner_text("#retour") and p.locator("#grille h4").count() == 3            # le retrait est inerte
    p.wait_for_timeout(200)
    assert p.evaluate("localStorage.getItem('sbx_favoris')") is None and p.evaluate("localStorage.getItem('sbx_favoris_meta')") is None
    assert [m for m in p.evaluate("__msgs") if "sbx" in m] == [] and [m for m in p.evaluate("__po") if "sbx" in m[0]] == []
    assert appels == [] and err == []
    captures(p, "demo-favoris-1400.png")
    ctx.close()


# ── 420 px ──
def test_telephone_420_sans_debordement_sur_les_nouvelles_vues(navigateur):
    pre = (f"localStorage.setItem('sbx_favoris',JSON.stringify(['{U_VID}','{U_CH}','{U_PL}']));"
           f"localStorage.setItem('sbx_favoris_meta',JSON.stringify({{'{U_CH}':{{type:'chaine',titre:'Une chaîne au nom très long qui doit passer à la ligne sans rien déborder',abonnes:12345678}}}}));")
    for q in ("", "?embed=1", "?demo=1"):
        ctx, p, err, _ = ouvre(navigateur, q, taille={"width": 420, "height": 800}, init=pre)

        def sain(etape):
            assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), (q, etape)
            assert p.evaluate("""[...document.querySelectorAll('.video,.fiche')].every(c => [...c.querySelectorAll('.act')].filter(a => a.offsetWidth > 0).every(a =>
                a.getBoundingClientRect().right <= c.getBoundingClientRect().right + 1 && a.getBoundingClientRect().left >= c.getBoundingClientRect().left - 1))"""), (q, etape)
            assert p.evaluate("[...document.querySelectorAll('#onglets .onglet')].every(o => o.getBoundingClientRect().right <= innerWidth)"), (q, etape)
        attend(p, "#grille .video")
        sain("envie")
        onglet(p, "chaines")
        attend(p, "#grille .fiche")
        sain("chaines")
        captures(p, f"chaines-420{'-embed' if 'embed' in q else '-demo' if 'demo' in q else ''}.png")
        p.locator("#grille .fiche").first.get_by_text("Ouvrir ›").click()
        p.wait_for_selector("#fil:not([hidden])")
        p.wait_for_selector("#grille .video", state="attached")
        sain("détail")
        if not q:
            captures(p, "detail-420.png")
        onglet(p, "playlists")
        attend(p, "#grille .video")
        sain("playlists")
        onglet(p, "favoris")
        p.wait_for_selector("#grille h4", state="attached")
        sain("favoris")
        if not q:
            captures(p, "favoris-420.png")
        assert err == [], q
        ctx.close()
