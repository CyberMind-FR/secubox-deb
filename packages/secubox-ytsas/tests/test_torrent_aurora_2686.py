# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2686 — Torrent au profil Aurora : la page d'administration (hub) et sa variante du conteneur (lecteur public).

Statique + vrai navigateur (API simulée sur http://sbx.test, données factices). Les deux pages partagent le même
habillage et le même contrat d'API ; seule l'administration charge le menu commun.
"""
import json
import re
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
TORRENT = PKG / "composants" / "torrent"
PAGES = {"admin": TORRENT / "www" / "torrent" / "index.html", "conteneur": TORRENT / "lxc" / "www" / "index.html"}
SOURCES = {k: p.read_text(encoding="utf-8") for k, p in PAGES.items()}
VARIANTES = list(PAGES)

IH = "0123456789abcdef0123456789abcdef01234567"
IH2 = "fedcba9876543210fedcba9876543210fedcba98"


# ───────────────────────── statique ─────────────────────────

@pytest.mark.parametrize("v", VARIANTES)
def test_page_autonome_sans_dialogue_natif_ni_ancienne_peau(v):
    src = SOURCES[v]
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in src
    assert re.findall(r"<script[^>]*\ssrc=", src) == []              # rien d'externe en dur : le menu est injecté à l'exécution
    assert "hybrid-skin" not in src and "hybrid-dark" not in src and "Courier" not in src
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "onclick=", "http://", "https://fonts"):
        assert interdit not in src, interdit
    assert "lorem" not in src.lower()
    assert "--fond:#060d1b" in src and "container-type:inline-size" in src
    assert "sbxVue" in src and "onglet: 'torrent'" in src and "demo" in src.lower() and "embed" in src
    assert "setItem" not in src and "Math.random" not in src


@pytest.mark.parametrize("v", VARIANTES)
def test_les_appels_d_api_sont_ceux_de_l_ancienne_page(v):
    """Mêmes routes, méthodes, corps et en-têtes qu'avant : on refait la peau, pas le contrat."""
    src = SOURCES[v]
    assert "var API = '/api/v1/torrent';" in src
    for r in ("lire('/status')", "lire('/list')", "'/files/'", "'/resume/'", "'/conserve/'", "'/keep/'", "'/ephemeral/'", "'/remove/'",
              "'/zip/'", "'/add-file'", "'/add'", "'/stream/'"):
        assert r in src, r
    assert "ecrire('POST', '/add'" in src and "ecrire('POST', '/add-file'" in src and "'application/x-bittorrent'" in src
    assert "{ torrentUrl: val }" in src and "{ magnet: val }" in src and "{ seconds: secs }" in src
    assert "localStorage.getItem('sbx_token')" in src and "'Bearer ' + t" in src
    assert "DELETE" not in src                                     # l'ancienne page n'en utilisait pas : tout part en POST
    # lecteur identique : balise video native sur /stream/<infohash>/<index>
    assert "document.createElement('video')" in src and "v.controls = true" in src and "v.autoplay = true" in src
    assert "'/stream/' + encodeURIComponent(ih) + '/' + encodeURIComponent(idx)" in src


def test_menu_commun_seulement_dans_l_administration():
    assert "'/shared/sidebar.js'" in SOURCES["admin"] and "!EMBED && !DEMO" in SOURCES["admin"]
    code = SOURCES["conteneur"].split("<body>", 1)[1]                # hors commentaire d'en-tête
    assert "/shared/" not in code and "sidebar.js" not in code


def test_la_variante_du_conteneur_garde_son_contrat_propre():
    # le moteur du conteneur n'écrit que PeerTube : pas de Lyrion, étiquette d'attente d'origine
    assert "lyrion" not in SOURCES["conteneur"].lower().replace("lyrion pour", "")
    assert "📼 upload…" in SOURCES["conteneur"]
    assert "Lyrion" in SOURCES["admin"] and "lyrion_path" in SOURCES["admin"]


# ───────────────────────── navigateur ─────────────────────────

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
STATUS = {"status": "ok", "active": 2, "disk_free": 5 * 1073741824, "webrtc": True}
LIST = [
    {"infohash": IH, "name": "alpha.iso", "complete": True, "ephemeral_until": None, "peertube_status": None, "lyrion_status": None,
     "stats": {"progress": 1, "downloadSpeed": 0, "uploadSpeed": 2048, "numPeers": 3, "wires": [1, 2, 3]}},
    {"infohash": IH2, "name": "beta.mp4", "complete": False, "ephemeral_until": NOW + 7200, "peertube_status": "done", "peertube_url": "https://pt.example.org/w/x",
     "stats": {"progress": 0.5, "downloadSpeed": 1048576, "uploadSpeed": 0, "numPeers": 4, "wires": [1]}},
    {"infohash": "00112233445566778899aabbccddeeff00112233", "name": "gamma", "complete": True, "ephemeral_until": None, "stats": None},
]
FILES = [{"idx": 0, "name": "film.mp4", "length": 2097152}, {"idx": 1, "name": "notes.txt", "length": 120}]
API = {"/status": (200, STATUS), "/list": (200, LIST), "/files/" + IH: (200, FILES)}


def ouvre(navigateur, v, routes, requete="", taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels, natifs, partages, flux = [], [], [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
    p.natifs, p.partages, p.flux = natifs, partages, flux

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            partages.append(chemin)
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.startswith("stream/"):
            flux.append(chemin)
            r.fulfill(status=200, content_type="video/mp4", body=b"")
        elif chemin.rstrip("/") == "torrent":
            r.fulfill(status=200, content_type="text/html", body=SOURCES[v])
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/torrent", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(r.request.method + " " + chemin, (200, {"status": "ok"}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/torrent/**", api)
    p.goto("http://sbx.test/torrent/" + requete)
    return ctx, p, erreurs, appels


def attend(p):
    p.wait_for_selector("#list .item", state="attached")


def attend_appel(p, appels, chemin, nb=1):
    for _ in range(100):
        if len([a for a in appels if a[1] == chemin and a[0] == "POST"]) >= nb:
            return
        p.wait_for_timeout(50)     # pas time.sleep : il bloquerait les routes simulées
    raise AssertionError("appel jamais reçu : " + chemin)


def ecritures(appels):
    return [(m, c) for m, c, *_ in appels if m != "GET"]


@pytest.mark.parametrize("v", VARIANTES)
def test_tuiles_et_liste_viennent_de_l_api(navigateur, v):
    ctx, p, err, _ = ouvre(navigateur, v, API)
    attend(p)
    assert [p.inner_text(i) for i in ("#tActifs", "#tDisque", "#tWebrtc", "#tTorrents", "#tEph")] == ["2", "5,0 Go", "Actif", "3", "1"]
    assert p.inner_text("#etat") == "ACTIF"
    t = p.inner_text("#list")
    assert "alpha.iso" in t and "beta.mp4" in t and "50 %" in t and "chargé à la lecture" in t and "purge dans 2 h" in t
    assert "PeerTube ✓" in t and "ZIP" in t and "Reprendre" in t
    assert p.locator(".tuile").count() == 5 and all(p.locator(".tuile").nth(i).get_attribute("title") for i in range(5))
    assert err == [] and p.natifs == []
    ctx.close()


@pytest.mark.parametrize("v", VARIANTES)
def test_webrtc_absent_donne_un_tiret_et_desactive_se_dit(navigateur, v):
    ctx, p, _, _ = ouvre(navigateur, v, {**API, "/status": (200, {"status": "ok", "running": False, "asleep": True})})
    attend(p)
    assert p.inner_text("#tWebrtc") == "—" and p.inner_text("#tActifs") == "—" and p.inner_text("#tDisque") == "—"
    assert p.inner_text("#etat") == "MOTEUR ENDORMI"
    ctx.close()
    ctx, p, _, _ = ouvre(navigateur, v, {**API, "/status": (200, {**STATUS, "webrtc": False})})
    attend(p)
    assert p.inner_text("#tWebrtc") == "BitTorrent seul" and "WebRTC désactivé" in p.inner_text("#sousTitre")
    ctx.close()


@pytest.mark.parametrize("v", VARIANTES)
def test_ajouts_envoient_les_memes_corps(navigateur, v):
    ctx, p, err, appels = ouvre(navigateur, v, API)
    attend(p)
    p.fill("#magnetInput", "magnet:?xt=urn:btih:abc")
    p.click("#btnAdd")
    p.wait_for_function("document.getElementById('rAjout').textContent.includes('Torrent ajouté')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/add"][0]
    assert json.loads(post[2]) == {"magnet": "magnet:?xt=urn:btih:abc"} and post[3]["content-type"] == "application/json"
    p.select_option("#addMode", "url")
    p.fill("#urlInput", "https://exemple.test/a.torrent")
    p.press("#urlInput", "Enter")
    attend_appel(p, appels, "/add", 2)
    posts = [json.loads(a[2]) for a in appels if a[0] == "POST" and a[1] == "/add"]
    assert {"torrentUrl": "https://exemple.test/a.torrent"} in posts
    p.select_option("#addMode", "file")
    p.set_input_files("#fileInput", files=[{"name": "x.torrent", "mimeType": "application/x-bittorrent", "buffer": b"d4:infod4:name1:aee"}])
    p.click("#btnAdd")

    attend_appel(p, appels, "/add-file")
    f = [a for a in appels if a[1] == "/add-file"][0]
    assert f[3]["content-type"] == "application/x-bittorrent" and f[2] == "d4:infod4:name1:aee"
    assert err == []
    ctx.close()


@pytest.mark.parametrize("v", VARIANTES)
def test_ajout_sans_valeur_ne_part_pas(navigateur, v):
    ctx, p, _, appels = ouvre(navigateur, v, API)
    attend(p)
    p.click("#btnAdd")
    assert "magnet requis" in p.inner_text("#rAjout")
    assert ecritures(appels) == []
    ctx.close()


@pytest.mark.parametrize("v", VARIANTES)
def test_actions_de_ligne_memes_appels(navigateur, v):
    routes = {**API, "POST /resume/" + "00112233445566778899aabbccddeeff00112233": (200, {"status": "resuming"})}
    ctx, p, err, appels = ouvre(navigateur, v, routes)
    attend(p)
    p.locator(".item").nth(2).get_by_text("Reprendre").click()
    p.wait_for_function("document.getElementById('rListe').textContent.includes('Reprise')")
    p.locator(".item").nth(1).get_by_text("Conserver").click()
    p.wait_for_function("document.getElementById('rListe').textContent.includes('conservé')")
    p.locator(".item").first.locator("select").select_option("3600")
    p.wait_for_function("document.getElementById('rListe').textContent.includes('Purge programmée')")
    p.locator(".item").first.get_by_text("Conserver").click()
    p.wait_for_function("document.getElementById('rListe').textContent.includes('Envoi vers PeerTube')")
    w = ecritures(appels)
    assert ("POST", "/resume/00112233445566778899aabbccddeeff00112233") in w
    assert ("POST", "/keep/" + IH2) in w and ("POST", "/ephemeral/" + IH) in w and ("POST", "/conserve/" + IH) in w
    eph = [a for a in appels if a[1] == "/ephemeral/" + IH][0]
    assert json.loads(eph[2]) == {"seconds": 3600} and eph[3]["content-type"] == "application/json"
    keep = [a for a in appels if a[1] == "/keep/" + IH2][0]
    assert keep[2] is None and "content-type" not in keep[3]        # pas d'en-tête JSON sans corps (Fastify répondrait 400)
    assert err == [] and p.natifs == []
    ctx.close()


@pytest.mark.parametrize("v", VARIANTES)
def test_suppression_demande_confirmation_dans_la_page(navigateur, v):
    ctx, p, _, appels = ouvre(navigateur, v, API)
    attend(p)
    p.locator(".item").first.get_by_text("Supprimer", exact=False).first.click()
    assert not [a for a in appels if "/remove/" in a[1]]
    assert "sans retour" in p.inner_text(".item >> nth=0")
    p.locator(".item").first.get_by_text("Annuler").click()
    assert not [a for a in appels if "/remove/" in a[1]]
    p.locator(".item").first.get_by_text("Supprimer", exact=False).first.click()
    p.locator(".item").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rListe').textContent.includes('supprimé')")
    assert ("POST", "/remove/" + IH) in ecritures(appels) and p.natifs == []
    ctx.close()


@pytest.mark.parametrize("v", VARIANTES)
def test_fichiers_lecteur_et_telechargement(navigateur, v):
    ctx, p, err, _ = ouvre(navigateur, v, API)
    attend(p)
    p.locator(".item").first.locator(".titre").click()
    p.wait_for_selector(".ligne-f")
    assert "film.mp4" in p.inner_text(".fichiers >> nth=0") and "2,0 Mo" in p.inner_text(".fichiers >> nth=0")
    dl = p.locator(".ligne-f a")
    assert dl.get_attribute("href") == "/stream/" + IH + "/1" and dl.get_attribute("download") == "notes.txt"
    p.locator(".ligne-f button").click()
    p.wait_for_selector("#player video")
    assert p.get_attribute("#player video", "src") == "/stream/" + IH + "/0"
    assert p.is_visible("#playerCard") and p.eval_on_selector("#player video", "v => v.controls && v.autoplay")
    assert err == []
    ctx.close()


def test_nom_de_telechargement_assaini(navigateur):
    files = [{"idx": 3, "name": "../../etc/passwd.bin", "length": 5}]
    ctx, p, _, _ = ouvre(navigateur, "admin", {**API, "/files/" + IH: (200, files)})
    attend(p)
    p.locator(".item").first.locator(".titre").click()
    p.wait_for_selector(".ligne-f a")
    assert p.get_attribute(".ligne-f a", "download") == ".._.._etc_passwd.bin"
    ctx.close()


def test_lien_peertube_non_http_n_est_pas_un_lien(navigateur):
    liste = [{**LIST[1], "peertube_url": "javascript:alert(1)"}]
    ctx, p, err, _ = ouvre(navigateur, "admin", {**API, "/list": (200, liste)})
    attend(p)
    assert p.locator(".item a[target=_blank]").count() == 0 and err == []
    ctx.close()


@pytest.mark.parametrize("v", VARIANTES)
def test_sans_session_bandeau_et_tirets(navigateur, v):
    refus = {k: (401, {"error": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, v, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tActifs", "#tDisque", "#tWebrtc", "#tTorrents", "#tEph")] == ["—"] * 5 and err == []
    ctx.close()


@pytest.mark.parametrize("v", VARIANTES)
def test_moteur_injoignable_annonce_hors_ligne(navigateur, v):
    ctx, p, err, _ = ouvre(navigateur, v, {k: (502, {}) for k in API})
    p.wait_for_selector("#erreur:not([hidden])")
    assert p.inner_text("#etat") == "HORS LIGNE" and err == []
    ctx.close()


@pytest.mark.parametrize("v", VARIANTES)
def test_demonstration_annoncee_et_actions_inertes(navigateur, v):
    ctx, p, err, appels = ouvre(navigateur, v, {}, "?demo=1")
    attend(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.inner_text("#tTorrents") == "3" and p.inner_text("#tActifs") == "2"
    p.fill("#magnetInput", "magnet:?xt=urn:btih:demo"); p.click("#btnAdd")
    p.wait_for_function("document.getElementById('rAjout').textContent.includes('inerte')")
    p.locator(".item").nth(1).locator(".titre").click()
    p.wait_for_selector(".ligne-f")
    p.locator(".item").first.get_by_text("Supprimer", exact=False).first.click()
    p.locator(".item").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rListe').textContent.includes('inerte')")
    p.locator(".ligne-f button").first.click()
    assert "aucun flux" in p.inner_text("#player")
    assert appels == [] and p.flux == [] and err == []
    assert "sidebar.js" not in " ".join(p.partages)
    ctx.close()


def test_menu_commun_charge_hors_embed_et_hors_demo(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "admin", API)
    attend(p)
    p.wait_for_function("true")
    assert "shared/sidebar.js" in p.partages and err == []
    ctx.close()
    ctx, p, _, _ = ouvre(navigateur, "conteneur", API)
    attend(p)
    assert p.partages == []                                         # le lecteur public ne dépend pas de /shared/
    ctx.close()


@pytest.mark.parametrize("v", VARIANTES)
def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur, v):
    ctx, p, err, _ = ouvre(navigateur, v, API, "?embed=1", taille={"width": 420, "height": 800})
    attend(p)
    p.locator(".item").first.locator(".titre").click()
    p.wait_for_selector(".ligne-f")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and "sidebar.js" not in " ".join(p.partages) and err == []
    ctx.close()


def test_hauteur_postee_a_l_hote(navigateur):
    ctx = navigateur.new_context(viewport={"width": 1000, "height": 700})
    p = ctx.new_page()
    p.add_init_script("window.__m = []; addEventListener('message', e => { if (e.data && e.data.sbxVue) window.__m.push(e.data); });")
    p.route("http://sbx.test/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SOURCES["admin"]) if r.request.url.endswith("/torrent/")
            else r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://sbx.test/api/v1/torrent/**", lambda r, *_: r.fulfill(status=200, content_type="application/json", body=json.dumps(LIST if r.request.url.endswith("/list") else STATUS)))
    p.goto("http://sbx.test/torrent/")
    p.wait_for_selector("#list .item", state="attached")
    p.wait_for_function("window.__m.length > 0")
    m = p.evaluate("window.__m[window.__m.length - 1]")
    assert m["onglet"] == "torrent" and 200 < m["sbxVue"] < 4000
    ctx.close()
