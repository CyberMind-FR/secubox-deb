# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2612 — /photoprism/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "photoprism" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-light" not in SRC and "/shared/crt-engine.js" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onchange=", "onsubmit="):
        assert interdit not in SRC, interdit
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'photoprism'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC


def test_routes_d_ecriture_a_l_identique():
    posts = set(re.findall(r"(?:action\(|ecrire\('POST', )'(/[a-z/_-]+)'", SRC))
    attendues = {"/container/stop", "/container/start", "/container/install", "/library/index", "/library/import",
                 "/container/update", "/backup", "/container/uninstall", "/album/create"}
    assert attendues <= posts, sorted(attendues - posts)
    # Réglages et reconnaissance faciale : l'API refuse de réécrire le TOML, la page ne les envoie plus.
    assert "/config'" not in SRC and "/faces/enable" not in SRC and "/faces/disable" not in SRC
    assert "DELETE" not in SRC and "/user" not in SRC
    # Plus de lien http://<hôte>:<port> (le port du LXC n'est pas exposé) : on suit public_url.
    assert "public_url" in SRC and "location.hostname" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"container_status": "running", "http_reachable": True, "lxc_state": "running", "lxc_name": "photoprism", "lxc_ip": "192.0.2.130", "port": 2342,
          "build": "native", "domain": "photos.example.org", "public_url": "https://photos.example.org/", "timezone": "Europe/Paris", "haproxy": True,
          "face_recognition": True, "experimental": False, "readonly": False, "public": False,
          "library_stats": {"total_photos": 1234, "total_videos": 56, "total_albums": 2, "storage_used": "12G", "import_pending": 7, "mesure_en_cours": False}}
ALBUMS = {"albums": [{"id": "a1", "title": "<b>Corse</b>", "photo_count": 40}, {"id": "a2", "title": "Famille", "photo_count": 0}]}
STORAGE = {"data_path": "/data/photoprism", "originals_path": "/data/shared/photos", "import_path": "/data/photoprism/import",
           "data_size": "1G", "originals_size": "12G", "import_size": "5M", "disk_free": "300G", "disk_total": "900G", "disk_used_percent": 66}
API = {"/status": (200, STATUS), "/albums": (200, ALBUMS), "/storage": (200, STORAGE), "/faces": (200, {"enabled": True, "status": "active"}),
       "/logs": (200, {"logs": "ligne un\nligne deux"})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif: " + d.message), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "photoprism":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/photoprism", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        if r.request.method != "GET":
            statut, corps = routes.get(chemin, (200, {"success": True}))
        else:
            statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/photoprism/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/photoprism/", API)
    p.wait_for_function("document.getElementById('tPhotos').textContent !== '—'")
    assert [p.inner_text(i) for i in ("#tEtat", "#tPhotos", "#tVideos", "#tAlbums", "#tStock", "#tImport")] == ["En marche", "1234", "56", "2", "12G", "7"]
    assert p.inner_text("#etat") == "EN MARCHE" and p.get_attribute("#ouvrir", "href") == "https://photos.example.org/"
    p.click("#o-albums")
    p.wait_for_selector("#gAlb .album")
    assert "<b>Corse</b>" in p.inner_text("#gAlb") and p.locator("#gAlb b b").count() == 0   # titre en texte, jamais en HTML
    p.click("#o-stockage"); p.wait_for_function("document.getElementById('sTotal').textContent !== '—'")
    assert p.inner_text("#sTotal") == "900G" and "/data/shared/photos" in p.inner_text("#bDoss")
    p.click("#o-journaux"); p.wait_for_function("document.getElementById('journal').textContent.includes('deux')")
    p.click("#o-reglages")
    assert "photos.example.org" in p.inner_text("#kDom") and "Activé" in p.inner_text("#kFaces")
    assert err == []
    ctx.close()


def test_mesure_en_cours_reste_a_tiret(navigateur):
    st = {**STATUS, "library_stats": {"total_photos": 0, "total_videos": 0, "total_albums": 0, "storage_used": "0", "import_pending": 0, "mesure_en_cours": True}}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/photoprism/", {**API, "/status": (200, st)})
    p.wait_for_function("document.getElementById('tEtat').textContent !== '—'")
    assert [p.inner_text(i) for i in ("#tPhotos", "#tVideos", "#tAlbums", "#tStock", "#tImport")] == ["—"] * 5
    assert err == []
    ctx.close()


def test_indexation_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/photoprism/", API)
    p.wait_for_function("!document.getElementById('btnIndex').disabled")
    p.click("#btnIndex")
    assert p.is_visible("#conf") and not [a for a in appels if a[0] == "POST"]
    p.click("#confNon")
    assert not p.is_visible("#conf") and not [a for a in appels if a[0] == "POST"]
    p.click("#btnIndex"); p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Indexation lancée')")
    assert ("POST", "/library/index", None) in appels and err == []
    ctx.close()


def test_arret_confirme_et_echec_affiche_le_motif(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/photoprism/", {**API, "/container/stop": (200, {"success": False, "output": "lxc-stop: refusé"})})
    p.wait_for_selector("#bascule:not([hidden])")
    assert p.inner_text("#bascule") == "Arrêter"
    p.click("#bascule")
    assert not [a for a in appels if a[1] == "/container/stop"]
    p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('refusé')")
    assert p.get_attribute("#retour", "class").endswith("ko") and err == []
    ctx.close()


def test_creer_un_album_envoie_le_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/photoprism/", {**API, "/album/create": (200, {"success": True, "album": {}})})
    p.click("#o-albums")
    p.fill("#fAlbum [name=title]", "Noël"); p.fill("#fAlbum [name=description]", "2026")
    p.click("#fAlbum button[type=submit]")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Album créé')")
    post = [a for a in appels if a[1] == "/album/create"][0]
    assert post[0] == "POST" and json.loads(post[2]) == {"title": "Noël", "description": "2026"} and err == []
    ctx.close()


def test_jeton_sbx_token_envoye(navigateur):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    vus = []
    p.route("http://sbx.test/**", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SRC) if r.request.url.endswith("/photoprism/") else
            (vus.append(r.request.headers.get("authorization")) or r.fulfill(status=200, content_type="application/json", body=json.dumps(STATUS))) if "/api/" in r.request.url
            else r.fulfill(status=200, content_type="application/javascript", body=""))
    p.add_init_script("localStorage.setItem('sbx_token','jeton-test')")
    p.goto("http://sbx.test/photoprism/")
    p.wait_for_function("document.getElementById('tEtat').textContent !== '—'")
    assert vus and all(v == "Bearer jeton-test" for v in vus)
    assert "jeton-test" not in p.inner_text("body")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/photoprism/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tEtat", "#tPhotos", "#tAlbums", "#tStock")] == ["—"] * 4
    assert p.url.endswith("/photoprism/") and err == []     # plus de redirection forcée vers /login.html
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/photoprism/?demo=1", {})
    p.wait_for_function("document.getElementById('tPhotos').textContent === '18452'")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.click("#btnImport")
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    p.click("#o-reglages"); p.click("#btnMaj"); p.click("#confOui")
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/photoprism/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tPhotos').textContent !== '—'")
    for onglet in ("o-albums", "o-stockage", "o-reglages", "o-journaux"):
        p.click("#" + onglet)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), onglet
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
