# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2637 — /podcaster/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "podcaster" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r"<script[^>]*\ssrc=", SRC) == []          # menu commun injecté à l'exécution, rien d'externe en dur
    assert "hybrid-dark" not in SRC and "crt-" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "http://", "https://fonts"):
        assert interdit not in SRC, interdit
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'podcaster'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "/shared/sidebar.js" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("'/feeds'", "'/feeds/import-opml'", "'/audiobook/upload?title='", "'/config'",
              "'/feeds/' + id + '/autodl?on='", "'/feeds/' + id + '/refresh'", "'DELETE', '/feeds/' + id",
              "'/episodes/' + id + '/download'", "'DELETE'", "'/status'", "'/episodes'", "'/media/'",
              "'/share/feed.xml'", "/podcaster/portal/"):
        assert r in SRC, r
    assert "{ url: u, auto_dl: ad }" in SRC and "{ opml }" in SRC and "application/zip" in SRC
    assert "media_path" in SRC and "max_parallel" in SRC and "refresh_minutes" in SRC and "public_base" in SRC and "share_title" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "Bearer" in SRC
    assert "setItem" not in SRC
    # l'ancienne page n'appelait ni /import/url ni /import/status : on ne les invente pas
    assert "/import/" not in SRC


def test_ajouts_2635_conserves():
    assert "f.last_error" in SRC and "f.last_refresh" in SRC and "copySrc(" in SRC and "refreshFeed(" in SRC
    assert "/refresh" in SRC and "navigator.clipboard.writeText" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
STATUS = {"service": "active", "worker": True, "media_path": "/data/podcaster", "public_base": "", "feeds": 2, "episodes": 5, "downloaded": 3, "queued": 1}
FEEDS = {"feeds": [
    {"id": 1, "title": "Radio Exemple", "url": "https://example.org/rss.xml", "site": "https://example.org/", "image": "", "auto_dl": 1,
     "episodes": 3, "downloaded": 2, "last_refresh": NOW - 600, "last_error": None},
    {"id": 2, "title": "Chaîne Test", "url": "https://www.youtube.com/@test", "site": "", "image": "", "auto_dl": 0,
     "episodes": 2, "downloaded": 1, "last_refresh": 0, "last_error": "Cookies refusés par le site"}]}
EPS = {"episodes": [
    {"id": 10, "feed_id": 1, "title": "Épisode un", "feed_title": "Radio Exemple", "pubdate": NOW - 86400, "duration": "12:30", "state": "done", "progress": 100, "error": None},
    {"id": 11, "feed_id": 1, "title": "Épisode deux", "feed_title": "Radio Exemple", "pubdate": NOW - 2 * 86400, "duration": "", "state": "new", "progress": 0, "error": None},
    {"id": 12, "feed_id": 2, "title": "Épisode trois", "feed_title": "Chaîne Test", "pubdate": NOW - 3 * 86400, "duration": "", "state": "error", "progress": 0, "error": "échec réseau"},
    {"id": 13, "feed_id": 2, "title": "Épisode quatre", "feed_title": "Chaîne Test", "pubdate": NOW - 4 * 86400, "duration": "", "state": "downloading", "progress": 40, "error": None}]}
CFG = {"config": {"media_path": "/data/podcaster", "max_parallel": 2, "refresh_minutes": 60, "public_base": "", "share_title": "Mon flux"}}
API = {"/status": (200, STATUS), "/feeds": (200, FEEDS), "/episodes": (200, EPS), "/config": (200, CFG)}

PRESSE_PAPIER = """window.__copie = [];
Object.defineProperty(navigator, 'clipboard', {value: {writeText: t => { window.__copie.push(t); return Promise.resolve(); }}, configurable: true});"""


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    p.add_init_script(PRESSE_PAPIER)
    erreurs, appels, natifs, partages = [], [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
    p.natifs, p.partages = natifs, partages

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            partages.append(chemin)
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "podcaster":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/podcaster", 1)[1]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        cle = chemin.split("?")[0]
        if r.request.method == "GET":
            statut, corps = routes.get(cle, (404, {}))
        else:
            statut, corps = routes.get(r.request.method + " " + cle, (200, {"ok": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/podcaster/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def ecritures(appels):
    return [a for a in appels if a[0] != "GET"]


def test_tuiles_flux_et_episodes_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/podcaster/", API)
    p.wait_for_selector("#feeds .feed", state="attached")
    p.wait_for_selector("#eps .ep", state="attached")
    assert [p.inner_text(i) for i in ("#tFlux", "#tEpisodes", "#tLocal", "#tFile")] == ["2", "5", "3", "1"]
    assert p.inner_text("#etat") == "PRÊT"
    assert p.locator("#feeds .feed").count() == 2 and p.locator("#eps .ep").count() == 4
    assert "Épisode un" in p.inner_text("#eps") and p.locator("#eps audio").count() == 1
    assert p.get_attribute("#eps audio", "src") == "/api/v1/podcaster/media/10"
    assert "/api/v1/podcaster/share/feed.xml" in p.inner_text("#partage")
    assert p.get_attribute("a.portail", "href") == "/podcaster/portal/"
    assert err == [] and p.natifs == []
    ctx.close()


def test_erreur_par_flux_et_date_de_verification(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/podcaster/", API)
    p.wait_for_selector("#feeds .feed", state="attached")
    flux = p.locator("#feeds .feed")
    assert "Cookies refusés par le site" in flux.nth(1).inner_text()
    assert "Cookies refusés" not in flux.nth(0).inner_text()
    assert "Vérifié —" in flux.nth(1).inner_text()                  # last_refresh = 0 -> « — »
    assert "Vérifié —" not in flux.nth(0).inner_text() and "Vérifié" in flux.nth(0).inner_text()
    ctx.close()


def test_selection_d_un_flux_filtre_les_episodes(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/podcaster/", API)
    p.wait_for_selector("#feeds .feed", state="attached")
    p.locator("#feeds .feed .titre").nth(1).click()
    p.wait_for_function("document.querySelector('#titre').textContent.includes('Épisodes')")
    assert any(a[0] == "GET" and a[1] == "/episodes?feed_id=2" for a in appels)
    ctx.close()


def test_copier_l_adresse_et_reimporter(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/podcaster/", API)
    p.wait_for_selector("#feeds .feed", state="attached")
    flux = p.locator("#feeds .feed")
    assert flux.nth(0).locator(".act-copy").count() == 1
    assert flux.nth(1).locator(".act-copy").count() == 1           # site vide -> url http(s)
    flux.nth(0).locator(".act-copy").click()
    flux.nth(1).locator(".act-copy").click()
    assert p.evaluate("window.__copie") == ["https://example.org/", "https://www.youtube.com/@test"]
    flux.nth(1).locator(".act-ref").click()
    p.wait_for_function("document.querySelector('#toast').textContent.includes('Réimport')")
    assert ("POST", "/feeds/2/refresh", None) in [a[:3] for a in appels]
    assert p.natifs == []
    ctx.close()


def test_copier_sans_presse_papier_replie_sur_un_toast(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/podcaster/", API)
    p.wait_for_selector("#feeds .feed", state="attached")
    p.evaluate("Object.defineProperty(navigator, 'clipboard', {value: undefined, configurable: true})")
    p.locator("#feeds .feed").nth(0).locator(".act-copy").click()
    p.wait_for_function("document.querySelector('#toast').textContent.includes('impossible')")
    assert p.natifs == []
    ctx.close()


def test_ajout_d_un_flux_meme_corps_et_en_tetes(navigateur):
    routes = {**API, "POST /feeds": (200, {"ok": True, "title": "Nouveau", "episodes": 7, "queued": 2})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/podcaster/", routes)
    p.wait_for_selector("#feeds .feed", state="attached")
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.fill("#feedUrl", "https://example.org/nouveau.xml")
    p.uncheck("#autodl")
    p.click("#btnAdd")
    p.wait_for_function("document.querySelector('#toast').textContent.includes('Nouveau')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/feeds"][0]
    assert json.loads(post[2]) == {"url": "https://example.org/nouveau.xml", "auto_dl": False}
    assert post[3] == "Bearer jeton-test"
    ctx.close()


def test_ajout_youtube_annonce_l_import(navigateur):
    routes = {**API, "POST /feeds": (200, {"ok": True, "imported": True})}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/podcaster/", routes)
    p.wait_for_selector("#feeds .feed", state="attached")
    p.fill("#feedUrl", "https://www.youtube.com/@x"); p.press("#feedUrl", "Enter")
    p.wait_for_function("document.querySelector('#toast').textContent.includes('YouTube')")
    ctx.close()


def test_auto_telechargement_par_flux(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/podcaster/", API)
    p.wait_for_selector("#feeds .feed", state="attached")
    p.locator("#feeds .feed").nth(1).locator(".act-ad").click()
    p.wait_for_function("document.querySelector('#toast').textContent.includes('auto-téléchargement')")
    assert ("POST", "/feeds/2/autodl?on=true", None) in [a[:3] for a in appels]
    p.locator("#feeds .feed").nth(0).locator(".act-ad").click()
    p.wait_for_timeout(200)
    assert ("POST", "/feeds/1/autodl?on=false", None) in [a[:3] for a in appels]
    ctx.close()


def test_suppression_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/podcaster/", {**API, "DELETE /feeds/1": (200, {"ok": True})})
    p.wait_for_selector("#feeds .feed", state="attached")
    p.locator("#feeds .feed").nth(0).locator(".act-del").click()
    assert not [a for a in appels if a[0] == "DELETE"]          # pas encore : il faut confirmer
    assert p.natifs == []
    p.locator("#feeds .feed").nth(0).locator(".act-ok").click()
    p.wait_for_function("document.querySelector('#toast').textContent.includes('supprimé')")
    assert ("DELETE", "/feeds/1", None) in [a[:3] for a in appels]
    assert p.natifs == []
    ctx.close()


def test_annuler_ne_supprime_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/podcaster/", API)
    p.wait_for_selector("#feeds .feed", state="attached")
    p.locator("#feeds .feed").nth(0).locator(".act-del").click()
    p.locator("#feeds .feed").nth(0).locator(".act-no").click()
    assert not [a for a in appels if a[0] == "DELETE"] and p.locator(".act-ok").count() == 0
    ctx.close()


def test_telechargement_d_un_episode(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/podcaster/", API)
    p.wait_for_selector("#eps .ep", state="attached")
    p.locator("#eps .ep").nth(1).locator(".act-dl").click()
    p.wait_for_function("document.querySelector('#toast').textContent.includes('file')")
    assert ("POST", "/episodes/11/download", None) in [a[:3] for a in appels]
    ctx.close()


def test_import_opml_meme_corps(navigateur):
    routes = {**API, "POST /feeds/import-opml": (200, {"added": 2, "total": 3})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/podcaster/", routes)
    p.wait_for_selector("#feeds .feed", state="attached")
    p.set_input_files("#opml", files=[{"name": "a.opml", "mimeType": "text/xml", "buffer": b"<opml/>"}])
    p.wait_for_function("document.querySelector('#toast').textContent.includes('2/3')")
    post = [a for a in appels if a[1] == "/feeds/import-opml"][0]
    assert json.loads(post[2]) == {"opml": "<opml/>"}
    ctx.close()


def test_audiobook_titre_dans_la_page_sans_prompt(navigateur):
    routes = {**API, "POST /audiobook/upload": (200, {"title": "Mon livre", "tracks": 4})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/podcaster/", routes)
    p.wait_for_selector("#feeds .feed", state="attached")
    p.set_input_files("#abzip", files=[{"name": "livre.zip", "mimeType": "application/zip", "buffer": b"PK\x03\x04"}])
    p.wait_for_selector("#zipPanel:not([hidden])")
    assert p.input_value("#zipTitre") == "livre"
    assert not [a for a in appels if a[0] == "POST"]
    p.fill("#zipTitre", "Mon livre"); p.click("#btnZipOk")
    p.wait_for_function("document.querySelector('#toast').textContent.includes('4')")
    assert ("POST", "/audiobook/upload?title=Mon%20livre") in [a[:2] for a in appels]
    assert p.natifs == []
    ctx.close()


def test_configuration_lecture_et_ecriture(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/podcaster/", API)
    p.wait_for_selector("#feeds .feed", state="attached")
    p.click("#cfgBtn")
    p.wait_for_function("document.querySelector('#c_media').value !== ''")
    assert p.input_value("#c_par") == "2" and p.input_value("#c_title") == "Mon flux"
    p.fill("#c_par", "3"); p.click("#btnSaveCfg")
    p.wait_for_function("document.querySelector('#rCfg').textContent.includes('Enregistré')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/config"][0]
    assert json.loads(post[2]) == {"media_path": "/data/podcaster", "max_parallel": 3, "refresh_minutes": 60, "public_base": "", "share_title": "Mon flux"}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/podcaster/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "Aucune mesure : session requise." in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tFlux", "#tEpisodes", "#tLocal", "#tFile")] == ["—"] * 4
    assert err == [] and p.natifs == [] and "login" not in p.url
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/podcaster/?demo=1", {})
    p.wait_for_selector("#feeds .feed", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.inner_text("#tFlux") != "—" and p.locator("#eps .ep").count() >= 3
    p.fill("#feedUrl", "https://example.org/x.xml"); p.click("#btnAdd")
    p.wait_for_function("document.querySelector('#toast').textContent.includes('inerte')")
    p.locator("#feeds .feed").nth(0).locator(".act-del").click(); p.locator(".act-ok").first.click()
    p.locator("#feeds .feed").nth(0).locator(".act-ad").click()
    p.locator("#feeds .feed").nth(0).locator(".act-ref").click()
    p.locator("#eps .act-dl").first.click()
    p.click("#cfgBtn"); p.click("#btnSaveCfg")
    p.set_input_files("#opml", files=[{"name": "a.opml", "mimeType": "text/xml", "buffer": b"<opml/>"}])
    p.wait_for_timeout(300)
    assert appels == [] and err == [] and p.natifs == []
    assert "sidebar.js" not in " ".join(p.partages)             # pas de menu commun en démonstration
    ctx.close()


def test_embed_sans_menu_une_colonne_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/podcaster/?embed=1", API, taille={"width": 1300, "height": 800})
    p.wait_for_selector("#feeds .feed", state="attached")
    assert not p.is_visible("#sidebar") and "sidebar.js" not in " ".join(p.partages)
    a = p.locator("#colFlux").bounding_box(); b = p.locator("#colEps").bounding_box()
    assert b["y"] >= a["y"] + a["height"] - 1                   # empilées, pas côte à côte
    ctx.close()
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/podcaster/", API)
    p.wait_for_selector("#feeds .feed", state="attached")
    assert "shared/sidebar.js" in p.partages and err == []       # hors embed et hors démo : menu commun
    ctx.close()


def test_hauteur_postee_a_l_hote(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/podcaster/", API)
    p.evaluate("window.__h = []; addEventListener('message', e => window.__h.push(e.data))")
    p.wait_for_selector("#feeds .feed", state="attached")
    p.click("#rafraichir")
    p.wait_for_timeout(300)
    assert p.evaluate("window.__h.some(m => m && m.onglet === 'podcaster' && m.sbxVue > 100)")
    ctx.close()


@pytest.mark.parametrize("url", ["http://sbx.test/podcaster/?embed=1", "http://sbx.test/podcaster/", "http://sbx.test/podcaster/?demo=1"])
def test_telephone_sans_debordement(navigateur, url):
    ctx, p, err, _ = ouvre(navigateur, url, API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#feeds .feed", state="attached")
    p.wait_for_selector("#eps .ep", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert err == []
    ctx.close()
