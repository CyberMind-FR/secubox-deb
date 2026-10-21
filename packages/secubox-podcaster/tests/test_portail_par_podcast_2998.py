# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2998 — portail public par podcast : mosaïque des podcasts, chacun avec son flux RSS, ses épisodes et son ZIP.

Page d'usager en lecture seule, mêmes routes de lecture ; le flux global reste en tête de page.
"""
import base64
import json
import re
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
PAGE = PKG / "www" / "podcaster" / "portal" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
LIB = {"title": "Radio du coin", "feeds": {"Atelier": 2, "Chronique": 1},
       "podcasts": [{"id": 1, "title": "Atelier", "description": "Le samedi", "image": "/api/v1/podcaster/feeds/1/cover", "episodes": 2,
                     "last": NOW - 86400, "bytes": 1048576, "rss": "/api/v1/podcaster/share/feed/1.xml", "zip": "/api/v1/podcaster/public/feed/1/zip"},
                    {"id": 2, "title": "Chronique", "description": None, "image": None, "episodes": 1, "last": NOW - 3600, "bytes": 2097152,
                     "rss": "/api/v1/podcaster/share/feed/2.xml", "zip": "/api/v1/podcaster/public/feed/2/zip"}],
       "episodes": [{"id": 11, "title": "Un", "feed": "Atelier", "feed_id": 1, "pubdate": NOW - 86400, "duration": "10:00", "bytes": 1048576},
                    {"id": 12, "title": "Deux", "feed": "Atelier", "feed_id": 1, "pubdate": NOW - 172800, "duration": None, "bytes": None},
                    {"id": 13, "title": "Trois", "feed": "Chronique", "feed_id": 2, "pubdate": NOW - 3600, "duration": "5:00", "bytes": 2097152}]}
SANS_PODCASTS = {k: v for k, v in LIB.items() if k != "podcasts"}      # API d'avant #2998
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")  # 1×1 valide


def ouvre(navigateur, url, lib, taille=None, init=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    if init:
        p.add_init_script(init)
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.rstrip("/") == "":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/podcaster", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin))
        if chemin.startswith("/media/") or chemin.endswith("/cover"):
            r.fulfill(status=200, content_type="audio/mpeg" if "/media/" in chemin else "image/png", body=b"" if "/media/" in chemin else PNG)
            return
        r.fulfill(status=200, content_type="application/json", body=json.dumps(lib))
    p.route("http://sbx.test/api/v1/podcaster/**", api)
    p.goto(url)
    p.wait_for_selector("#list .ep", state="attached")
    return ctx, p, erreurs, appels


def test_mosaique_des_podcasts_chacun_avec_son_flux(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/", LIB)
    assert p.locator("#filters .pod").count() == 2
    at = p.locator("#filters .pod[data-id='1']")
    assert "Atelier" in at.inner_text() and "2" in at.inner_text() and "Le samedi" in at.inner_text()
    assert at.locator("img").get_attribute("src") == "/api/v1/podcaster/feeds/1/cover"
    assert at.locator("a.podrss").get_attribute("href") == "/api/v1/podcaster/share/feed/1.xml"
    ch = p.locator("#filters .pod[data-id='2']")
    assert ch.locator("img").count() == 0 and ch.locator(".initiale").inner_text() == "C"       # sans pochette : initiale
    assert p.get_attribute("#rss", "href") == "/api/v1/podcaster/share/feed.xml"                 # le flux global reste en tête
    assert {m for m, _ in appels} == {"GET"} and err == []
    ctx.close()


def test_choisir_un_podcast_montre_ses_episodes_son_flux_et_son_zip(navigateur):
    init = "window.__cp=null; Object.defineProperty(navigator,'clipboard',{value:{writeText:t=>{window.__cp=t;return Promise.resolve()}}});"
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/", LIB, init=init)
    p.get_by_role("button", name=re.compile("^Chronique")).click()
    assert p.locator(".ep").count() == 1 and "Trois" in p.inner_text("#list")
    assert p.get_attribute("#zipbar a", "href") == "/api/v1/podcaster/public/feed/2/zip"
    assert p.get_attribute("#zipbar a.podflux", "href") == "/api/v1/podcaster/share/feed/2.xml"
    assert "Chronique" in p.inner_text("#nEp")
    assert p.locator("#filters .pod.on").get_attribute("data-id") == "2"
    p.click("#copy")                                                                              # copie l'adresse DU PODCAST choisi
    p.wait_for_function("document.getElementById('copy').textContent.includes('Copié')")
    assert p.evaluate("window.__cp") == "http://sbx.test/api/v1/podcaster/share/feed/2.xml"
    p.get_by_role("button", name="Tous").click()
    assert p.locator(".ep").count() == 3 and p.locator("#zipbar a").count() == 0
    p.click("#copy")
    p.wait_for_function("document.getElementById('copy').textContent.includes('Copié')")
    assert p.evaluate("window.__cp") == "http://sbx.test/api/v1/podcaster/share/feed.xml"
    assert err == []
    ctx.close()


def test_api_sans_liste_podcasts_derive_la_mosaique_des_episodes(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/", SANS_PODCASTS)
    assert p.locator("#filters .pod").count() == 2
    assert p.locator("#filters .pod[data-id='1'] a.podrss").get_attribute("href") == "/api/v1/podcaster/share/feed/1.xml"
    p.get_by_role("button", name=re.compile("^Atelier")).click()
    assert p.locator(".ep").count() == 2 and err == []
    ctx.close()


def test_megabarre_du_hall_choisit_un_podcast(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/?embed=1", LIB, taille={"width": 420, "height": 800})
    assert p.is_visible("#filtresPan") and p.locator("#filters .pod").count() == 2 and not p.is_visible("#chips")
    p.evaluate("postMessage({sbx:'contexte-choix', cle:'feed:Chronique'}, '*')")
    p.wait_for_function("document.querySelectorAll('#list .ep').length === 1")
    assert p.get_attribute("#zipbar a.podflux", "href") == "/api/v1/podcaster/share/feed/2.xml"
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and err == []
    ctx.close()


def test_demonstration_montre_des_podcasts_fictifs_sans_appel(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/?demo=1", {})
    assert p.locator("#filters .pod").count() == 2 and appels == [] and err == []
    assert p.locator("#filters .pod img").count() == 0           # aucune image demandée en démonstration
    ctx.close()


def test_telephone_sans_debordement_avec_la_mosaique(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/", LIB, taille={"width": 390, "height": 800})
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and err == []
    ctx.close()
