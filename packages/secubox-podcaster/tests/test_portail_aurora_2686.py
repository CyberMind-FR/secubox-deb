# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2686 — portail d'écoute /podcaster/portal/ au profil Aurora : page statique + vrai navigateur, API simulée.

Page d'usager, lecture seule : aucune écriture, mêmes routes de lecture qu'avant, contrats du Hall (mégabarre, bus média) conservés.
"""
import json
import re
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
PAGE = PKG / "www" / "podcaster" / "portal" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
MICRO = PKG / "www" / "podcaster" / "portal" / "micro.html"


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r"<script[^>]*\ssrc=", SRC) == []          # le menu commun est injecté à l'exécution, rien d'externe en dur
    assert "hybrid-dark" not in SRC and "JetBrains" not in SRC and "--cosmos-black" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "onclick=", "http://", "https://fonts"):
        assert interdit not in SRC, interdit
    assert "lorem" not in SRC.lower()
    assert "--fond:#060d1b" in SRC and "container-type:inline-size" in SRC
    assert "sbxVue" in SRC and "onglet: 'podcaster-portail'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_lecture_seule_memes_routes_de_lecture():
    """Page d'usager (require_session / require_lecture) : que des GET, les mêmes routes qu'avant, aucune écriture."""
    assert "var API = '/api/v1/podcaster';" in SRC
    for r in ("API + '/public/library'", "API + '/share/feed.xml'", "API + '/media/'", "'/public/feed/'", "/zip'"):
        assert r in SRC, r
    for ecriture in ("method:", "POST", "PUT", "DELETE", "PATCH", "FormData", "XMLHttpRequest", "sendBeacon", "/feeds", "/config", "/import", "/audiobook"):
        assert ecriture not in SRC, ecriture
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer ' + t" in SRC
    assert "credentials: 'same-origin'" in SRC


def test_contrats_du_hall_conserves():
    for m in ("sbx: 'contexte'", "id: 'podcaster'", "titre: 'Officines'", "sbx !== 'contexte-choix'", "cle: '__all'", "'feed:' + f",
              "sbx: 'media'", "sbx !== 'cmd'", "'toggle'", "'pause'", "'stop'", "'vol'", "'muet'", "sbx.podcaster.etat", "classList.add('sbx-embed')"):
        assert m in SRC, m


def test_vue_micro_non_touchee():
    assert "Podcaster — vue micro" in MICRO.read_text(encoding="utf-8")


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
LIB = {"title": "Radio du coin", "feeds": {"Atelier": 2, "Chronique": 1},
       "episodes": [{"id": 11, "title": "Un", "feed": "Atelier", "feed_id": 1, "pubdate": NOW - 86400, "duration": "10:00", "bytes": 1048576},
                    {"id": 12, "title": "Deux", "feed": "Atelier", "feed_id": 1, "pubdate": NOW - 172800, "duration": None, "bytes": None},
                    {"id": 13, "title": "Trois", "feed": "Chronique", "feed_id": 2, "pubdate": NOW - 3600, "duration": "5:00", "bytes": 2097152}]}
API = {"/public/library": (200, LIB)}


def ouvre(navigateur, url, routes, taille=None, init=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    if init:
        p.add_init_script(init)
    erreurs, appels, natifs, partages = [], [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
    p.natifs, p.partages = natifs, partages

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            partages.append(chemin)
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") in ("podcaster/portal", ""):
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/podcaster", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.headers.get("authorization")))
        if chemin.startswith("/media/"):
            r.fulfill(status=200, content_type="audio/mpeg", body=b"")
            return
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/podcaster/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def attend(p):
    p.wait_for_selector("#list .ep", state="attached")


def test_tuiles_et_episodes_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/", API)
    attend(p)
    assert [p.inner_text(i) for i in ("#tEp", "#tFlux", "#tVolume")] == ["3", "2", "3,0 Mo"]
    assert "partiel : 2 sur 3" in p.inner_text("#sVolume") and p.inner_text("#tDernier") != "—"
    assert p.inner_text("#title") == "Radio du coin" and p.inner_text("#etat") == "EN LIGNE"
    assert p.locator(".ep").count() == 3 and "Atelier" in p.inner_text("#list")
    assert p.get_attribute(".ep audio >> nth=0", "src") == "/api/v1/podcaster/media/11"
    assert p.get_attribute(".ep a.btn >> nth=0", "href") == "/api/v1/podcaster/media/11" and p.get_attribute(".ep a.btn >> nth=0", "download") is not None
    assert p.get_attribute("#rss", "href") == "/api/v1/podcaster/share/feed.xml"
    assert all(p.locator(".tuile").nth(i).get_attribute("title") for i in range(4))
    assert {m for m, *_ in appels} == {"GET"} and err == [] and p.natifs == []
    ctx.close()


def test_filtre_par_flux_et_zip(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/", API)
    attend(p)
    assert p.locator("#zipbar a").count() == 0
    p.get_by_role("button", name="Chronique").click()
    assert p.locator(".ep").count() == 1 and "Trois" in p.inner_text("#list")
    assert p.get_attribute("#zipbar a", "href") == "/api/v1/podcaster/public/feed/2/zip"
    p.get_by_role("button", name="Tous").click()
    assert p.locator(".ep").count() == 3 and p.locator("#zipbar a").count() == 0
    assert err == []
    ctx.close()


def test_jeton_envoye_en_bearer_et_copie_de_l_adresse(navigateur):
    init = ("localStorage.setItem('sbx_token','abc123');"
            "window.__cp=null; Object.defineProperty(navigator,'clipboard',{value:{writeText:t=>{window.__cp=t;return Promise.resolve()}}});")
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/", API, init=init)
    attend(p)
    assert appels[0][2] == "Bearer abc123"
    p.click("#copy")
    p.wait_for_function("document.getElementById('copy').textContent.includes('Copié')")
    assert p.evaluate("window.__cp") == "http://sbx.test/api/v1/podcaster/share/feed.xml"
    assert err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/", {"/public/library": (401, {"detail": "session requise"})})
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tEp", "#tFlux", "#tDernier", "#tVolume")] == ["—"] * 4 and err == []
    ctx.close()


def test_portail_indisponible(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/", {"/public/library": (502, {})})
    p.wait_for_selector("#erreur:not([hidden])")
    assert p.inner_text("#etat") == "INDISPONIBLE" and "indisponible" in p.inner_text("#erreur") and err == []
    ctx.close()


def test_aucun_episode_dit_aucun_episode(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/", {"/public/library": (200, {"title": "X", "feeds": {}, "episodes": []})})
    p.wait_for_selector("#list .vide")
    assert "Aucun épisode" in p.inner_text("#list") and p.inner_text("#tEp") == "0" and p.inner_text("#tDernier") == "—"
    ctx.close()


def test_demonstration_annoncee_sans_aucun_appel(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/podcaster/portal/?demo=1", {})
    attend(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.inner_text("#tEp") == "4" and p.get_attribute(".ep audio >> nth=0", "src") is None
    p.locator(".ep a.btn").first.click()
    p.wait_for_function("document.getElementById('rActions').textContent.includes('Démonstration')")
    p.get_by_role("button", name=re.compile("Atelier")).click()
    p.locator("#zipbar a").first.click()      # le ZIP ; le flux RSS du podcast (#2998) le suit
    assert appels == [] and err == [] and p.natifs == []
    assert "sidebar.js" not in " ".join(p.partages)
    ctx.close()


def test_menu_commun_seulement_sous_le_hub(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/podcaster/portal/", API)
    attend(p)
    p.wait_for_function("document.body.classList.contains('menu')")
    assert "shared/sidebar.js" in p.partages and err == []
    ctx.close()
    # vhost public : racine du dossier, /shared/ n'existe pas
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/", API)
    attend(p)
    assert p.partages == [] and not p.evaluate("document.body.classList.contains('menu')") and err == []
    ctx.close()
    # ni embarqué, ni en démonstration
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/podcaster/portal/?embed=1", API)
    attend(p)
    assert p.partages == []
    ctx.close()


def test_embarque_masque_l_en_tete_et_pousse_la_megabarre(navigateur):
    init = "window.__m = []; addEventListener('message', e => window.__m.push(e.data));"
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/?embed=1", API, taille={"width": 420, "height": 800}, init=init)
    attend(p)
    assert not p.is_visible(".tete") and not p.is_visible("#filtresPan")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    p.wait_for_function("window.__m.some(m => m && m.sbxVue)")
    m = p.evaluate("window.__m.filter(m => m && m.sbxVue).pop()")
    assert m["onglet"] == "podcaster-portail" and m["sbxVue"] > 100
    # la mégabarre est poussée vers le parent ; ici la page est son propre parent (hors cadre) : on rejoue le message reçu
    p.evaluate("postMessage({sbx:'contexte-choix', cle:'feed:Chronique'}, '*')")
    p.wait_for_function("document.querySelectorAll('#list .ep').length === 1")
    assert err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/", API, taille={"width": 420, "height": 800})
    attend(p)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1") and err == []
    ctx.close()
