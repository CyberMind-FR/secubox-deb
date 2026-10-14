# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2612 — /lyrion/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "lyrion" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "fonts.googleapis" not in SRC and "hybrid-dark" not in SRC and "crt-light" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onchange="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'lyrion'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("'/rescan'", "'/medialib/mount'", "'/medialib/unmount'", "{ path }", "action/' + verbe", "'power'", "'volume'", "'sync'",
              "{ on: ck.checked }", "{ level: Number(cur.value) }", "{ target: t }", "'action/unsync'", "method: 'POST'"):
        assert r in SRC
    assert SRC.count("method: 'POST'") == 1  # un seul point d'écriture
    for lecture in ("'/status'", "'/components'", "'/access'", "'/now-playing'", "'/players'", "'/medialib'"):
        assert lecture in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"module": "lyrion", "version": "1.7.0", "overall": "yellow"}
COMP = {"components": [{"name": "lxc", "state": "running", "detail": "lyrion @ 192.0.2.5"},
                       {"name": "daemon", "state": "stopped", "detail": "lyrion, port 9000"},
                       {"name": "host-api", "state": "running", "detail": "uvicorn"}]}
ACCESS = {"access": [{"url": "http://192.0.2.5:9000/", "auth": "lan-only", "scope": "lan"},
                     {"url": "javascript:alert(1)", "auth": "x", "scope": "public"}]}
NOW = {"title": "Titre <b>test</b>", "artist": "Artiste", "album": "Album", "player": "Salon", "mode": "play"}
PLAYERS = {"players": [{"id": "00:00:5e:00:53:01", "name": "Salon", "model": "Squeezelite", "ip": "192.0.2.21", "power": True},
                       {"id": "00:00:5e:00:53:02", "name": "Cuisine", "model": "Touch", "ip": "192.0.2.22", "power": False}], "count": 2}
MEDIA = {"external": None, "mounted": False, "devices": [{"device": "/dev/sdb1", "label": "CLE", "size": "8G", "fstype": "vfat", "removable": True, "mounted": False}],
         "candidates": [{"path": "/media/disque", "label": "disque", "audio_files": 1284}]}
VERSION = {"version": "1.7.0", "build": "x"}
API = {"/status": (200, STATUS), "/components": (200, COMP), "/access": (200, ACCESS), "/now-playing": (200, NOW),
       "/players": (200, PLAYERS), "/medialib": (200, MEDIA), "/version": (200, VERSION)}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    if jeton:
        ctx.add_init_script("try{localStorage.setItem('sbx_token','%s')}catch(e){}" % jeton)
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "lyrion":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/lyrion", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (200, {"ok": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/lyrion/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def ecritures(appels):
    return [a for a in appels if a[0] == "POST"]


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/lyrion/", API)
    p.wait_for_selector("#bComp tr td.mono", state="attached")
    assert p.inner_text("#tSante") == "Dégradé" and p.inner_text("#etat") == "DÉGRADÉ"
    assert p.inner_text("#tLxc") == "EN MARCHE" and p.inner_text("#tJoueurs") == "2"
    assert p.inner_text("#tLecture") == "Titre <b>test</b>"   # texte brut, jamais interprété
    assert p.locator("#kTitre b").count() == 0
    assert "ARRÊTÉ" in p.inner_text("#bComp") and p.inner_text("#tMedia") == "Aucune" and p.inner_text("#tVersion") == "1.7.0"
    assert "Salon" in p.inner_text("#listeJoueurs") and "Cuisine" in p.inner_text("#listeJoueurs")
    assert "1284" in p.inner_text("#bCand") and "/dev/sdb1" in p.inner_text("#bDev")
    # le lien « public » en javascript: est refusé, le lien LAN est repris
    assert p.get_attribute("#ouvrir", "href") == "http://192.0.2.5:9000/" and p.locator("#bAcces a").count() == 1
    assert err == []
    ctx.close()


def test_commandes_lecteur_meme_route_meme_corps_et_jeton(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/lyrion/", API, jeton="jt-test")
    p.wait_for_selector(".joueur")
    p.locator(".joueur").first.get_by_title("Pause").click()
    p.wait_for_function("true")
    p.locator(".joueur").first.locator("input[type=checkbox]").uncheck()
    p.locator(".joueur").first.locator("input[type=range]").fill("30")
    p.locator(".joueur").first.locator("select").select_option(label="Cuisine")
    p.wait_for_function("document.querySelector('.joueur')")
    esc = {(a[1], a[2]) for a in ecritures(appels)}
    base = "/player/00%3A00%3A5e%3A00%3A53%3A01/"
    assert (base + "action/pause", "{}") in esc
    assert (base + "power", '{"on":false}') in esc
    assert (base + "volume", '{"level":30}') in esc
    assert (base + "sync", '{"target":"00:00:5e:00:53:02"}') in esc
    assert all(a[3] == "Bearer jt-test" for a in ecritures(appels))
    assert err == []
    ctx.close()


def test_reindexation_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/lyrion/", API)
    p.wait_for_selector("#bCand tr td.act")
    p.click("#rescan")
    assert p.is_visible("#cAct") and not ecritures(appels)         # rien ne part avant confirmation
    p.click("#cAct >> text=Annuler")
    assert not p.is_visible("#cAct") and not ecritures(appels)
    p.click("#rescan"); p.click("#cAct >> text=Confirmer")
    p.wait_for_function("document.getElementById('rAct').textContent.includes('demandée')")
    assert ("POST", "/rescan", "{}") in [a[:3] for a in appels]
    ctx.close()


def test_montage_et_demontage_confirmes_avec_le_bon_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/lyrion/", API, jeton="jt")
    p.wait_for_selector("#bCand tr td.act button")
    p.get_by_text("Monter", exact=True).click()
    assert "lecture seule" in p.inner_text("#cMedia") and not ecritures(appels)
    p.click("#cMedia >> text=Confirmer")
    p.wait_for_function("document.getElementById('rMedia').textContent.includes('montée')")
    mont = [a for a in ecritures(appels) if a[1] == "/medialib/mount"][0]
    assert json.loads(mont[2]) == {"path": "/media/disque"} and mont[3] == "Bearer jt"
    ctx.close()
    # médiathèque déjà montée : démontage confirmé, corps vide
    montee = {**API, "/medialib": (200, {**MEDIA, "external": "/media/disque", "mounted": True})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/lyrion/", montee)
    p.wait_for_selector("#aDemonter:not([hidden])")
    assert p.inner_text("#tMedia") == "Montée"
    p.click("#demonter"); p.click("#cMedia >> text=Confirmer")
    p.wait_for_function("document.getElementById('rMedia').textContent.includes('démontée')")
    assert ("POST", "/medialib/unmount", "{}") in [a[:3] for a in appels]
    ctx.close()


def test_echec_de_montage_affiche_l_erreur_de_l_api(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/lyrion/", {**API, "/medialib/mount": (200, {"ok": False, "error": "path not found: /media/disque"})})
    p.wait_for_selector("#bCand tr td.act button")
    p.get_by_text("Monter", exact=True).click(); p.click("#cMedia >> text=Confirmer")
    p.wait_for_function("document.getElementById('rMedia').textContent.includes('path not found')")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/lyrion/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tSante", "#tLxc", "#tJoueurs", "#tLecture", "#tMedia")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/lyrion/?demo=1", {})
    p.wait_for_selector(".joueur")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator(".joueur").first.get_by_title("Lecture").click()
    p.wait_for_function("document.getElementById('rJoueurs').textContent.includes('inerte')")
    p.click("#rescan"); p.click("#cAct >> text=Confirmer")
    p.wait_for_function("document.getElementById('rAct').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/lyrion/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector(".joueur")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
