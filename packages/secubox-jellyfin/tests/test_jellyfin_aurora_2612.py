# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2612 — /jellyfin/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "jellyfin" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "hybrid-dark" not in SRC and "hybrid-skin" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'jellyfin'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("'/control'", "{ action }", "'/partner/wire'", "{ name: nom }", "{ all: true }", "'/partner/unwire'", "'/library/scan'"):
        assert r in SRC
    # lectures réelles de l'API
    for r in ("'/status'", "'/partners'", "'/library/status'", "'/check-upgrade'"):
        assert r in SRC
    assert SRC.count("method: 'POST'") == 1 and "'PUT'" not in SRC and "'DELETE'" not in SRC
    assert "10.100.0.170" not in SRC  # adresse LAN figée de l'ancienne page


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"status": "ok", "lxc_state": "running", "jellyfin_reachable": True, "port": 8096, "version": "10.10.7", "libraries": 2,
          "sessions": 1, "startup_wizard_completed": True, "setup_required": False}
PARTNERS = {"partners": [
    {"name": "photos", "present": True, "media_path": "/srv/photos", "kind": "photos", "wired": True},
    {"name": "torrent", "present": True, "media_path": "/srv/torrents", "kind": "torrents", "wired": False},
    {"name": "files", "present": False, "media_path": None, "kind": "files", "wired": False},
    {"name": "peertube", "present": True, "media_path": None, "kind": "link", "wired": False}]}
LIBS = {"libraries": [{"name": "photos", "path": "/media/photos", "kind": "photos"}, {"name": "music", "path": "/media/music", "kind": "music"}]}
UPG = {"current": "10.10.7", "latest": "10.10.8", "available": True, "major_jump": False}
API = {"/status": (200, STATUS), "/partners": (200, PARTNERS), "/library/status": (200, LIBS), "/check-upgrade": (200, UPG)}


def ouvre(navigateur, url, routes, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels, entetes = [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    if jeton:
        p.add_init_script("localStorage.setItem('sbx_token', %s)" % json.dumps(jeton))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "jellyfin":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/jellyfin", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        entetes.append(r.request.headers.get("authorization"))
        statut, corps = routes.get(chemin, (200, {"ok": True}) if r.request.method != "GET" else (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/jellyfin/**", api)
    p.goto(url)
    p.entetes = entetes
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/jellyfin/", API, jeton="tok")
    p.wait_for_selector("#bPart tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tLxc", "#tJoi", "#tLib", "#tSes", "#tVer")] == ["running", "oui", "2", "1", "10.10.7"]
    assert p.inner_text("#etat") == "EN LIGNE" and "DISPONIBLE 10.10.8" in p.inner_text("#kUpg")
    assert "Bearer tok" in p.entetes
    p.click("#o-partenaires")
    t = p.inner_text("#bPart")
    assert "BRANCHÉ" in t and "PRÉSENT" in t and "ABSENT" in t and "lien seul" in t
    assert p.locator("#bPart tr").nth(2).get_by_role("button", name="Brancher").is_disabled()
    p.click("#o-bibliotheques")
    assert "/media/music" in p.inner_text("#bLib") and "2 bibliothèques" in p.inner_text("#nLib")
    assert err == []
    ctx.close()


def test_pas_d_en_tete_sans_jeton(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/jellyfin/", API)
    p.wait_for_selector("#bPart tr td.mono", state="attached")
    assert set(p.entetes) == {None}
    ctx.close()


def test_controle_demande_confirmation_puis_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/jellyfin/", {**API, "/control": (200, {"ok": True, "state": "inactive"})})
    p.wait_for_selector("#bPart tr", state="attached")
    p.click("[data-ctl=stop]")
    assert p.is_visible("#conf") and "Arrêter" in p.inner_text("#confQ")
    assert not [a for a in appels if a[0] == "POST"]
    p.click("#confNon")
    assert not p.is_visible("#conf") and not [a for a in appels if a[0] == "POST"]
    p.click("[data-ctl=stop]"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rCtl').textContent.includes('exécutée')")
    assert [json.loads(a[2]) for a in appels if a[1] == "/control"] == [{"action": "stop"}]
    ctx.close()


def test_controle_refuse_n_est_pas_annonce_comme_reussi(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/jellyfin/", {**API, "/control": (200, {"ok": False, "state": "failed"})})
    p.wait_for_selector("#bPart tr", state="attached")
    p.click("[data-ctl=start]"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rCtl').textContent.includes('refusée')")
    assert "ko" in p.get_attribute("#rCtl", "class")
    ctx.close()


def test_brancher_debrancher_tout_brancher_et_scanner(navigateur):
    routes = {**API, "/partner/wire": (200, {"ok": True, "wired": ["torrent"], "skipped": []}), "/partner/unwire": (200, {"ok": True}),
              "/library/scan": (200, {"ok": True})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/jellyfin/", routes)
    p.click("#o-partenaires"); p.wait_for_selector("#bPart tr td.act")
    p.locator("#bPart tr").nth(1).get_by_role("button", name="Brancher").click()
    assert not [a for a in appels if a[0] == "POST"] and "torrent" in p.inner_text("#confQ")
    p.click("#confOui")
    p.wait_for_function("document.getElementById('rPart').textContent.includes('branché : torrent')")
    p.locator("#bPart tr").first.get_by_role("button", name="Débrancher").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('rPart').textContent.includes('débranché')")
    p.click("#toutBrancher"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rPart').textContent.includes('Tout brancher')")
    p.click("#o-bibliotheques"); p.click("#scanner"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rLib').textContent.includes('Scan démarré')")
    posts = [(a[1], json.loads(a[2])) for a in appels if a[0] == "POST"]
    assert posts == [("/partner/wire", {"name": "torrent"}), ("/partner/unwire", {"name": "photos"}),
                     ("/partner/wire", {"all": True}), ("/library/scan", {})]
    ctx.close()


def test_branchement_ignore_et_scan_non_lance_sont_signales(navigateur):
    routes = {**API, "/partner/wire": (200, {"ok": True, "wired": [], "skipped": ["torrent"]}), "/library/scan": (200, {"ok": False})}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/jellyfin/", routes)
    p.click("#o-partenaires"); p.wait_for_selector("#bPart tr td.act")
    p.locator("#bPart tr").nth(1).get_by_role("button", name="Brancher").click(); p.click("#confOui")
    p.wait_for_function("document.getElementById('rPart').textContent.includes('rien de branché')")
    assert "ko" in p.get_attribute("#rPart", "class")
    p.click("#o-bibliotheques"); p.click("#scanner"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rLib').textContent.includes('non lancé')")
    ctx.close()


def test_donnees_d_api_jamais_interpretees_comme_html(navigateur):
    mal = {"partners": [{"name": "x<img src=x onerror=window.pwn=1>", "present": True, "media_path": "<b>y</b>", "kind": "files", "wired": False}]}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/jellyfin/", {**API, "/partners": (200, mal)})
    p.click("#o-partenaires"); p.wait_for_selector("#bPart tr td.mono", state="attached")
    assert p.locator("#bPart img, #bPart b").count() == 0 and p.evaluate("window.pwn") is None and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/jellyfin/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tLxc", "#tJoi", "#tLib", "#tSes", "#tVer")] == ["—"] * 5 and err == []
    ctx.close()


def test_assistant_a_terminer_est_signale(navigateur):
    st = {**STATUS, "startup_wizard_completed": False, "setup_required": True}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/jellyfin/", {**API, "/status": (200, st)})
    p.wait_for_selector("#setup:not([hidden])")
    assert p.inner_text("#etat") == "CONFIGURATION REQUISE"
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/jellyfin/?demo=1", {})
    p.wait_for_selector("#bPart tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo") and p.inner_text("#tVer") == "10.10.7"
    p.click("[data-ctl=restart]"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rCtl').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/jellyfin/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bPart tr td.mono", state="attached")
    for t in ("partenaires", "bibliotheques", "externe", "reglages"):
        p.click("#o-" + t)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), t
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
