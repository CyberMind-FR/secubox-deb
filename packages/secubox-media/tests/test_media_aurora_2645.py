# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2645 — /media/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "media" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-" not in SRC and "googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'media'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_a_l_identique():
    for r in ("'/detect'", "'/roots'", "'/jobs'", "'/browse?path='", "'/mount'", "'/unmount'", "'/automount'",
              "'/compare'", "'/' + verb", "transfer('copy')", "transfer('sync')"):
        assert r in SRC
    assert SRC.count("headers: hdrs()") >= 5          # chaque POST porte le jeton
    assert "method: 'POST'" in SRC and "'DELETE'" not in SRC
    assert "JSON.stringify({ path: dev, rw })" in SRC
    assert "JSON.stringify({ path: dev, on, rw })" in SRC
    assert "JSON.stringify({ src: st.srcPath + '/' + n, dst: st.dstPath })" in SRC
    assert "JSON.stringify({ src: st.srcPath, dst: st.dstPath })" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "try {" in SRC
    assert "devAction" in SRC and "d.mountable === false" in SRC
    assert "login.html?redirect=" in SRC


def test_aucun_secret_ni_stockage():
    assert "setItem" not in SRC and "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


DETECT = {"alerts": [{"port": "1-1.3", "disconnects": 5}], "devices": [
    {"device": "/dev/sda1", "label": "CLE", "size": "14G", "fstype": "vfat", "transport": "usb", "removable": True,
     "mounted": True, "mountpoint": "/media/CLE", "mountable": True, "uuid": "U1", "automount": False},
    {"device": "/dev/sdb1", "label": "DISQUE", "size": "1T", "fstype": "ext4", "transport": "usb", "removable": True,
     "mounted": False, "mountable": True, "uuid": "U2"},
    {"device": "/dev/sdc1", "label": "MAC", "size": "500G", "fstype": "hfsplus", "mounted": False, "mountable": False,
     "unsupported_reason": "HFS+ non pris en charge"},
    {"device": "/dev/mmcblk0p1", "label": "sys", "system": True, "mounted": True, "mountpoint": "/"}]}
ROOTS = {"ok": True, "roots": [{"label": "Musique", "path": "/data/musique", "writable": True, "exists": True}]}
LISTES = {"/media/CLE": [{"name": "Dossier", "dir": True}, {"name": "a.flac", "size": 2048}, {"name": "b.flac", "size": 1048576}],
          "/media/CLE/Dossier": [{"name": "c.flac", "size": 10}],
          "/data/musique": []}
JOBS = {"jobs": [{"src": "/media/CLE/a.flac", "dst": "/data/musique", "state": "queued"},
                 {"src": "/media/CLE/b.flac", "dst": "/data/musique", "state": "failed"}]}


def ouvre(navigateur, url, statut_lecture=200, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "media":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        reste = r.request.url.split("/api/v1/media", 1)[1]
        chemin, _, requete = reste.partition("?")
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        if statut_lecture != 200:
            r.fulfill(status=statut_lecture, content_type="application/json", body='{"detail":"jeton requis"}')
            return
        if r.request.method == "POST":
            corps = {"ok": True, "mountpoint": "/media/DISQUE", "differences": 3, "automount": True, "rw": False}
        elif chemin == "/detect":
            corps = DETECT
        elif chemin == "/roots":
            corps = ROOTS
        elif chemin == "/jobs":
            corps = JOBS
        elif chemin == "/browse":
            from urllib.parse import parse_qs
            ch = parse_qs(requete)["path"][0]
            corps = {"ok": True, "path": ch, "truncated": False,
                     "entries": [{"name": e["name"], "dir": e.get("dir", False), "size": e.get("size")} for e in LISTES.get(ch, [])]}
        else:
            corps = {}
        r.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/media/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def prete(p):
    p.wait_for_selector("#src-list .row", state="attached")
    p.wait_for_selector("#jobs .job", state="attached")


def test_tuiles_supports_et_volets_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/media/")
    prete(p)
    assert [p.inner_text(i) for i in ("#tSupports", "#tMontes", "#tAlertes", "#tJobs")] == ["3", "1", "1", "1"]
    assert p.inner_text("#etat") == "PORT INSTABLE"
    assert "déconnecte en boucle" in p.inner_text("#alerts")
    sup = p.inner_text("#devices")
    assert "CLE" in sup and "DISQUE" in sup and "HFS+ non pris en charge" in sup and "sys" not in sup
    # support illisible : motif à la place du bouton
    assert p.locator("[data-mount]").count() == 1 and p.locator("[data-unmount]").count() == 1
    assert "1,0 Mo" in p.inner_text("#src-list") and "2,0 Ko" in p.inner_text("#src-list")
    assert p.locator("#src-sel option").count() == 2
    assert all(p.get_attribute(s, "title") for s in (".tuile >> nth=0", ".tuile >> nth=1", ".tuile >> nth=2", ".tuile >> nth=3"))
    assert err == []
    ctx.close()


def test_jeton_en_bearer(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/media/")
    p.evaluate("localStorage.setItem('sbx_token','abc')")
    p.reload(); prete(p)
    assert any(a[1] == "/detect" and a[3] == "Bearer abc" for a in appels)
    ctx.close()


def test_copier_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/media/")
    prete(p)
    assert p.is_disabled("#act-copy") and p.is_disabled("#act-move") and p.is_disabled("#act-copy-back")
    p.select_option("#dst-sel", "/data/musique")
    p.wait_for_function("document.getElementById('dst-crumb').textContent == '/data/musique'")
    p.locator("#src-list .row", has_text="a.flac").click()
    assert not p.is_disabled("#act-copy")
    p.click("#act-copy")
    p.wait_for_function("document.getElementById('rTransfert').textContent.includes('mis en file')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/copy"][0]
    assert json.loads(post[2]) == {"src": "/media/CLE/a.flac", "dst": "/data/musique"}
    p.locator("#src-list .row", has_text="b.flac").click()
    p.click("#act-sync")
    p.wait_for_function("document.querySelectorAll('.row.on').length === 0")
    assert [a for a in appels if a[1] == "/sync"]
    ctx.close()


def test_comparer_montage_et_automount(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/media/")
    prete(p)
    p.select_option("#dst-sel", "/data/musique")
    p.wait_for_function("document.getElementById('dst-crumb').textContent == '/data/musique'")
    p.locator("#src-list .row", has_text="a.flac").click()
    p.click("#act-compare")
    p.wait_for_function("document.getElementById('rTransfert').textContent.includes('3 écart')")
    assert json.loads([a for a in appels if a[1] == "/compare"][0][2]) == {"src": "/media/CLE", "dst": "/data/musique"}
    p.click("[data-mount-rw]")
    p.wait_for_function("document.getElementById('toast').textContent.includes('écriture')")
    assert json.loads([a for a in appels if a[1] == "/mount"][0][2]) == {"path": "/dev/sdb1", "rw": True}
    p.click("[data-unmount]")
    p.wait_for_function("document.getElementById('toast').textContent.includes('Démonté')")
    assert json.loads([a for a in appels if a[1] == "/unmount"][0][2]) == {"path": "/media/CLE"}
    p.locator("[data-auto]").first.check()
    p.wait_for_function("document.getElementById('toast').textContent.includes('démarrage')")
    assert json.loads([a for a in appels if a[1] == "/automount"][0][2]) == {"path": "/dev/sda1", "on": True, "rw": False}
    ctx.close()


def test_navigation_double_clic_et_remontee(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/media/")
    prete(p)
    assert p.is_disabled("#src-up")
    p.locator("#src-list .row", has_text="Dossier").dblclick()
    p.wait_for_function("document.getElementById('src-crumb').textContent == '/media/CLE/Dossier'")
    assert "c.flac" in p.inner_text("#src-list") and not p.is_disabled("#src-up")
    p.click("#src-up")
    p.wait_for_function("document.getElementById('src-crumb').textContent == '/media/CLE'")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/media/", statut_lecture=401)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tSupports", "#tMontes", "#tAlertes", "#tJobs")] == ["—"] * 4
    assert err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/media/?demo=1")
    prete(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#src-list .row", has_text="morceau-01").click()
    p.select_option("#dst-sel", "/data/musique")
    p.wait_for_function("document.getElementById('dst-crumb').textContent == '/data/musique'")
    p.click("#act-copy")
    p.wait_for_function("document.getElementById('rTransfert').textContent.includes('inerte')")
    p.click("[data-mount]")
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    for url in ("http://sbx.test/media/?embed=1&demo=1", "http://sbx.test/media/?demo=1"):
        ctx, p, err, _ = ouvre(navigateur, url, taille={"width": 420, "height": 800})
        prete(p)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
        assert err == []
        if "embed" in url:
            assert not p.is_visible("#sidebar")
        ctx.close()
