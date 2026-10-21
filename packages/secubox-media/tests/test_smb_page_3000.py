# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3000 — panneau « Partages SMB » (/media/smb.html) : page Aurora autonome, tout par /api/v1/media/smb/*, confirmations dans la page."""
import json
import re
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
PAGE = PKG / "www" / "media" / "smb.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif_ni_secret():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script[^>]*\ssrc="([^"]+)"', SRC) == ["/shared/sidebar.js"]      # le menu commun, rien d'autre
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "insertAdjacentHTML", "document.write", "eval(", "onclick=", "http://", "https://fonts"):
        assert interdit not in SRC, interdit
    assert "lorem" not in SRC.lower()
    assert "--fond:#060d1b" in SRC and "container-type:inline-size" in SRC
    assert "sbxVue" in SRC and "onglet: 'media-smb'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert 'type="password"' in SRC and "$('usPw').value = ''" in SRC          # le secret est effacé après envoi


def test_routes_citees():
    assert "var API = '/api/v1/media'" in SRC or "const API = '/api/v1/media'" in SRC
    for r in ("'/smb/status'", "'/smb/users'", "'/smb/users/delete'", "'/smb/shares'", "'/smb/shares/delete'", "'/smb/sync-shares'", "'/smb/reload'"):
        assert r in SRC, r
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer ' + t" in SRC


def test_menu_declare_la_page():
    m = json.loads((PKG / "menu.d" / "151-media-smb.json").read_text(encoding="utf-8"))
    assert m["path"] == "/media/smb.html" and m["id"] == "media-smb"


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"ok": True, "module_loaded": True, "service": "active", "listening": True, "users": 1, "usable": True, "netbios": "SECUBOX",
          "interfaces": "eth2", "min_protocol": "SMB3_00", "roots": ["/data", "/media"],
          "shares": [{"name": "data", "path": "/data", "readonly": False, "exists": True, "comment": "Donnees", "users": [], "auto": False},
                     {"name": "CLE", "path": "/media/secubox-media/CLE", "readonly": True, "exists": True, "comment": "", "users": [], "auto": True}]}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif " + d.type), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin == "media/smb.html":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/media", 1)[1].split("?")[0]
        corps = r.request.post_data
        appels.append((r.request.method, chemin, json.loads(corps) if corps else None))
        statut, rep = routes.get(chemin, (404, {"detail": "inconnue"}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(rep))
    p.route("http://sbx.test/api/v1/media/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


ROUTES = {"/smb/status": (200, STATUS), "/smb/users": (200, {"ok": True, "users": ["admin"]}),
          "/smb/shares": (200, {"ok": True, "share": "Photos", "path": "/data/photos", "created": True}),
          "/smb/shares/delete": (200, {"ok": True}), "/smb/users/delete": (200, {"ok": True}),
          "/smb/sync-shares": (200, {"ok": True, "shares": 1, "changed": True}),
          "/smb/reload": (200, {"ok": True})}


def test_etat_partages_et_comptes_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/media/smb.html", ROUTES)
    p.wait_for_selector("#shares tr")
    assert p.inner_text("#etat") == "EN SERVICE" and p.inner_text("#tUsable") == "Utilisable"
    assert p.inner_text("#tShares") == "2" and "1 manuel(s) · 1 généré(s)" in p.inner_text("#sShares") and p.inner_text("#tUsers") == "1"
    assert p.inner_text("#tNetbios") == "\\\\SECUBOX" and "eth2" in p.inner_text("#sNetbios")
    assert p.locator("#shares tr").count() == 2
    assert p.locator("#shares tr[data-name=data] button").count() == 1 and p.locator("#shares tr[data-name=CLE] button").count() == 0   # un généré ne se retire pas ici
    assert "GÉNÉRÉ" in p.inner_text("#shares tr[data-name=CLE]")
    assert p.locator("#users .compte").count() == 1
    assert all(m == "GET" for m, *_ in appels) and err == []
    ctx.close()


def test_creer_un_partage_envoie_le_bon_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/media/smb.html", ROUTES)
    p.wait_for_selector("#shares tr")
    p.fill("#shName", "Photos")
    p.fill("#shPath", "/data/photos")
    p.fill("#shUsers", "admin, gk2")
    p.fill("#shComment", "Albums")
    p.check("input[name=mode][value=rw]")
    p.click("#fShare button[type=submit]")
    p.wait_for_function("document.getElementById('rNew').textContent.includes('créé')")
    m, chemin, corps = [a for a in appels if a[0] == "POST"][-1]
    assert chemin == "/smb/shares" and corps == {"name": "Photos", "path": "/data/photos", "readonly": False, "users": ["admin", "gk2"], "comment": "Albums"}
    assert err == []
    ctx.close()


def test_retirer_un_partage_demande_confirmation_dans_la_page(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/media/smb.html", ROUTES)
    p.wait_for_selector("#shares tr")
    p.click("#shares tr[data-name=data] button")
    assert p.is_visible("#confShare") and "data" in p.inner_text("#confShare")
    assert not [a for a in appels if a[0] == "POST"]
    p.get_by_role("button", name="Annuler").click()
    assert not p.is_visible("#confShare") and not [a for a in appels if a[0] == "POST"]
    p.click("#shares tr[data-name=data] button")
    p.get_by_role("button", name="Confirmer").click()
    p.wait_for_function("document.getElementById('rShare').textContent.includes('retiré')")
    assert [a for a in appels if a[0] == "POST"][-1][1:] == ("/smb/shares/delete", {"name": "data"})
    assert err == []
    ctx.close()


def test_compte_mot_de_passe_envoye_puis_efface(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/media/smb.html", dict(ROUTES, **{"/smb/users": (200, {"ok": True, "users": ["admin"], "user": "gk2", "created": True})}))
    p.wait_for_selector("#shares tr")
    p.fill("#usName", "gk2")
    p.fill("#usPw", "s3cret")
    p.click("#fUser button[type=submit]")
    p.wait_for_function("document.getElementById('rUser').textContent.includes('créé')")
    assert [a for a in appels if a[0] == "POST"][-1][1:] == ("/smb/users", {"user": "gk2", "password": "s3cret"})
    assert p.input_value("#usPw") == "" and "s3cret" not in p.inner_text("body")
    assert err == []
    ctx.close()


def test_refus_du_ctl_affiche_le_motif(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/media/smb.html", dict(ROUTES, **{"/smb/shares": (400, {"detail": "chemin hors des racines partageables"})}))
    p.wait_for_selector("#shares tr")
    p.fill("#shName", "X")
    p.fill("#shPath", "/etc")
    p.click("#fShare button[type=submit]")
    p.wait_for_function("document.getElementById('rNew').textContent.includes('hors des racines')")
    assert err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/media/smb.html", {"/smb/status": (401, {"detail": "jeton requis"}), "/smb/users": (401, {})})
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE" and p.inner_text("#tShares") == "—" and p.inner_text("#tUsers") == "—" and err == []
    ctx.close()


def test_demonstration_sans_aucun_appel_et_telephone(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/media/smb.html?demo=1", {}, taille={"width": 420, "height": 800})
    p.wait_for_selector("#shares tr")
    assert p.is_visible("#demo") and p.locator("#shares tr").count() == 3
    p.fill("#shName", "X")
    p.fill("#shPath", "/data/x")
    p.click("#fShare button[type=submit]")
    p.wait_for_function("document.getElementById('rNew').textContent.includes('Démonstration')")
    assert appels == [] and err == []
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    ctx.close()
