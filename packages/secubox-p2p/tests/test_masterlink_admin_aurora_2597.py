# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2597 — /master-link/admin.html au profil Aurora : statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "master-link" / "admin.html"
SRC = PAGE.read_text(encoding="utf-8")
JETON = "tok-secret-0123456789abcdef"


def test_page_autonome_sans_dialogue_natif_ni_ancienne_peau():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "crt-light" not in SRC and "hybrid-dark" not in SRC and "innerHTML" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'master-link-admin'" in SRC and "demo" in SRC and "embed" in SRC and "ResizeObserver" in SRC


def test_ecritures_identiques_a_l_ancienne_page_et_jeton_jamais_stocke():
    assert SRC.count("method: 'POST'") == 2
    assert "'/invite-local?auto_approve=' + auto + '&ttl=' + ttl" in SRC
    assert "appel('/approve'" in SRC and "JSON.stringify({ fingerprint: p.fingerprint, action: 'approve' })" in SRC
    for lecture in ("'/status'", "'/peers'", "'/tree'"):
        assert lecture in SRC
    assert "localStorage.setItem" not in SRC and "sessionStorage" not in SRC
    assert "sbx_token" in SRC and "'Authorization': 'Bearer ' + t" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"enabled": True, "role": "master", "depth": 0, "max_depth": 3, "upstream": None, "fingerprint": "4f9a1c7be2d08a35",
          "hostname": "maitre<b>x</b>", "auto_approve": False, "peers": {"pending": 1, "approved": 1, "rejected": 0, "total": 2}, "active_tokens": 2}
PEERS = {"peers": [{"fingerprint": "aa11", "hostname": "<img src=x>", "address": "192.0.2.5", "status": "approved", "approved_at": "2026-10-01T09:00:00"},
                   {"fingerprint": "bb22'); alert(1);//", "hostname": "noeud-2", "address": None, "status": "pending", "joined_at": "2026-10-12T08:00:00"}], "count": 2}
TREE = {"tree": {"fingerprint": "4f9a1c7be2d08a35", "hostname": "maitre", "role": "master", "depth": 0, "address": "192.0.2.1",
                 "children": [{"fingerprint": "aa11bb22cc33dd44", "hostname": "enfant", "role": "peer", "address": "192.0.2.5", "children": []}]}}
INVITE = {"token": JETON, "url": "https://192.0.2.1/master-link/?token=" + JETON, "cli": "sbx-mesh-join 192.0.2.1 " + JETON, "expires_ts": 1900000000, "expires": "x"}
API = {("GET", "/status"): (200, STATUS), ("GET", "/peers"): (200, PEERS), ("GET", "/tree"): (200, TREE),
       ("POST", "/invite-local"): (200, INVITE), ("POST", "/approve"): (200, {"status": "approved"})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif"), d.dismiss()))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "master-link/admin.html":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin, _, requete = r.request.url.split("/api/v1/p2p/master-link", 1)[1].partition("?")
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization"), requete))
        statut, corps = routes.get((r.request.method, chemin), (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/p2p/master-link/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


URL = "http://sbx.test/master-link/admin.html"


def test_tuiles_pairs_et_echappement(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API)
    p.wait_for_function("document.getElementById('tAppr').textContent !== '—'")
    assert [p.inner_text(i) for i in ("#tRole", "#tProf", "#tAppr", "#tAtt", "#tTok")] == ["Maître", "0", "1", "1", "2"]
    assert p.inner_text("#kNom") == "maitre<b>x</b>" and p.inner_text("#kAmont") == "aucun (maître racine)"
    assert p.locator("#bPairs tr").count() == 2 and "<img src=x>" in p.inner_text("#bPairs")
    assert p.locator("#bPairs img").count() == 0 and "APPROUVÉ" in p.inner_text("#bPairs") and "EN ATTENTE" in p.inner_text("#bPairs")
    assert p.locator("#bPairs button").count() == 1                         # seul le pair en attente se valide
    p.click("[data-onglet=arbre]")
    assert "enfant" in p.inner_text("#arbre") and "4f9a1c7be2d0" in p.inner_text("#arbre")
    assert all(a[0] == "GET" for a in appels) and err == []
    ctx.close()


def test_approbation_confirmee_dans_la_page_avec_le_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API)
    p.click("[data-onglet=pairs]"); p.wait_for_selector("#bPairs button")
    p.click("#bPairs button")
    assert p.is_visible("#confirm") and not [a for a in appels if a[0] == "POST"]       # rien n'est parti avant confirmation
    p.click("#confNon")
    assert not p.is_visible("#confirm") and not [a for a in appels if a[0] == "POST"]
    p.click("#bPairs button"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rPairs').textContent.includes('approuvé')")
    posts = [a for a in appels if a[0] == "POST"]
    assert len(posts) == 1 and posts[0][1] == "/approve"
    assert json.loads(posts[0][2]) == {"fingerprint": "bb22'); alert(1);//", "action": "approve"} and err == []
    ctx.close()


def test_approbation_refusee_n_affiche_plus_un_faux_succes(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, {**API, ("POST", "/approve"): (404, {"detail": "No pending request for this fingerprint"})})
    p.click("[data-onglet=pairs]"); p.wait_for_selector("#bPairs button")
    p.click("#bPairs button"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rPairs').textContent.includes('Échec')")
    assert "No pending request" in p.inner_text("#rPairs") and "ko" in p.get_attribute("#rPairs", "class") and err == []
    ctx.close()


def test_invitation_meme_appel_et_jeton_non_conserve(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API)
    p.click("[data-onglet=inviter]")
    p.uncheck("#auto"); p.fill("#ttl", "120")
    p.click("#btnInv")
    p.wait_for_selector("#jeton:not([hidden])")
    posts = [a for a in appels if a[0] == "POST"]
    assert len(posts) == 1 and posts[0][1] == "/invite-local" and posts[0][2] is None and posts[0][4] == "auto_approve=false&ttl=120"
    texte = p.inner_text("#jeton")
    assert JETON in texte and "sbx-mesh-join 192.0.2.1" in texte and "/master-link/?token=" in texte
    assert p.evaluate("JSON.stringify([localStorage, sessionStorage])").count(JETON) == 0 and err == []
    ctx.close()


def test_jeton_porte_en_bearer_depuis_sbx_token(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.evaluate("localStorage.setItem('sbx_token','jwt-test')")
    p.click("#rafraichir"); p.wait_for_timeout(300)
    assert any(a[1] == "/status" and a[3] == "Bearer jwt-test" for a in appels)
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, {("GET", "/status"): (401, {"detail": "jeton requis"}), ("GET", "/peers"): (401, {}), ("GET", "/tree"): (403, {})})
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tRole", "#tProf", "#tAppr", "#tAtt", "#tTok", "#kFp")] == ["—"] * 6
    assert err == []
    ctx.close()


def test_demonstration_annoncee_et_inerte(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_selector("#demo:not([hidden])")
    assert p.inner_text("#tAppr") == "2" and "192.0.2." in p.inner_text("#bPairs")
    p.click("[data-onglet=pairs]"); p.click("#bPairs button"); p.click("#confOui")
    p.wait_for_function("document.getElementById('rPairs').textContent.includes('inerte')")
    p.click("[data-onglet=inviter]"); p.click("#btnInv")
    p.wait_for_function("document.getElementById('rInv').textContent.includes('inerte')")
    assert appels == [] and not p.is_visible("#jeton") and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_function("document.getElementById('tAppr').textContent !== '—'")
    for o in ("pairs", "arbre", "inviter", "vue"):
        p.click("[data-onglet=%s]" % o)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
