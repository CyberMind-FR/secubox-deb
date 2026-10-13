# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2584 — /master-link/ (page de jonction) au profil Aurora : statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "master-link" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
JETON = "tok-secret-0123456789abcdef"


def test_page_autonome_sans_dialogue_natif_ni_ancienne_peau():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "innerHTML" not in SRC
    for interdit in ("confirm(", "alert(", "prompt("):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'master-link'" in SRC and "demo" in SRC and "embed" in SRC and "ResizeObserver" in SRC


def test_une_seule_ecriture_identique_et_jeton_jamais_stocke_ni_affiche():
    assert SRC.count("method: 'POST'") == 1
    assert "API + '/join'" in SRC and "API + '/status'" in SRC
    assert "token: JETON_INVITATION, fingerprint:" in SRC and "hostname:" in SRC
    assert "localStorage.setItem" not in SRC and "sessionStorage" not in SRC
    assert "textContent = JETON" not in SRC and "sbx_token" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"enabled": True, "role": "master", "depth": 0, "max_depth": 3, "upstream": None, "fingerprint": "4f9a1c7be2d08a35",
          "hostname": "maitre<b>x</b>", "auto_approve": False, "peers": {"pending": 1, "approved": 3, "rejected": 0, "total": 4}, "active_tokens": 2}
API = {"/status": (200, STATUS), "/join": (200, {"status": "pending", "fingerprint": "x"})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "master-link":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/p2p/master-link", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/p2p/master-link/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


URL = "http://sbx.test/master-link/?token=" + JETON


def test_tuiles_identite_et_echappement(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#pJoin:not([hidden])")
    assert [p.inner_text(i) for i in ("#tRole", "#tProf", "#tAppr", "#tAtt", "#tTok")] == ["Maître", "0", "3", "1", "2"]
    assert "sur 3" in p.inner_text("#sProf") and p.inner_text("#etat") == "MAÎTRE PRÊT"
    assert p.inner_text("#kFp") == "4f9a1c7be2d08a35" and p.inner_text("#kNom") == "maitre<b>x</b>"   # texte, jamais du HTML
    assert JETON not in p.content() and err == []
    ctx.close()


def test_jonction_envoie_le_meme_corps_une_seule_fois(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#pJoin:not([hidden])")
    p.fill("#hote", "noeud-test")
    p.click("#btnJoin")
    p.wait_for_selector("#pFait:not([hidden])")
    posts = [a for a in appels if a[0] == "POST"]
    assert len(posts) == 1 and posts[0][1] == "/join"
    corps = json.loads(posts[0][2])
    assert set(corps) == {"token", "fingerprint", "hostname"} and corps["token"] == JETON and corps["hostname"] == "noeud-test" and len(corps["fingerprint"]) == 16
    assert "EN ATTENTE" in p.inner_text("#pEtat") and JETON not in p.content() and err == []
    ctx.close()


def test_jonction_approuvee_et_refus_affiche(navigateur):
    ctx, p, _, _ = ouvre(navigateur, URL, {**API, "/join": (200, {"success": True, "status": "approved", "depth": 1})})
    p.wait_for_selector("#pJoin:not([hidden])"); p.click("#btnJoin"); p.wait_for_selector("#pFait:not([hidden])")
    assert p.inner_text("#pEtat") == "APPROUVÉ" and "profondeur 1" in p.inner_text("#rFait")
    ctx.close()
    ctx, p, _, _ = ouvre(navigateur, URL, {**API, "/join": (403, {"detail": "Token expired"})})
    p.wait_for_selector("#pJoin:not([hidden])"); p.click("#btnJoin")
    p.wait_for_function("document.getElementById('rJoin').textContent.includes('Token expired')")
    assert p.is_visible("#pJoin") and p.is_enabled("#btnJoin")
    ctx.close()


def test_jeton_porte_en_bearer_depuis_sbx_token(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.evaluate("localStorage.setItem('sbx_token','jwt-test')")
    p.click("#rafraichir")
    p.wait_for_timeout(300)
    assert any(a[1] == "/status" and a[3] == "Bearer jwt-test" for a in appels)
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, {"/status": (401, {"detail": "jeton requis"})})
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tRole", "#tProf", "#tAppr", "#tAtt", "#tTok", "#kFp")] == ["—"] * 6
    assert not p.is_visible("#pJoin") and err == []
    ctx.close()


def test_sans_jeton_dans_l_adresse(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/master-link/", API)
    p.wait_for_selector("#erreur:not([hidden])")
    assert "jeton" in p.inner_text("#erreur") and appels == [] and err == []
    ctx.close()


def test_demonstration_annoncee_et_inerte(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/master-link/?demo=1", {})
    p.wait_for_selector("#pJoin:not([hidden])")
    assert "DÉMONSTRATION" in p.inner_text("#demo") and p.inner_text("#tAppr") == "3"
    p.click("#btnJoin")
    p.wait_for_function("document.getElementById('rJoin').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "&embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#pJoin:not([hidden])")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
