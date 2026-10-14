# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2642 — /assist/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

SRC = (Path(__file__).resolve().parents[1] / "www" / "assist" / "index.html").read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "hybrid-skin" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onsubmit="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'assist'" in SRC and "DEMO" in SRC and "embed" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("/api/v1/assist/request'", "/api/v1/assist/offer'", "/api/v1/assist/offer/revoke", "/api/v1/assist/request/open",
              "/api/v1/assist/request/answer", "/api/v1/assist/match/accept", "/api/v1/assist/joinlink",
              "/api/v1/assist/delegation/assertion", "/api/v1/assist/close", "/api/v1/assist/console/grant",
              "/api/v1/assist/console/revoke", "/api/v1/annuaire/sync/now"):
        assert r in SRC
    for r in ("'/sessions'", "'/offers'", "'/requests/open'", "'/matches'", "'/delegations'"):
        assert r in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "Authorization" in SRC


def test_aucun_secret_ni_serie_inventee():
    assert "setItem" not in SRC and "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


OFFRES = [{"offer_id": "o1", "tags": ["dns"], "scope": None, "noeud": "gk2", "de_moi": False, "reste_s": 3000},
          {"offer_id": "o2", "tags": ["waf"], "scope": "sbx", "noeud": "gk1", "de_moi": True, "reste_s": 600}]
DEMANDES = [{"req_id": "r1", "tags": ["gk1"], "reason": "besoin", "noeud": "gk1", "de_moi": True, "reste_s": 3500},
            {"req_id": "r2", "tags": ["dns"], "reason": "<img src=x onerror=window.__xss=1>", "noeud": "gk2", "de_moi": False, "reste_s": 90}]
MATCHS = [{"offer_id": "o1", "req_id": "r1", "mon_cote": "request", "offre_acceptee": True, "demande_acceptee": False, "prete": False,
           "noeud_offre": "gk2", "noeud_demande": "gk1", "tags": ["dns"]}]
SESSION = {"active_session": {"session_id": "sess-1", "center_did": "did:plc:centre", "expires_ts": "2030-01-01T00:00:00Z"}, "pending": []}
DELEG = [{"noeud": "gk3", "fin": "2030-01-01T00:00:00Z", "session_id": "sess-9"}]


def ouvre(navigateur, url="http://sbx.test/assist/", statut=200, session=SESSION, taille=None, jeton=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, posts, gets, boites = [], [], [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (boites.append(d.type), d.dismiss()))
    if jeton:
        p.add_init_script("localStorage.setItem('sbx_token','%s')" % jeton)

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "assist":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        u, m = r.request.url, r.request.method
        if m == "POST":
            posts.append((u.split("/api/v1/")[-1], json.loads(r.request.post_data or "{}")))
            return r.fulfill(status=200, content_type="application/json", body=json.dumps({"url": "https://x.example/lien"}))
        gets.append((u.split("/api/v1/assist")[-1], r.request.headers.get("authorization")))
        if statut != 200:
            return r.fulfill(status=statut, content_type="application/json", body="{}")
        corps = (OFFRES if u.endswith("/offers") else DEMANDES if u.endswith("/requests/open") else MATCHS if u.endswith("/matches")
                 else DELEG if u.endswith("/delegations") else session if u.endswith("/sessions") else [])
        r.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/**", api)
    p.goto(url)
    return ctx, p, erreurs, posts, gets, boites


def pause(p):
    p.wait_for_timeout(400)


def attend(p):
    p.wait_for_function("document.getElementById('enc-maj').textContent.length > 0 || !document.getElementById('enc-err').hidden")
    p.wait_for_function("document.getElementById('tDel').textContent !== '—' || document.getElementById('tSes').textContent === '—'")


def test_tuiles_et_listes_viennent_de_l_api_avec_le_jeton(navigateur):
    ctx, p, err, _, gets, boites = ouvre(navigateur, jeton="abc")
    attend(p)
    assert [p.inner_text(i) for i in ("#tReq", "#tOff", "#tMat", "#tSes", "#tDel")] == ["2", "2", "1", "Oui", "1"]
    assert "gk2" in p.inner_text("#enc-req") and "mon offre" in p.inner_text("#enc-off") and "expire dans 50 min" in p.inner_text("#enc-off")
    assert "sess-1" in p.inner_text("#active") and "{" not in p.inner_text("#active")
    assert gets and all(a == "Bearer abc" for _, a in gets)
    assert p.evaluate("window.__xss") is None and "<img" in p.inner_text("#enc-req")
    assert err == [] and boites == []
    ctx.close()


def test_chaque_tuile_a_sa_definition(navigateur):
    ctx, p, *_ = ouvre(navigateur)
    assert all(len(t) > 25 for t in p.eval_on_selector_all(".tuile", "e => e.map(x => x.title)"))
    ctx.close()


def test_actions_du_marche_envoient_les_memes_corps(navigateur):
    ctx, p, _, posts, _, _ = ouvre(navigateur)
    attend(p)
    p.click("#enc-req [data-act=request-answer]")
    pause(p)
    p.click("#enc-mat [data-act=match-accept]")
    p.click("#enc-off [data-act=offer-revoke]")
    p.fill("#offer-tags", "dns, waf"); p.fill("#offer-ttl", "120"); p.click("[data-act=offer]")
    pause(p)
    p.click("#mtabs [data-tab=reqopen]")
    assert p.get_attribute("#mtabs [data-tab=reqopen]", "aria-selected") == "true"
    p.fill("#reqopen-tags", "nft"); p.fill("#reqopen-reason", "aide"); p.click("[data-act=request-open]")
    p.click("#mtabs [data-tab=invite]")
    p.fill("#invite-ref", "o1"); p.click("[data-act=joinlink]")
    p.wait_for_function("document.getElementById('invite-url').value.length > 0")
    pause(p)
    assert ("assist/request/answer", {"req_id": "r2"}) in posts
    assert ("assist/match/accept", {"offer_id": "o1", "req_id": "r1", "side": "request"}) in posts
    assert ("assist/offer/revoke", {"offer_id": "o2"}) in posts
    assert ("assist/offer", {"tags": ["dns", "waf"], "scope": None, "ttl_s": 120}) in posts
    assert ("assist/request/open", {"tags": ["nft"], "scope": None, "ttl_s": 3600, "reason": "aide"}) in posts
    assert ("assist/joinlink", {"ref": "o1", "ttl_s": 900}) in posts
    ctx.close()


def test_demande_ciblee_et_consentement_console(navigateur):
    ctx, p, _, posts, _, _ = ouvre(navigateur)
    attend(p)
    p.fill("#center", "did:plc:c"); p.fill("#reason", "dns"); p.click("[data-act=request]")
    p.select_option("#deleg-duree", "14400"); p.click("[data-act=console-grant]")
    pause(p)
    p.click("[data-act=console-revoke]")
    pause(p)
    assert ("assist/request", {"center_did": "did:plc:c", "mode": "per-incident", "scope": "", "duration_s": 1800, "reason": "dns"}) in posts
    assert ("assist/console/grant", {"session_id": "sess-1", "duration_s": 14400}) in posts
    assert ("assist/console/revoke", {"session_id": "sess-1"}) in posts
    ctx.close()


def test_fermer_la_session_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, posts, _, boites = ouvre(navigateur)
    attend(p)
    p.click("#active-card [data-act=close]")
    assert p.is_visible("#conf-close") and not [x for x in posts if x[0].endswith("/close")]
    p.click("[data-act=close-annuler]")
    assert not p.is_visible("#conf-close") and not [x for x in posts if x[0].endswith("/close")]
    p.click("#active-card [data-act=close]"); p.click("[data-act=close-ok]")
    pause(p)
    assert ("assist/close", {"session_id": "sess-1"}) in posts and boites == []
    ctx.close()


def test_administrer_demande_l_assertion(navigateur):
    ctx, p, _, posts, _, _ = ouvre(navigateur)
    attend(p)
    p.evaluate("window.open = () => null")
    p.click("#delegations-list [data-act=administrer]")
    pause(p)
    assert ("assist/delegation/assertion", {"session_id": "sess-9"}) in posts
    ctx.close()


def test_synchro_appelle_l_annuaire(navigateur):
    ctx, p, _, posts, _, _ = ouvre(navigateur)
    attend(p)
    p.click("#sync-now")
    p.wait_for_function("document.getElementById('sync-etat').textContent.length > 0 && !document.getElementById('sync-now').disabled")
    assert any(u == "annuaire/sync/now" for u, _ in posts)
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _, _, _ = ouvre(navigateur, statut=401)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tReq", "#tOff", "#tMat", "#tSes", "#tDel")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, posts, gets, boites = ouvre(navigateur, "http://sbx.test/assist/?demo=1")
    attend(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert p.inner_text("#tReq") == "2" and gets == []
    p.click("#enc-req [data-act=request-answer]"); p.click("#sync-now")
    p.click("#active-card [data-act=console-grant]")
    p.wait_for_function("document.getElementById('toast').textContent.includes('inerte')")
    assert posts == [] and gets == [] and err == [] and boites == []
    ctx.close()


def test_telephone_sans_debordement_et_menu_masque_en_embed(navigateur):
    for url in ("http://sbx.test/assist/?embed=1", "http://sbx.test/assist/?demo=1"):
        ctx, p, err, *_ = ouvre(navigateur, url, taille={"width": 420, "height": 800})
        attend(p)
        for onglet in ("reqopen", "matches", "invite", "join"):
            p.click("#mtabs [data-tab=%s]" % onglet)
            assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), onglet
        assert err == []
        if "embed" in url:
            assert not p.is_visible("#sidebar")
        ctx.close()
