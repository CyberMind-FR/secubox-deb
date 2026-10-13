# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2542 — /assist/ : le panneau « En cours » montre demandes, offres et correspondances, avec les gestes utiles. Vrai navigateur, API simulée."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = (Path(__file__).resolve().parents[1] / "www" / "assist" / "index.html").read_text(encoding="utf-8")
OFFRES = [{"offer_id": "px-o1", "tags": ["dns"], "scope": None, "issued_by": "did:autre", "noeud": "gk2", "de_moi": False, "reste_s": 3000},
          {"offer_id": "px-o2", "tags": ["waf"], "scope": "sbx", "issued_by": "did:moi", "noeud": "gk1", "de_moi": True, "reste_s": 600}]
DEMANDES = [{"req_id": "py-r1", "tags": ["gk1"], "reason": "besoin d'aide", "issued_by": "did:moi", "noeud": "gk1", "de_moi": True, "reste_s": 3500},
            {"req_id": "py-r2", "tags": ["dns"], "reason": "<img src=x onerror=window.__xss=1>", "issued_by": "did:autre", "noeud": "gk2", "de_moi": False, "reste_s": 90}]
MATCHS = [{"match_id": "m1", "offer_id": "px-o1", "req_id": "py-r1", "offerer_did": "did:autre"}]


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, offres=OFFRES, demandes=DEMANDES, matchs=MATCHS, statut=200):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    posts = []
    p.route("http://sbx.test/", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=PAGE))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, content_type="application/javascript", body=""))

    def api(r, *_):
        u, m = r.request.url, r.request.method
        if m == "POST":
            posts.append((u.split("/api/v1/assist/")[-1], json.loads(r.request.post_data or "{}")))
            return r.fulfill(status=200, content_type="application/json", body="{}")
        if statut != 200:
            return r.fulfill(status=statut, content_type="application/json", body="{}")
        corps = (offres if u.endswith("/offers") else demandes if u.endswith("/requests/open") else matchs if u.endswith("/matches")
                 else {"active_session": None, "pending": []} if u.endswith("/sessions") else [])
        r.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/**", api)
    boites = []
    p.on("dialog", lambda d: (boites.append(d.type), d.dismiss()))
    p.goto("http://sbx.test/")
    p.wait_for_function("document.getElementById('enc-maj').textContent.length > 0 || !document.getElementById('enc-err').hidden")
    return ctx, p, posts, boites


def test_les_trois_listes_sont_visibles_sans_ouvrir_d_onglet_avec_leurs_comptes(navigateur):
    ctx, p, _, _ = ouvre(navigateur)
    assert p.inner_text("#enc-nreq") == "(2)" and p.inner_text("#enc-noff") == "(2)" and p.inner_text("#enc-nmat") == "(1)"
    assert "gk2" in p.inner_text("#enc-req") and "ma demande" in p.inner_text("#enc-req")
    assert "mon offre" in p.inner_text("#enc-off") and "expire dans 50 min" in p.inner_text("#enc-off")
    ctx.close()


def test_repondre_n_est_propose_que_sur_la_demande_d_un_autre(navigateur):
    ctx, p, posts, _ = ouvre(navigateur)
    assert p.locator("#enc-req [data-act=request-answer]").count() == 1
    p.click("#enc-req [data-act=request-answer]")
    p.wait_for_function("window.__posts !== undefined || true")
    assert ("request/answer", {"req_id": "py-r2"}) in posts
    ctx.close()


def test_retirer_n_est_propose_que_sur_mon_offre(navigateur):
    ctx, p, posts, _ = ouvre(navigateur)
    assert p.locator("#enc-off [data-act=offer-revoke]").count() == 1
    p.click("#enc-off [data-act=offer-revoke]")
    p.wait_for_function("true")
    assert ("offer/revoke", {"offer_id": "px-o2"}) in posts
    ctx.close()


def test_accepter_l_aide_pose_le_cote_demande_et_nomme_le_noeud(navigateur):
    ctx, p, posts, _ = ouvre(navigateur)
    assert "gk2" in p.inner_text("#enc-mat") and "Accepter l'aide" in p.inner_text("#enc-mat")
    p.click("#enc-mat [data-act=match-accept]")
    p.wait_for_function("true")
    assert ("match/accept", {"offer_id": "px-o1", "req_id": "py-r1", "side": "request"}) in posts
    assert "Une aide vous est proposée" in p.inner_text("#enc-req")
    ctx.close()


def test_etats_vides_expliques(navigateur):
    ctx, p, _, _ = ouvre(navigateur, [], [], [])
    t = p.inner_text("#encours")
    assert "Aucune demande en cours" in t and "Aucune offre en cours" in t and "Rien à accepter" in t
    ctx.close()


def test_autorisation_manquante_est_dite_au_lieu_de_laisser_vide(navigateur):
    ctx, p, _, _ = ouvre(navigateur, statut=401)
    assert "Session requise" in p.inner_text("#enc-err") and p.is_visible("#enc-err")
    ctx.close()


def test_erreur_serveur_est_dite(navigateur):
    ctx, p, _, _ = ouvre(navigateur, statut=500)
    assert "HTTP 500" in p.inner_text("#enc-err")
    ctx.close()


def test_le_contenu_distant_est_echappe_et_aucune_boite_native(navigateur):
    ctx, p, _, boites = ouvre(navigateur)
    assert p.evaluate("window.__xss") is None and "<img" in p.inner_text("#enc-req") and boites == []
    ctx.close()


def test_le_parcours_est_explique_dans_la_page(navigateur):
    ctx, p, _, _ = ouvre(navigateur)
    p.click("#encours details.aide summary")
    t = p.inner_text("#encours details.aide")
    assert "Répondre" in t and "Accepter l'aide" in t and "expire" in t
    ctx.close()
