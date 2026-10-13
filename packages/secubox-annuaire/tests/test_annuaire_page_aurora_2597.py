# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2597 — /annuaire/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "annuaire" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "/shared/crt-engine.js" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'annuaire'" in SRC and "demo" in SRC and "embed" in SRC
    assert "sbx_token" in SRC


def test_routes_lues_et_ecriture_a_l_identique():
    for r in ("/status", "/log?limit=50", "/services", "/subscriptions"):
        assert r in SRC
    # écriture : seule l'abonnement existait, même route, même corps
    assert SRC.count("ecrire('POST'") == 1
    assert "'/service/' + s.service_id + '/subscribe'" in SRC
    assert "{ subscriber_did: did, subscriber_priv_hex: cle }" in SRC
    # la clé privée est saisie en champ masqué, jamais affichée ni stockée
    assert 'id="aboCle" type="password"' in SRC
    assert "localStorage.setItem" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


DID1 = "did:plc:" + "0123456789abcdef0123456789abcdef"
DID2 = "did:plc:" + "fedcba9876543210fedcba9876543210"
STATUS = {"module": "annuaire", "chain_ok": True, "chain_broken_at": None, "merkle_root": "ab" * 32, "tip_height": 2}
LOG = [{"height": 0, "op": "genesis", "payload_type": "Genesis", "author": DID1, "created_at": "2026-10-10T08:00:00Z"},
       {"height": 1, "op": "service_offer", "payload_type": "ServiceOffer", "author": DID1, "created_at": "2026-10-11T09:30:00Z"},
       {"height": 2, "op": "service_subscribe", "payload_type": "Subscription", "author": DID2, "created_at": "2026-10-12T10:15:00Z"}]
SERVICES = {"services": [{"service_id": "svc1", "name": "miroir-apt", "kind": "mirror", "provider": DID1, "approval_mode": "auto"},
                         {"service_id": "svc2", "name": "api-x", "kind": "api", "provider": DID2, "approval_mode": "pending"}]}
SUBS = {"subscriptions": [{"subscription_id": "s" * 32, "service_id": "svc1", "subscriber": DID2, "state": "approved", "provider": DID1}]}
API = {"/status": (200, STATUS), "/log": (200, LOG), "/services": (200, SERVICES), "/subscriptions": (200, SUBS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "annuaire":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/annuaire", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("authorization")))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/annuaire/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/annuaire/", API)
    p.wait_for_selector("#bLog tr td.mono", state="attached")
    p.wait_for_selector("#bAbos tr td.mono", state="attached")
    assert p.inner_text("#tChaine") == "Vérifiée" and p.inner_text("#etat") == "CHAÎNE VÉRIFIÉE"
    assert p.inner_text("#tEntrees") == "3" and "pointe 2" in p.inner_text("#sEntrees")
    assert p.inner_text("#tServices") == "2" and p.inner_text("#tAbos") == "1"
    assert p.get_attribute("#tMerkle", "title") == "ab" * 32
    log = p.inner_text("#bLog")
    # la date vient de created_at (l'ancienne page lisait ts/timestamp, toujours vides)
    assert "2026" in log and "service_offer" in log
    # plus récente en haut
    assert p.locator("#bLog tr").first.inner_text().startswith("2")
    assert "APPROUVÉ" in p.inner_text("#bAbos") and "SUR VALIDATION" in p.inner_text("#bServ")
    assert any(a[1] == "/log" for a in appels) and err == []
    ctx.close()


def test_jeton_envoye_et_limite_de_journal(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/annuaire/", API)
    p.wait_for_selector("#bLog tr td.mono", state="attached")
    assert all(a[3] is None for a in appels)
    p.evaluate("localStorage.setItem('sbx_token','jeton-test')")
    p.click("#rafraichir")
    p.wait_for_function("true")
    p.wait_for_timeout(300)
    assert any(a[3] == "Bearer jeton-test" for a in appels)
    ctx.close()


def test_abonnement_confirmation_dans_la_page_et_meme_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/annuaire/", {**API, "/service/svc1/subscribe": (200, {"subscription_id": "z" * 32, "state": "approved"})})
    p.wait_for_selector("#bServ tr td button", state="attached")
    p.locator("#bServ tr").first.get_by_text("S’abonner").click()
    assert p.is_visible("#fAbo") and "miroir-apt" in p.inner_text("#titreAbo")
    assert not [a for a in appels if a[0] == "POST"]           # rien n'est envoyé avant confirmation
    cle = "a1" * 32
    p.fill("#aboDid", DID2); p.fill("#aboCle", cle)
    assert p.get_attribute("#aboCle", "type") == "password"
    p.click("#fAbo button[type=submit]")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('Abonné')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/service/svc1/subscribe"
    assert json.loads(post[2]) == {"subscriber_did": DID2, "subscriber_priv_hex": cle}
    assert cle not in p.content() and p.input_value("#aboCle") == ""
    ctx.close()


def test_abonnement_entree_invalide_n_envoie_rien(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/annuaire/", API)
    p.wait_for_selector("#bServ tr td button", state="attached")
    p.locator("#bServ tr").first.get_by_text("S’abonner").click()
    p.fill("#aboDid", DID2); p.fill("#aboCle", "court")
    p.click("#fAbo button[type=submit]")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('annulé')")
    assert not [a for a in appels if a[0] == "POST"] and err == []
    ctx.close()


def test_donnees_d_api_jamais_interpretees_comme_html(navigateur):
    mechant = {"services": [{"service_id": "x'\"><img src=x onerror=window.pwn=1>", "name": "<b>gras</b>", "kind": "<i>k</i>", "provider": DID1, "approval_mode": "auto"}]}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/annuaire/", {**API, "/services": (200, mechant)})
    p.wait_for_selector("#bServ tr td button", state="attached")
    assert "<b>gras</b>" in p.inner_text("#bServ") and p.evaluate("window.pwn") is None
    assert p.locator("#bServ b, #bServ img").count() == 0 and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/annuaire/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tChaine", "#tEntrees", "#tServices", "#tAbos", "#tMerkle")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/annuaire/?demo=1", {})
    p.wait_for_selector("#bLog tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#bServ tr").first.get_by_text("S’abonner").click()
    p.fill("#aboDid", DID2); p.fill("#aboCle", "b2" * 32); p.click("#fAbo button[type=submit]")
    p.wait_for_function("document.getElementById('rServ').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/annuaire/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bLog tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
