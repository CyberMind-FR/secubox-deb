# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2646 — /messagerie/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "messagerie" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "insertAdjacentHTML"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'messagerie'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_et_en_tetes_a_l_identique():
    for r in ("'/fil'", "'/prives'", "'/annuaire'", "API + '/messages'", "API + '/messages/' + encodeURIComponent(m.id)",
              "method: 'POST'", "method: 'DELETE'", "'X-Sbx-Messagerie': '1'", "'Content-Type': 'application/json'"):
        assert r in SRC
    for champ in ("b.parent = reponse.id", "b.public =", "b.destinataire =", "b.pseudo ="):
        assert champ in SRC


def test_aucun_secret():
    assert "sbx_token" not in SRC and "password" not in SRC.lower()


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
FIL = {"moi": {"type": "sbx", "pseudo": "alice", "moderateur": False},
       "messages": [
           {"id": "m1", "pseudo": "bob", "source": "local", "cree_le": NOW - 600, "corps": "<b>bonjour</b>", "auteur_type": "sbx"},
           {"id": "m2", "pseudo": "alice", "source": "local", "de_moi": True, "cree_le": NOW - 300, "corps": "salut", "auteur_type": "sbx"},
           {"id": "m3", "pseudo": "dj", "source": "radio", "cree_le": NOW - 100, "corps": "en direct", "auteur_type": "visiteur"}]}
PRIVES = {"messages": [{"id": "p1", "pseudo": "bob", "source": "local", "prive": True, "cree_le": NOW - 50, "corps": "psst", "auteur_type": "sbx"}]}
ANNU = {"personnes": [{"pseudo": "bob", "ref": "u-bob"}]}
API = {"/fil": (200, FIL), "/prives": (200, PRIVES), "/annuaire": (200, ANNU)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "messagerie":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/messagerie", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data, r.request.headers.get("x-sbx-messagerie")))
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, (404, {}))
        else:
            statut, corps = routes.get(chemin, (200, {"ok": True, "prive": False, "source": "local"}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/messagerie/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


URL = "http://sbx.test/messagerie/"


def test_tuiles_et_fil_viennent_de_l_api_sans_html_interprete(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, API)
    p.wait_for_selector("#fil .msg", state="attached")
    assert [p.inner_text(i) for i in ("#tMur", "#tPrives", "#tQui")] == ["3", "1", "alice"]
    assert p.inner_text("#etat") == "EN LIGNE"
    assert "<b>bonjour</b>" in p.inner_text("#fil") and p.locator("#fil b").count() == 0
    assert p.locator("#fil .msg.radio").count() == 1
    assert err == []
    ctx.close()


def test_onglet_prives(navigateur):
    ctx, p, _, _ = ouvre(navigateur, URL, API)
    p.wait_for_selector("#fil .msg", state="attached")
    p.click("#o-prives")
    p.wait_for_function("document.getElementById('fil').textContent.includes('psst')")
    assert p.get_attribute("#o-prives", "aria-selected") == "true"
    ctx.close()


def test_publier_envoie_le_meme_corps_et_l_en_tete(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#fil .msg", state="attached")
    p.fill("#corps", "mon message")
    p.click("#envoi")
    p.wait_for_function("document.getElementById('retour').textContent.includes('Publié')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/messages"][0]
    assert json.loads(post[2]) == {"corps": "mon message"} and post[3] == "1"
    ctx.close()


def test_repondre_en_prive_envoie_parent_et_visibilite(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#fil .msg", state="attached")
    p.locator("#fil .msg").first.get_by_text("En privé").click()
    assert p.is_visible("#rep")
    p.fill("#corps", "en privé")
    p.click("#envoi")
    p.wait_for_function("document.getElementById('retour').textContent.length > 0")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/messages"][0]
    assert json.loads(post[2]) == {"corps": "en privé", "parent": "m1", "public": False}
    ctx.close()


def test_retirer_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, {**API, "/messages/m2": (200, {"ok": True})})
    p.wait_for_selector("#fil .msg.moi", state="attached")
    p.locator("#fil .msg.moi").get_by_text("Retirer", exact=True).click()
    assert not [a for a in appels if a[0] == "DELETE"]
    p.locator("#fil .msg.moi").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('retour').textContent.includes('retiré')")
    assert ("DELETE", "/messages/m2", None, "1") in appels
    ctx.close()


def test_annuler_ne_retire_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, URL, API)
    p.wait_for_selector("#fil .msg.moi", state="attached")
    p.locator("#fil .msg.moi").get_by_text("Retirer", exact=True).click()
    p.locator("#fil .msg.moi").get_by_text("Annuler").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, URL, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tMur", "#tPrives", "#tQui", "#tDernier")] == ["—"] * 4 and err == []
    ctx.close()


def test_service_arrete_hors_ligne(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, {k: (503, {}) for k in API})
    p.wait_for_function("document.getElementById('etat').textContent === 'HORS LIGNE'")
    assert p.inner_text("#tMur") == "—" and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_selector("#fil .msg", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.fill("#corps", "test")
    p.click("#envoi")
    p.wait_for_function("document.getElementById('retour').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#fil .msg", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
