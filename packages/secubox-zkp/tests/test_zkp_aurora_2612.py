# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2612 — /zkp/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "zkp" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'zkp'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_d_ecriture_a_l_identique():
    for r in ("'POST', '/keygen'", "'POST', '/prove'", "'POST', '/verify'", "'DELETE', '/keys/'", "/status", "/keys"):
        assert r in SRC
    assert "{ name: SEL }" in SRC and "density" in SRC and "nodes" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC


def test_aucun_secret_ni_stockage_de_secret():
    assert "setItem" not in SRC
    # ni témoin, ni clé privée, ni série inventée
    assert "Math.random" not in SRC
    assert "witness" not in SRC.lower() and "private" not in SRC.lower()


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
STATUS = {"tools_available": True, "version": "zkp 1.0.0", "key_count": 2}
KEYS = {"keys": [{"name": "alpha", "nodes": 20, "graph_size": 1840, "key_size": 612, "created": NOW - 3600},
                 {"name": "beta", "nodes": 12, "graph_size": 720, "key_size": 388, "created": NOW - 86400}]}
API = {"/status": (200, STATUS), "/keys": (200, KEYS)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "zkp":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/zkp", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (200, {"success": True})) if r.request.method != "GET" else routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/zkp/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableau_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/zkp/", API)
    p.wait_for_selector("#bCles tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tOutils", "#tVersion", "#tCles", "#tPreuves")] == ["OK", "zkp 1.0.0", "2", "—"]
    assert p.inner_text("#etat") == "PRÊT"
    t = p.inner_text("#bCles")
    assert "alpha" in t and "beta" in t and "20" in t and "1,8 Ko" in t and "1970" not in t
    assert err == []
    ctx.close()


def test_generer_une_cle_envoie_le_meme_corps(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/zkp/", API)
    p.wait_for_selector("#bCles tr td.mono", state="attached")
    p.fill("#nom", "gamma"); p.fill("#noeuds", "15"); p.select_option("#densite", "0.7")
    p.click("#btnCle")
    p.wait_for_function("document.getElementById('rCle').textContent.includes('générée')")
    post = [a for a in appels if a[0] == "POST" and a[1] == "/keygen"][0]
    assert json.loads(post[2]) == {"name": "gamma", "nodes": 15, "density": 0.7}
    ctx.close()


def test_prouver_et_verifier(navigateur):
    routes = {**API, "/prove": (200, {"success": True, "name": "alpha", "proof_size": 2048, "proof_file": "/var/lib/zkp/proofs/alpha.proof", "proof_preview": "QUJD" * 40}),
              "/verify": (200, {"success": True, "name": "alpha", "result": "ACCEPT", "valid": True, "output": "ACCEPT"})}
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/zkp/", routes)
    p.wait_for_selector("#bCles tr td.mono", state="attached")
    assert p.is_disabled("#btnProuve")
    p.select_option("#cle", "alpha")
    p.click("#btnProuve")
    p.wait_for_function("document.getElementById('rPreuve').textContent.includes('Preuve générée')")
    txt = p.inner_text("#rPreuve")
    assert "2,0 Ko" in txt and "QUJD" in txt and txt.count("QUJD") <= 15   # aperçu tronqué à 60 caractères
    p.click("#btnVerifie")
    p.wait_for_selector("#verdict:not([hidden])")
    assert "VÉRIFIÉE" in p.inner_text("#verdict")
    assert ("POST", "/prove", '{"name":"alpha"}') in appels and ("POST", "/verify", '{"name":"alpha"}') in appels
    assert err == []
    ctx.close()


def test_verification_refusee(navigateur):
    routes = {**API, "/verify": (200, {"success": True, "name": "alpha", "result": "REJECT", "valid": False, "output": "REJECT"})}
    ctx, p, _, _ = ouvre(navigateur, "http://sbx.test/zkp/", routes)
    p.wait_for_selector("#bCles tr td.mono", state="attached")
    p.select_option("#cle", "alpha"); p.click("#btnVerifie")
    p.wait_for_selector("#verdict.ko")
    assert "ÉCHOUÉE" in p.inner_text("#verdict")
    ctx.close()


def test_suppression_demande_une_confirmation_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/zkp/", {**API, "/keys/alpha": (200, {"success": True})})
    p.wait_for_selector("#bCles tr td.act")
    p.locator("#bCles tr").first.get_by_text("Supprimer").click()
    assert not [a for a in appels if a[0] == "DELETE"]          # pas encore : il faut confirmer
    p.locator("#bCles tr").first.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rCles').textContent.includes('supprimée')")
    assert ("DELETE", "/keys/alpha", None) in appels
    ctx.close()


def test_annuler_ne_supprime_rien(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/zkp/", API)
    p.wait_for_selector("#bCles tr td.act")
    p.locator("#bCles tr").first.get_by_text("Supprimer").click()
    p.locator("#bCles tr").first.get_by_text("Annuler").click()
    assert not [a for a in appels if a[0] == "DELETE"]
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/zkp/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tOutils", "#tVersion", "#tCles", "#tPreuves")] == ["—"] * 4 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/zkp/?demo=1", {})
    p.wait_for_selector("#bCles tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.select_option("#cle", "maillage-gk2"); p.click("#btnProuve")
    p.wait_for_function("document.getElementById('rPreuve').textContent.includes('inerte')")
    p.fill("#nom", "x-demo"); p.click("#btnCle")
    p.wait_for_function("document.getElementById('rCle').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/zkp/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bCles tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
