# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Companion 2.0 : écrans locaux, dans un vrai navigateur, plugin natif et box simulés."""
import functools
import http.server
import json
import re
import threading
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www"
playwright = pytest.importorskip("playwright.sync_api")

BOX = "https://admin.gk12.secubox.in"
LIEN = "secubox%3A%2F%2Fassocier%3Fbox%3Dhttps%253A%252F%252Fadmin.gk12.secubox.in"

# Simule le plugin natif et enregistre ses appels dans window.__appels.
CAPACITOR = """
window.__appels = [];
window.Capacitor = {Plugins: {Boite: {
  ouvrir: async (a) => { window.__appels.push(['ouvrir', a]); return {joignable: true}; },
  navigateur: async (a) => { window.__appels.push(['navigateur', a]); },
}}};
"""


@pytest.fixture(scope="module")
def serveur():
    class Silencieux(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Silencieux, directory=str(WWW)))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d/" % srv.server_address[1]
    srv.shutdown()


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, serveur, fragment="", stockage=None, version=("200", {"version": "2.0"}), echec=False):
    ctx = navigateur.new_context(viewport={"width": 420, "height": 800})
    ctx.add_init_script(CAPACITOR)
    if stockage is not None:
        ctx.add_init_script("if (!sessionStorage.getItem('init')) { sessionStorage.setItem('init','1');"
                            " for (const [k,v] of Object.entries(%s)) localStorage.setItem(k, v); }" % json.dumps(stockage))
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("console", lambda m: erreurs.append(m.text) if m.type == "error" else None)

    def box(r, *_):
        if echec:
            r.abort()
        else:
            r.fulfill(status=int(version[0]), content_type="application/json", body=json.dumps(version[1]))
    p.route("https://**/companion/version.json", box)
    p.goto(serveur + ("#" + fragment if fragment else ""))
    return ctx, p, erreurs


def sans_debordement(p):
    return p.evaluate("document.documentElement.scrollWidth") <= 420


def test_liste_vide_montre_association(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur)
    assert "/companion/" in p.inner_text("#app")
    assert p.locator("input#adresse").is_visible()
    assert sans_debordement(p) and not err
    ctx.close()


def test_hash_associer_confirme_puis_ouvre(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur, "associer=" + LIEN)
    assert "Ajouter admin.gk12.secubox.in à vos box ?" in p.inner_text("#app")
    assert sans_debordement(p)
    p.click("text=Oui")
    p.wait_for_function("window.__appels.length > 0")
    assert p.evaluate("window.__appels") == [["ouvrir", {"origine": BOX}]]
    boites = json.loads(p.evaluate("localStorage.getItem('sbx.boites')"))
    assert boites[0]["origine"] == BOX
    assert not err
    ctx.close()


def test_hash_associer_non_ne_garde_rien(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur, "associer=" + LIEN)
    p.click("text=Non")
    assert p.evaluate("localStorage.getItem('sbx.boites')") is None
    assert p.evaluate("window.__appels") == [] and "Mes box" in p.inner_text("#app")
    ctx.close()


def test_hash_associer_refus_non_https(navigateur, serveur):
    lien = "secubox%3A%2F%2Fassocier%3Fbox%3Dhttp%253A%252F%252Fadmin.gk12.secubox.in"
    ctx, p, err = ouvre(navigateur, serveur, "associer=" + lien)
    assert "refusé" in p.inner_text("#app") and "https requis" in p.inner_text("#app")
    assert p.evaluate("localStorage.getItem('sbx.boites')") is None
    assert sans_debordement(p) and not err
    ctx.close()


def test_injoignable(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur, stockage={"sbx.boites": json.dumps([{"origine": BOX, "nom": "admin.gk12.secubox.in", "vu": 1}])}, echec=True)
    p.click("text=Ouvrir")
    p.wait_for_selector("text=Box injoignable")
    assert p.locator("text=Réessayer").is_visible() and p.locator("text=Choisir une autre box").is_visible()
    assert p.evaluate("window.__appels") == [] and sans_debordement(p)
    p.click("text=Choisir une autre box")
    assert "Mes box" in p.inner_text("#app")
    ctx.close()


def test_hash_injoignable_pose_par_le_natif(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur, "injoignable=" + "https%3A%2F%2Fadmin.gk12.secubox.in")
    assert "Box injoignable" in p.inner_text("#app") and "admin.gk12.secubox.in" in p.inner_text("#app")
    assert sans_debordement(p)
    ctx.close()


def test_plugin_rejette_alors_injoignable(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur, stockage={"sbx.boites": json.dumps([{"origine": BOX, "nom": "x", "vu": 1}])})
    p.evaluate("() => { window.Capacitor.Plugins.Boite.ouvrir = async () => { throw new Error('non'); }; }")
    p.click("text=Ouvrir")
    p.wait_for_selector("text=Box injoignable")
    ctx.close()


def test_delai_4s_par_minuteur(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur, stockage={"sbx.boites": json.dumps([{"origine": BOX, "nom": "x", "vu": 1}])})
    p.unroute("https://**/companion/version.json")
    p.route("https://**/companion/version.json", lambda r, *_: None)  # ne répond jamais
    p.click("text=Ouvrir")
    p.wait_for_selector("text=Box injoignable", timeout=7000)
    ctx.close()


def test_nouvelle_version_bandeau(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur, stockage={"sbx.boites": json.dumps([{"origine": BOX, "nom": "x", "vu": 1}])},
                        version=("200", {"version": "2.1"}))
    p.click("text=Ouvrir")
    p.click("text=Nouvelle version")
    assert p.evaluate("window.__appels") == [["ouvrir", {"origine": BOX}], ["navigateur", {"url": BOX + "/companion/"}]]
    assert sans_debordement(p)
    ctx.close()


def test_retrait_avec_confirmation(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur, stockage={"sbx.boites": json.dumps([{"origine": BOX, "nom": "x", "vu": 1}])})
    p.click("text=Retirer")
    assert "Retirer cette box ?" in p.inner_text("#app") and sans_debordement(p)
    p.click("button:has-text('Retirer')")
    assert json.loads(p.evaluate("localStorage.getItem('sbx.boites')")) == []
    ctx.close()


def test_stockage_corrompu(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur, stockage={"sbx.boites": "{x"})
    assert "/companion/" in p.inner_text("#app") and p.locator("input#adresse").is_visible()
    assert not err
    ctx.close()


def test_migration_1x(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur, stockage={"sbx.meta": json.dumps({"url": "https://companion.gk12.secubox.in"})})
    assert "admin.gk12.secubox.in" in p.inner_text("#app")
    ctx.close()


def test_adresse_saisie_invalide(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur)
    p.fill("#adresse", "http://exemple.test")
    p.click("text=Ajouter cette box")
    assert "invalide" in p.inner_text("#msg-adresse")
    ctx.close()


def test_hote_hostile_rendu_en_texte(navigateur, serveur):
    ctx, p, err = ouvre(navigateur, serveur, stockage={"sbx.boites": json.dumps([{"origine": BOX, "nom": "<img src=x onerror=alert(1)>", "vu": 1}])})
    assert "<img" in p.inner_text("#app") and p.locator("#app img").count() == 0
    ctx.close()


def test_aucun_innerhtml():
    for f in WWW.rglob("*"):
        if f.is_file() and f.suffix in {".js", ".html"}:
            src = f.read_text(encoding="utf-8")
            assert not re.search(r"innerHTML\s*=\s*(?!''|\"\")", src), f
            assert "outerHTML" not in src and "insertAdjacentHTML" not in src, f


def test_csp_et_aucune_ressource_externe():
    src = (WWW / "index.html").read_text(encoding="utf-8")
    assert "default-src 'self'; connect-src https:; img-src 'self' data:" in src
    assert not re.search(r'(src|href)="https?://', src)
    assert "<script>" not in src
