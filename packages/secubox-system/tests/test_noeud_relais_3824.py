# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3824 — page Système, panneau « Nom du nœud » : l'interrupteur du relais des autres chemins du nom public vers
l'ancienne cible (fermé par défaut). API de secubox-system simulée (#3883 : elle était celle de secubox-webos) ;
confirmation dans le panneau, jamais de dialogue."""
import json
import os
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "system" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")
ROUTE = "/api/v1/system/noeud/relais"

ETAT = {"domaine": "gk2.secubox.in", "relais_api": False, "relais_actif": False, "vhost": True, "cible": "192.168.1.200:8000",
        "chemins_cible": ["/api/v1/metrics", "/api/v1/metablogizer/", "/api/v1/admin/", "/api/v1/system/metrics",
                          "/api/v1/health", "/"],
        "source_chemins": "/etc/nginx/sites-enabled/eye-remote-api",
        "servis": ["/", "/_noeud/de3d.js", "/_noeud/polices/", "/_noeud/sbx-dice.js", "/_noeud/dice/", "/api/v1/health"], "mot_de_passe_defaut": False}


def test_panneau_statique():
    assert 'id="pNoeud"' in SRC and 'role="switch"' in SRC and f"'{ROUTE}'" in SRC
    assert "/api/v1/webos/" not in SRC and "secubox-webos" not in SRC      # #3883 : la carte ne dépend plus du Hall
    assert "JSON.stringify({ actif })" in SRC and "method: 'POST'" in SRC
    assert "demande('cNoeud'" in SRC                          # confirmation intégrée au panneau
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML"):
        assert interdit not in SRC
    bloc = SRC[SRC.index("const API_NOEUD"):SRC.index("$('redetect')")]
    assert "if (DEMO) { retour('rNoeud', true, 'Démonstration : action inerte.'); return; }" in bloc
    assert not re.search(r"192\.168\.", bloc)                  # données de démonstration fictives


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, etat=None, statut=200, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, posts = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.add_init_script("localStorage.setItem('sbx_token', 'abc')")
    courant = dict(etat or ETAT)

    def tout(r, *_):
        url = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if url.rstrip("/") == "/system":
            return r.fulfill(status=200, content_type="text/html", body=SRC)
        if url.startswith("/shared/"):
            return r.fulfill(status=200, content_type="application/javascript", body="")
        if url == ROUTE:
            assert r.request.headers.get("authorization") == "Bearer abc"
            if statut != 200:
                return r.fulfill(status=statut, content_type="application/json", body='{"detail":"refusé"}')
            if r.request.method == "POST":
                corps = json.loads(r.request.post_data)
                posts.append(corps)
                courant.update(relais_api=corps["actif"], relais_actif=corps["actif"])
                return r.fulfill(status=200, content_type="application/json", body=json.dumps({"success": True, **courant}))
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(courant))
        if url.startswith("/api/v1/system/"):
            return r.fulfill(status=200, content_type="application/json", body="{}")
        return r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", tout)
    p.goto("http://sbx.test/system/")
    return ctx, p, erreurs, posts


def test_ouvrir_puis_fermer_avec_confirmation(navigateur):
    ctx, p, err, posts = ouvre(navigateur)
    sw = p.locator("#noInterr")
    p.wait_for_function("!document.getElementById('noInterr').disabled")
    assert sw.get_attribute("aria-checked") == "false" and p.inner_text("#noRelais") == "404 — FERMÉ"
    assert p.inner_text("#noDom") == "gk2.secubox.in" and p.inner_text("#noCible") == "192.168.1.200:8000"
    assert p.locator("#noChemins").is_hidden()
    sw.click()
    assert posts == []                                          # pas encore : il faut confirmer
    texte = p.inner_text("#cNoeud")
    assert "4 chemins" in texte and "/api/v1/admin/" in texte and "deviendront publics sur gk2.secubox.in" in texte
    p.locator("#cNoeud").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('noInterr').getAttribute('aria-checked') === 'true'")
    assert posts == [{"actif": True}]
    assert p.inner_text("#noRelais") == "RELAYÉS" and "Relais ouvert" in p.inner_text("#rNoeud")
    liste = p.locator("#noListe li").all_inner_texts()
    assert liste == ["/api/v1/metrics", "/api/v1/metablogizer/", "/api/v1/admin/", "/api/v1/system/metrics"]
    assert "eye-remote-api" in p.inner_text("#noChemins")
    sortie = os.environ.get("SBX_CAPTURES")
    if sortie:
        p.locator("#pNoeud").screenshot(path=f"{sortie}/relais-noeud.png")
        p.screenshot(path=f"{sortie}/relais-noeud-page.png", full_page=True)
    # fermer : confirmation aussi, puis retour à 404
    sw.click()
    assert "Fermer le relais" in p.inner_text("#cNoeud")
    p.locator("#cNoeud").get_by_text("Annuler").click()
    assert posts == [{"actif": True}]
    sw.click()
    p.locator("#cNoeud").get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('noInterr').getAttribute('aria-checked') === 'false'")
    assert posts[-1] == {"actif": False} and p.locator("#noChemins").is_hidden()
    assert err == []
    ctx.close()


def test_mot_de_passe_par_defaut_ou_sans_cible_interdit_d_ouvrir(navigateur):
    ctx, p, err, posts = ouvre(navigateur, etat={**ETAT, "mot_de_passe_defaut": True})
    p.wait_for_function("document.getElementById('noDom').textContent === 'gk2.secubox.in'")
    assert p.locator("#noInterr").is_disabled() and p.locator("#noDefaut").is_visible()
    ctx.close()
    ctx, p, err, posts = ouvre(navigateur, etat={**ETAT, "cible": None, "chemins_cible": []})
    p.wait_for_function("document.getElementById('noDom').textContent === 'gk2.secubox.in'")
    assert p.locator("#noInterr").is_disabled() and p.inner_text("#noCible") == "aucune"
    assert err == []
    ctx.close()


@pytest.mark.parametrize("statut,message", [(401, "Réservé aux administrateurs."), (404, "secubox-core trop ancien")])
def test_sans_droit_ou_coeur_ancien(navigateur, statut, message):
    ctx, p, err, posts = ouvre(navigateur, statut=statut)
    p.wait_for_function(f"document.getElementById('noNote').textContent.includes({json.dumps(message)})")
    assert p.locator("#noInterr").is_disabled() and p.inner_text("#noRelais") == "—"
    assert err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, posts = ouvre(navigateur, etat={**ETAT, "relais_api": True, "relais_actif": True}, taille={"width": 420, "height": 860})
    p.wait_for_function("document.getElementById('noInterr').getAttribute('aria-checked') === 'true'")
    assert p.evaluate("document.documentElement.scrollWidth") <= 420
    assert err == []
    ctx.close()
