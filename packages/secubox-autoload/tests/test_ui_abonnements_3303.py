# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3303 : page « Abonnements & profils » dans un vrai navigateur, API simulée : une ligne par box, écart signalé, action sur UNE box avec
confirmation intégrée, échappement, « Appliquer » désactivé tant que #3302 n'est pas livré, aucun prix."""
import json
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
PAGE = ICI / "www" / "autoload" / "abonnements.html"
playwright = pytest.importorskip("playwright.sync_api")

PIEGE = '<img src=x onerror="window.__pwn=1">'
LIGNES = [{"id": 1, "box": "SN-GK5", "client": "atelier-nord", "serie": "SN-GK5", "lot": None, "jeton": "reclame", "formule": "sans-ecran", "formule_libelle": "Sans écran",
           "expire_le": 1_830_000_000, "jours_restants": 300, "statut": "actif", "motif": None, "profil_commande": "distante", "profil_formule": "distante",
           "profil_applique": "lite", "ecart": True},
          {"id": 2, "box": "2", "client": PIEGE, "serie": None, "lot": None, "jeton": "reclame", "formule": None, "formule_libelle": None, "expire_le": None,
           "jours_restants": None, "statut": "suspendu", "motif": PIEGE, "profil_commande": "lite", "profil_formule": None, "profil_applique": None, "ecart": False}]
FORMULES = [{"nom": "sans-ecran", "libelle": "Sans écran", "profil": "distante", "mois": 12}]


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, appels):
    ctx = navigateur.new_context(viewport={"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(route, *_):
        req = route.request
        chemin = req.url.split("/api/v1/autoload", 1)[1].split("?")[0]
        appels.append((req.method, chemin, json.loads(req.post_data) if req.post_data else None))
        rep = {"/abonnements": LIGNES, "/formules": FORMULES}.get(chemin, {"ok": True, "tunnel_applique": True})
        route.fulfill(status=200, content_type="application/json", body=json.dumps(rep))

    p.route("**/api/v1/autoload/**", api)
    p.route("**/shared/**", lambda r, *_: r.fulfill(status=200, body=""))
    p.route("http://box.test/abonnements.html", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.add_init_script("localStorage.setItem('sbx_token','JETON')")
    p.goto("http://box.test/abonnements.html")
    p.wait_for_selector("#lignes tr")
    return p, erreurs


def test_une_ligne_par_box_ecart_et_echappement(navigateur):
    appels = []
    p, erreurs = ouvre(navigateur, appels)
    assert p.locator("#lignes tr").count() == 2
    assert "appliqué : lite · formule : distante" in p.locator("#lignes").inner_text()
    assert p.evaluate("window.__pwn") is None and not erreurs
    assert p.locator("#tEcart").inner_text() == "1"
    appliquer = p.get_by_role("button", name="Appliquer distante")
    assert appliquer.is_disabled() and "3302" in appliquer.get_attribute("title")
    assert "€" not in p.content() and "prix" not in p.content().lower()


def test_suspendre_vise_une_seule_box_avec_motif(navigateur):
    appels = []
    p, _ = ouvre(navigateur, appels)
    p.locator("#lignes tr").first.get_by_role("button", name="Suspendre").click()
    assert "Cette box seule" in p.locator("#conf").inner_text()
    p.locator("#confForm input").fill("impayé")
    p.locator("#confOui").click()
    p.wait_for_selector("#retour:not([hidden])")
    assert ("POST", "/boxes/1/abonnement/suspendre", {"motif": "impayé"}) in appels


def test_revoquer_envoie_la_confirmation_saisie(navigateur):
    appels = []
    p, _ = ouvre(navigateur, appels)
    p.locator("#lignes tr").first.get_by_role("button", name="Révoquer").click()
    entrees = p.locator("#confForm input")
    entrees.nth(0).fill("fin de contrat")
    entrees.nth(1).fill("SN-GK5")
    p.locator("#confOui").click()
    p.wait_for_selector("#retour:not([hidden])")
    assert ("POST", "/boxes/1/abonnement/revoquer", {"motif": "fin de contrat", "confirmation": "SN-GK5"}) in appels
