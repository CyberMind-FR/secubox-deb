# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2255 : la carte « Mes comptes » du Hall affiche PhotoPrism, ouvert d'office par OIDC, même sans lien sbxid (un compte OIDC se crée à la
première connexion) — et jamais deux fois s'il en existait un."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
CARTE = Path(__file__).resolve().parents[1] / "www" / "hall" / "cardlets" / "comptes.html"


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, moi, statut=200):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    p.route("http://hall.exemple.test/api/v1/sbxid/moi", lambda r: r.fulfill(status=statut, content_type="application/json", body=json.dumps(moi)))
    p.route("http://hall.exemple.test/hall/**", lambda r: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://hall.exemple.test/c.html", lambda r: r.fulfill(status=200, content_type="text/html", body=CARTE.read_text(encoding="utf-8")))
    p.goto("http://hall.exemple.test/c.html")
    return ctx, p


def liens(p):
    return {a.get_attribute("href"): a.inner_text() for a in p.locator("a.cpt").all()}


def test_photoprism_apparait_meme_sans_lien_et_ouvre_par_l_entree_oidc(navigateur):
    ctx, p = ouvre(navigateur, {"identite": {"pseudo": "gek"}, "liens": [{"app": "nextcloud", "app_handle": "gek"}]})
    p.wait_for_selector("a.cpt")
    h = liens(p)
    assert "https://photoprism.exemple.test/api/v1/oidc/login" in h and "PhotoPrism" in h["https://photoprism.exemple.test/api/v1/oidc/login"]
    assert any("nc.exemple.test" in k for k in h)                       # les comptes liés restent
    ctx.close()


def test_une_personne_sans_aucun_lien_voit_quand_meme_les_services_oidc(navigateur):
    ctx, p = ouvre(navigateur, {"identite": {"pseudo": "gek"}, "liens": []})
    p.wait_for_selector("a.cpt")
    assert "https://photoprism.exemple.test/api/v1/oidc/login" in liens(p)
    ctx.close()


def test_sans_identite_pas_de_service_oidc_affiche(navigateur):
    ctx, p = ouvre(navigateur, {"identite": None, "liens": []})
    p.wait_for_selector(".vide")
    assert p.locator("a.cpt").count() == 0
    ctx.close()
