# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Panneau d'administration Audio Mood au profil Aurora (#3026) : contrat statique, rendu démo et à vide."""
import re
from pathlib import Path

import pytest

ADMIN = Path(__file__).resolve().parents[1] / "admin"
HTML = (ADMIN / "index.html").read_text(encoding="utf-8")
JS = (ADMIN / "admin.js").read_text(encoding="utf-8")


def test_licence_spdx_et_attribut_hidden_force():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in HTML and "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in JS
    assert "[hidden]{display:none!important}" in HTML.replace(" ", "")


def test_page_sans_skin_ni_police_distante_script_a_part_pour_la_csp():
    srcs = re.findall(r'<(?:script|link)[^>]+(?:src|href)="([^"]+)"', HTML)
    assert srcs == ["admin.js"], srcs                      # la CSP de la route refuse le script en ligne ; rien d'autre
    assert "hybrid-skin.css" not in HTML and "fonts.googleapis.com" not in HTML
    assert "/shared/sidebar.js" in JS and "!EMBED && !DEMO" in JS
    assert "100vh" not in HTML


def test_hauteur_demo_et_session():
    assert "sbxVue" in JS and "onglet: 'audio-mood'" in JS and "location.origin" in JS
    assert "DONNÉES DE DÉMONSTRATION" in HTML and "demo" in JS and "embed" in JS
    assert "session administrateur requise" in HTML.lower()


def test_actions_conservees_a_l_identique_sans_dialogue_du_navigateur():
    assert "const API = '/api/mood/admin'" in JS
    assert "api('/etat')" in JS
    assert "api('/reglages', { method: 'POST', body: JSON.stringify(corps) })" in JS
    assert "api('/purge', { method: 'POST', body: JSON.stringify({ quoi }) })" in JS
    assert "historique: $('r-historique').checked" in JS and "memoire_voix: $('r-memoire').checked" in JS and "retention_jours: parseInt" in JS
    assert "purge('retention'" in JS and "purge('tout'" in JS
    for interdit in ("confirm(", "alert(", "prompt("):
        assert interdit not in JS, interdit
    assert 'id="c-tout"' in HTML and "DELETE" not in JS


def test_ni_lorem_ni_chiffre_invente():
    assert "lorem" not in HTML.lower()
    assert "new Array(24).fill(0)" in JS           # sans série : barres vides, pas une courbe inventée


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _ouvre(nav, largeur, suffixe):
    ctx = nav.new_context(viewport={"width": largeur, "height": 900})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.goto((ADMIN / "index.html").as_uri() + suffixe)
    p.wait_for_timeout(400)
    return ctx, p, erreurs


@pytest.mark.parametrize("largeur", [1400, 420])
def test_rendu_en_demonstration_sans_debordement(nav, largeur):
    ctx, p, erreurs = _ouvre(nav, largeur, "?demo=1")
    assert p.inner_text("#pastille") == "HISTORIQUE 30 J"
    assert p.inner_text("#tMinutes") == "3 184"
    assert p.locator("#barres rect").count() == 24
    assert p.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
    assert not p.is_hidden("#demo") and p.is_hidden("#session")
    p.click("#b-tout")
    assert not p.is_hidden("#c-tout")
    p.click("#c-tout-oui")
    assert "Démonstration" in p.inner_text("#m-purge")
    assert erreurs == []
    ctx.close()


def test_rendu_a_vide_sans_session(nav):
    ctx, p, erreurs = _ouvre(nav, 1000, "")
    assert p.inner_text("#tMinutes") == "—" and p.inner_text("#tSessions") == "—"
    assert p.inner_text("#pastille") in ("HORS LIGNE", "SESSION REQUISE")
    assert erreurs == []
    ctx.close()
