# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Page /vault/ au profil Aurora (#3020) : contrat statique, puis rendu réel en démonstration et à vide."""
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "vault" / "index.html"
HTML = PAGE.read_text(encoding="utf-8")


def test_licence_spdx_et_attribut_hidden_force():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in HTML
    assert "[hidden]{display:none!important}" in HTML.replace(" ", "")


def test_page_autonome_sans_skin_ni_ressource_externe():
    srcs = re.findall(r'<(?:script|link)[^>]+(?:src|href)="([^"]+)"', HTML)
    assert srcs == [], srcs                       # CSS et JS en ligne ; sidebar.js injectée par script hors embed
    assert "hybrid-dark.css" not in HTML and "crt-light.css" not in HTML and "sidebar-light.css" not in HTML
    assert "/shared/sidebar.js" in HTML and "!EMBED && !encadre && !DEMO" in HTML
    assert "100vh" not in HTML


def test_hauteur_demo_et_session():
    assert "sbxVue" in HTML and "onglet: 'vault'" in HTML and "location.origin" in HTML
    assert "DONNÉES DE DÉMONSTRATION" in HTML and "demo" in HTML and "embed" in HTML
    assert "session requise" in HTML.lower()


def test_actions_conservees_a_l_identique_et_confirmations_dans_la_page():
    for route in ("'/etat'", "'/serrures/appareil'", "'/secrets'", "'/journal?n=20'",
                  "api('/ouvrir', { method: 'POST'", "api('/sceller', { method: 'POST'",
                  "api('/secrets', { method: 'POST'", "api('/serrures/appareil/preparer', { method: 'POST'",
                  "api('/serrures/appareil', { method: 'POST'"):
        assert route in HTML, route
    assert "'/serrures/appareil/' + encodeURIComponent(id), { method: 'DELETE' }" in HTML
    assert "'/secrets/' + encodeURIComponent(s.c) + '/' + encodeURIComponent(s.n), { method: 'DELETE' }" in HTML
    assert "compartiment: 'box'" in HTML and "genre: 'appareil'" in HTML and "genre: $('secours').checked ? 'secours' : 'phrase'" in HTML
    assert "prf: { evalByCredential" in HTML and "residentKey: 'discouraged'" in HTML
    for interdit in ("confirm(", "alert(", "prompt("):
        assert interdit not in HTML, interdit
    assert 'id="c-sceller"' in HTML and 'id="c-app"' in HTML and 'id="c-sec"' in HTML


def test_ni_lorem_ni_secret_affiche():
    assert "lorem" not in HTML.lower()
    assert "valeurs jamais affichées" in HTML
    assert ".valeur" not in HTML.split("DEMO_SECRETS")[0].split("function rendre")[1]   # le rendu ne lit jamais une valeur


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
    p.goto(PAGE.as_uri() + suffixe)
    p.wait_for_timeout(400)
    return ctx, p, erreurs


@pytest.mark.parametrize("largeur", [1400, 420])
def test_rendu_en_demonstration_sans_debordement(nav, largeur):
    ctx, p, erreurs = _ouvre(nav, largeur, "?demo=1")
    assert p.inner_text("#pastille") == "OUVERT"
    assert p.inner_text("#tSecrets") == "5"
    assert "jwt-secret" in p.inner_text("#secrets") and p.locator("#secrets td").all_inner_texts().count("jwt-secret") == 0
    assert p.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
    assert not p.is_hidden("#demo") and p.is_hidden("#session")
    # Retirer un secret passe par une confirmation dans la page, inerte en démonstration.
    p.click("#secrets button[data-n='jwt-secret']")
    assert not p.is_hidden("#c-sec")
    p.click("#c-sec-oui")
    assert "Démonstration" in p.inner_text("#m-secrets")
    assert erreurs == []
    ctx.close()


def test_rendu_a_vide_sans_session(nav):
    ctx, p, erreurs = _ouvre(nav, 1000, "")
    assert p.inner_text("#tEtat") == "—" and p.inner_text("#tJournal") == "—"
    assert p.inner_text("#pastille") in ("HORS LIGNE", "SESSION REQUISE")
    assert erreurs == []
    ctx.close()
