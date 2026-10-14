# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2687 — /portal/login.html (hub) au profil Aurora : simple relais vers /login.html, que possède secubox-portal (#1064)."""
import re
from pathlib import Path

import pytest

HUB = Path(__file__).resolve().parents[1]
PAGE = HUB / "www" / "portal" / "login.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_formulaire_ni_jeton():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert not re.search(r"<script[^>]+src=", SRC) and "fonts.googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "<form", "<input", "fetch(", "localStorage", "sbx_token", "sidebar"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()


def test_cible_fixe_et_requete_fragment_reportes():
    assert "window.location.replace('/login.html' + window.location.search + window.location.hash)" in SRC
    assert 'content="0;url=/login.html"' in SRC


def test_le_hub_ne_livre_pas_le_login_racine():
    # #1064 : /login.html appartient à secubox-portal ; un login.html à la racine du hub écraserait sa page TOTP
    assert not (HUB / "www" / "login.html").exists()
    assert (HUB / "www" / "portal" / "login.html").exists()


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, url, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1000, "height": 800})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test", 1)[1].split("?")[0].split("#")[0]
        if chemin == "/portal/login.html":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=200, content_type="text/html", body="<html><body id='cible'>connexion</body></html>")
    p.route("http://sbx.test/**", fichier)
    p.goto(url)
    return ctx, p, erreurs


def test_relais_conserve_requete_et_fragment(navigateur):
    ctx, p, err = ouvre(navigateur, "http://sbx.test/portal/login.html?redirect=/soc/&deconnexion=1#elevation=" + "B" * 44)
    p.wait_for_selector("#cible", state="attached")
    assert p.evaluate("location.pathname") == "/login.html"
    assert p.evaluate("location.search") == "?redirect=/soc/&deconnexion=1"
    assert p.evaluate("location.hash") == "#elevation=" + "B" * 44 and err == []
    ctx.close()


def test_relais_sans_parametre(navigateur):
    ctx, p, err = ouvre(navigateur, "http://sbx.test/portal/login.html")
    p.wait_for_selector("#cible", state="attached")
    assert p.url == "http://sbx.test/login.html" and err == []
    ctx.close()


def test_relais_ne_peut_pas_sortir_de_l_hote(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/portal/login.html?redirect=//evil.example/")
    p.wait_for_selector("#cible", state="attached")
    assert p.evaluate("location.host") == "sbx.test" and p.evaluate("location.pathname") == "/login.html"
    ctx.close()


def test_rendu_et_telephone_sans_debordement(navigateur):
    ctx = navigateur.new_context(viewport={"width": 420, "height": 800})
    p = ctx.new_page()
    # on fige la page (sans le script ni le rafraîchissement) pour mesurer le rendu du relais
    figee = re.sub(r"<script>.*?</script>", "", SRC, flags=re.S)
    figee = re.sub(r"<noscript><meta[^>]*></noscript>", "", figee)
    p.set_content(figee.replace("<noscript><p>", "<div><p>").replace("</p></noscript>", "</p></div>"))
    assert p.is_visible("main.app") and p.get_by_role("link", name="Ouvrir la page de connexion").count() == 1
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth")
    ctx.close()
