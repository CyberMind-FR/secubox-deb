# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2613 — /acces/ s'integre a la navigation systeme (barre du haut et menu de gauche communs).

Ouverte directement, la page n'avait ni la barre du haut ni le menu de gauche des autres panneaux. Encadree (iframe du Hall, /i/acces/) ou avec ?embed=1,
elle doit RESTER sans menu : deux menus imbriques seraient pires que pas de menu."""
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
DIR = Path(__file__).resolve().parents[1] / "acces" / "www" / "acces"
TYPES = {".html": "text/html", ".js": "application/javascript", ".css": "text/css"}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, url, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    demandes = []
    p.on("request", lambda r: demandes.append(r.url))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin == "parent":
            r.fulfill(status=200, content_type="text/html", body='<iframe id="f" src="/acces/" style="width:1200px;height:800px"></iframe>')
        elif chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.startswith("acces/"):
            f = DIR / (chemin[len("acces/"):] or "index.html")
            if f.is_file():
                r.fulfill(status=200, content_type=TYPES.get(f.suffix, "text/plain"), body=f.read_text(encoding="utf-8"))
            else:
                r.fulfill(status=404, body="")
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    p.route("http://sbx.test/api/**", lambda r, *_: r.fulfill(status=401, content_type="application/json", body="{}"))
    p.goto(url)
    p.wait_for_timeout(400)
    return ctx, p, demandes


def test_ouverte_directement_elle_porte_le_menu_et_decale_son_contenu(navigateur):
    ctx, p, demandes = ouvre(navigateur, "http://sbx.test/acces/")
    assert p.locator("nav#sidebar.sidebar").count() == 1
    assert any(u.endswith("/shared/sidebar.js") for u in demandes)
    assert p.evaluate("getComputedStyle(document.querySelector('.cadre')).marginLeft") == "220px"
    ctx.close()


def test_avec_embed_ni_menu_ni_decalage(navigateur):
    ctx, p, demandes = ouvre(navigateur, "http://sbx.test/acces/?embed=1")
    assert p.locator("nav#sidebar").count() == 0
    assert not any(u.endswith("/shared/sidebar.js") for u in demandes)
    assert p.evaluate("getComputedStyle(document.querySelector('.cadre')).marginLeft") != "220px"
    ctx.close()


def test_encadree_dans_une_iframe_ni_menu_ni_decalage(navigateur):
    ctx, p, demandes = ouvre(navigateur, "http://sbx.test/parent")
    f = p.frame_locator("#f")
    f.locator(".cadre").wait_for()
    assert f.locator("nav#sidebar").count() == 0
    assert not any(u.endswith("/shared/sidebar.js") for u in demandes)
    ctx.close()


def test_sur_telephone_le_menu_ne_decale_plus_le_contenu(navigateur):
    ctx, p, _ = ouvre(navigateur, "http://sbx.test/acces/", taille={"width": 420, "height": 800})
    assert p.evaluate("getComputedStyle(document.querySelector('.cadre')).marginLeft") != "220px"
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    ctx.close()
