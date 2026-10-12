# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2485 — /apercu/ au profil Aurora : page autonome, démonstration, valeurs en texte brut, tuiles calculées sur les données lues."""
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "apercu" / "index.html"


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _demo(navigateur):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs, natifs = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
    p.goto("file://" + str(PAGE) + "?demo=1")
    p.wait_for_selector("#espaces .carte")
    return ctx, p, erreurs, natifs


def test_page_autonome_sans_feuille_ni_script_separes_et_sans_boite_native():
    src = PAGE.read_text(encoding="utf-8")
    assert "apercu.css" not in src and "apercu.js" not in src and "hybrid-dark" not in src
    assert not (PAGE.parent / "apercu.css").exists() and not (PAGE.parent / "apercu.js").exists()
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", src, flags=re.S)).replace("onerror=alert(1)", "")
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])" + f + r"\(", code), f


def test_demo_tuiles_espaces_et_ressources(navigateur):
    ctx, p, erreurs, natifs = _demo(navigateur)
    assert p.locator("#espaces .carte").count() == 5 and p.inner_text("#tEsp") == "5"
    assert p.inner_text("#tAct").replace(" ", " ").replace("\xa0", " ") == "59 / 61" and p.inner_text("#tArr") == "2" and p.inner_text("#tAl") == "2"
    assert "12 j" in p.inner_text("#tUp") and p.is_visible("#demo")
    r = p.inner_text("#ressources")
    assert "31 %" in r and "62 %" in r and "—" in r and "0.84 · 0.71 · 0.66" in r        # disque absent : tiret, pas un zéro
    assert erreurs == [] and natifs == []
    ctx.close()


def test_noms_et_alertes_hostiles_restent_du_texte(navigateur):
    ctx, p, erreurs, natifs = _demo(navigateur)
    assert p.locator("#espaces img, #alertes img").count() == 0 and p.evaluate("window.__xss") is None
    assert "<img src=x onerror=alert(1)>" in p.inner_text("#espaces") and "<img src=x onerror=window.__xss=1>" in p.inner_text("#alertes")
    ctx.close()


def test_les_cartes_menent_a_l_espace_avec_un_identifiant_encode(navigateur):
    ctx, p, _, _ = _demo(navigateur)
    hrefs = p.evaluate("[...document.querySelectorAll('#espaces a.carte')].map(a => a.getAttribute('href'))")
    assert hrefs[0] == "/espace/#protection" and all(h.startswith("/espace/#") for h in hrefs)
    ctx.close()
