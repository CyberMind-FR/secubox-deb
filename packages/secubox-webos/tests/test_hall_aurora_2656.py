# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2656 — la coque du Hall au profil Aurora : jetons, thème conservé, CSP, rendu 1400/420 px (réseau simulé)."""
import mimetypes
import re
from pathlib import Path

import pytest

HALL_DIR = Path(__file__).resolve().parents[1] / "www" / "hall"
SRC = (HALL_DIR / "index.html").read_text(encoding="utf-8")
STYLE = SRC.split("<style>", 1)[1].split("</style>", 1)[0]


def test_en_tete_spdx_et_doctype_en_premier():
    assert SRC.startswith("<!DOCTYPE html>")
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC


def test_jetons_aurora_presents():
    for jeton in ("--fond:#060d1b", "--trait:rgba(86,150,255,.22)", "--trait2:rgba(86,150,255,.38)", "--texte:#eaf1ff",
                  "--doux:#9fb3d6", "--faible:#6f84a8", "--cyan:#29b6f6", "--bleu:#3b82f6", "--vert:#2ecc71",
                  "--rouge:#ff4d5e", "--orange:#ff9f1c", "--violet:#a78bfa", "--jaune:#ffd23f"):
        assert jeton in STYLE, jeton
    assert '"IBM Plex Sans","Inter"' in STYLE
    assert "radial-gradient(1200px 520px at 85% -10%,rgba(59,130,246,.2)" in STYLE
    assert not re.findall(r'font-family:[^;}]*(?:Fraunces|Cinzel)', STYLE) and "@font-face{font-family:\"Fraunces\"" not in STYLE


def test_anciens_noms_de_jetons_conserves_pour_le_js_et_les_regles():
    for nom in ("--ink", "--paper", "--panel", "--line", "--soft", "--dim", "--coral", "--mint", "--sky", "--nav"):
        assert re.search(re.escape(nom) + r":", STYLE), nom


def test_selecteur_de_theme_conserve():
    assert 'id="theme"' in SRC
    assert ':root[data-theme="light"]' in STYLE                 # variante claire sobre
    assert "root.setAttribute('data-theme', suivant)" in SRC     # la bascule existe toujours
    assert "setAttribute(\"data-theme\",\"dark\")" in SRC        # sombre par défaut (Aurora)


def test_aucune_ressource_externe():
    assert not re.findall(r'<(?:script|img|link|source)\b[^>]*(?:src|href)="(?:https?:)?//', SRC)
    assert "@import" not in STYLE
    assert not re.findall(r"url\(\s*['\"]?https?://", STYLE)
    for f in re.findall(r'url\("(/fonts/[^"]+)"\)', STYLE):
        assert (HALL_DIR / f.lstrip("/")).is_file(), f


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, largeur, theme):
    ctx = nav.new_context(viewport={"width": largeur, "height": 860}, color_scheme="light")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u.startswith("/api/"):
            return r.fulfill(status=401, content_type="application/json", body="{}")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.add_init_script("try{localStorage.setItem('sbx.hall.invit-.theme','%s');localStorage.setItem('sbx.hall.anonyme.theme','%s')}catch(e){}" % (theme, theme))
    p.goto("http://sbx.test/")
    p.wait_for_selector(".fcard", state="attached")
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    return ctx, p, erreurs


def lum(rgb):
    def c(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = rgb
    return 0.2126 * c(r) + 0.7152 * c(g) + 0.0722 * c(b)


def rgb_de(css):
    return [float(x) for x in re.findall(r"[\d.]+", css)[:3]]


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("largeur", [1400, 420])
def test_rendu_sans_debordement_contraste_et_cartes_encadrees(nav, largeur, theme):
    ctx, p, erreurs = ouvre(nav, largeur, theme)
    assert p.evaluate("document.documentElement.getAttribute('data-theme')") == theme
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    # contraste du texte principal sur le fond Aurora
    texte, fond = p.evaluate("[getComputedStyle(document.body).color, getComputedStyle(document.documentElement).getPropertyValue('--fond').trim()]")
    if fond.startswith("#"):
        fond = "rgb(%d,%d,%d)" % tuple(int(fond[i:i + 2], 16) for i in (1, 3, 5))
    a, b = sorted([lum(rgb_de(texte)), lum(rgb_de(fond))], reverse=True)
    assert (a + 0.05) / (b + 0.05) >= 7, (texte, fond)
    # les cartes restent encadrées d'un trait visible
    cartes = p.evaluate("""[...document.querySelectorAll('.fcard')].map(e=>{const s=getComputedStyle(e);return [s.borderTopWidth,s.borderTopStyle,s.borderTopColor]})""")
    assert cartes
    for w, st, col in cartes:
        assert w == "1px" and st == "solid" and not col.endswith(", 0)")
    if theme == "dark":
        assert p.evaluate("getComputedStyle(document.body).backgroundImage").count("radial-gradient") == 2
    assert erreurs == []
    ctx.close()


def test_la_bascule_de_theme_fonctionne(nav):
    ctx, p, _ = ouvre(nav, 1400, "dark")
    p.click("#theme")
    assert p.evaluate("document.documentElement.getAttribute('data-theme')") == "light"
    p.click("#theme")
    assert p.evaluate("document.documentElement.getAttribute('data-theme')") == "dark"
    ctx.close()


def test_defaut_sombre_meme_si_le_systeme_est_clair(nav):
    ctx = nav.new_context(viewport={"width": 900, "height": 700}, color_scheme="light")
    p = ctx.new_page()
    p.route("http://sbx.test/**", lambda r: r.fulfill(status=200, content_type="text/html", body=SRC) if r.request.url.rstrip("/").endswith("sbx.test") else r.fulfill(status=404, body=""))
    p.goto("http://sbx.test/")
    assert p.evaluate("document.documentElement.getAttribute('data-theme')") == "dark"
    ctx.close()
