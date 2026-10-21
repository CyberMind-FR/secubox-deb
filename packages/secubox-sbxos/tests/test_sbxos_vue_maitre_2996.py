# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 — la coquille /sbxos/ au profil de la vue maître : jetons --sbx-* du Hall, thème clair par redéfinition seule,
topbar (marque, salutation, heure, profil), barre basse en icônes SVG qui devient la sidebar au large."""
import mimetypes
import os
import re
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www"
SRC = (WWW / "index.html").read_text(encoding="utf-8")
CSS = (WWW / "ui" / "styles.css").read_text(encoding="utf-8")
CAPTURES = os.environ.get("SBX_CAPTURES")
PALETTE = {"--sbx-fond": "#070C1C", "--sbx-surface": "#0F1830", "--sbx-bordure": "#243457", "--sbx-texte": "#E8EEFB",
           "--sbx-texte-attenue": "#8A9BC3", "--sbx-accent": "#2563EB", "--sbx-accent-2": "#60A5FA", "--sbx-ok": "#4ADE80"}


def _bloc(css, selecteur):
    i = css.index(selecteur)
    return css[css.index("{", i) + 1:css.index("}", i)]


def test_jetons_du_hall_et_theme_clair_par_redefinition_seule():
    racine = _bloc(CSS, ":root {")
    for jeton, valeur in PALETTE.items():
        assert f"{jeton}:{valeur}" in racine.replace(" ", ""), jeton
    for sel in (':root[data-theme="light"]', ':root[data-theme="dark"]', ':root:not([data-theme="dark"])'):
        bloc = _bloc(CSS, sel)
        for ligne in [x.strip() for x in bloc.replace("\n", ";").split(";") if x.strip() and not x.strip().startswith("/*")]:
            assert ligne.startswith("--sbx-") or ligne.startswith("color-scheme"), (sel, ligne)
    # les composants du damier lisent les anciens noms : rebranchés sur les jetons
    for ancien in ("--bord:var(--sbx-bordure-2)", "--encre:var(--sbx-texte)", "--accent:var(--sbx-accent-2)", "--alerte:var(--sbx-off)"):
        assert ancien in CSS.replace(" ", ""), ancien
    assert "Inter" in CSS and "JetBrains Mono" in CSS and "https://" not in CSS


def test_coquille_en_svg_sans_emoji_ni_script_externe():
    coquille = SRC.split("<script type=\"module\">", 1)[0]
    assert not re.search(r"[\U0001F300-\U0001FAFF☀-➿]", coquille.replace("☆", "")), "emoji dans la coquille"
    assert coquille.count('<svg class="sbx-ico"') == 3 and 'class="cube"' in coquille
    assert '<time class="heure" id="heure">' in coquille
    assert re.findall(r'<script[^>]+src="([^"]+)"', SRC) == []
    assert 'content="#070C1C"' in SRC and '"theme_color": "#070C1C"' in (WWW / "manifest.webmanifest").read_text(encoding="utf-8")
    assert "'/sbxos/ui/styles.css'" in (WWW / "offline" / "sw.js").read_text(encoding="utf-8")


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, query="?demo=1", taille=None, theme="dark"):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900}, color_scheme=theme)
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        url = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if url.startswith("/api/"):
            return r.fulfill(status=404, content_type="application/json", body="{}")
        if not url.startswith("/sbxos/"):
            return r.fulfill(status=404, body="")
        f = WWW / (url[len("/sbxos/"):] or "index.html")
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(f.name)[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    p.goto("http://sbx.test/sbxos/" + query)
    p.wait_for_selector("sbx-carlette", state="attached")
    return ctx, p, erreurs


def _lum(rgb):
    def c(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = rgb
    return 0.2126 * c(r) + 0.7152 * c(g) + 0.0722 * c(b)


def contraste(a, b):
    la, lb = sorted([_lum([float(x) for x in re.findall(r"[\d.]+", a)[:3]]), _lum([float(x) for x in re.findall(r"[\d.]+", b)[:3]])], reverse=True)
    return (la + 0.05) / (lb + 0.05)


def test_large_sidebar_de_220_px_topbar_et_horloge(navigateur):
    ctx, p, err = ouvre(navigateur)
    assert round(p.evaluate("document.getElementById('barre').getBoundingClientRect().width")) == 220
    assert p.evaluate("parseFloat(getComputedStyle(document.body).paddingLeft)") == 220
    assert p.evaluate("getComputedStyle(document.querySelector('.mast')).position") == "sticky"
    assert re.fullmatch(r"\d{2}:\d{2}", p.inner_text("#heure"))
    assert p.inner_text("#bonjour").startswith(("Bonjour", "Bonsoir"))
    assert p.evaluate("[...document.querySelectorAll('#barre button')].every(b=>b.querySelector('svg.sbx-ico')&&b.querySelector('span').textContent)")
    texte, fond = p.evaluate("[getComputedStyle(document.body).color, getComputedStyle(document.body).backgroundColor]")
    assert contraste(texte, fond) >= 4.5
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    if CAPTURES:
        p.screenshot(path=str(Path(CAPTURES) / "sbxos-1300.png"))
    assert err == []
    ctx.close()


def test_telephone_barre_basse_44_px_et_theme_clair(navigateur):
    ctx, p, err = ouvre(navigateur, taille={"width": 390, "height": 844})
    assert p.evaluate("getComputedStyle(document.getElementById('barre')).position") == "fixed"
    assert p.evaluate("[...document.querySelectorAll('#barre button')].every(b=>b.getBoundingClientRect().height>=44&&b.getBoundingClientRect().width>=44)")
    assert p.evaluate("parseFloat(getComputedStyle(document.body).paddingBottom)") >= 64
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    if CAPTURES:
        p.screenshot(path=str(Path(CAPTURES) / "sbxos-390.png"))
    p.click("#barre button[data-ecran=reglages]")
    p.select_option("#choix-theme", "clair")
    assert p.get_attribute("html", "data-theme") == "light"
    texte, fond = p.evaluate("[getComputedStyle(document.body).color, getComputedStyle(document.body).backgroundColor]")
    assert contraste(texte, fond) >= 4.5 and fond.startswith("rgb(243")
    assert err == []
    ctx.close()
