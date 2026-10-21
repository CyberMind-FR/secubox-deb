# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 — Hall « vue maître », phase 1 : jetons --sbx-*, coque (sidebar / topbar / barre basse), flag hall.v2.

L'ancien Hall reste le rendu par défaut ; la coque v2 ne s'active que par le flag de la box ou, pour la prévisualisation,
par `?hall=v2`. Les trois largeurs de la maquette (1440 / 834 / 390) sont rendues dans Chromium, et les captures sont
déposées dans le dossier `SBX_CAPTURES` quand il est donné.
"""
import mimetypes
import os
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import api.main as m

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"
SRC = (HALL_DIR / "index.html").read_text(encoding="utf-8")
TOKENS = (HALL_DIR / "tokens.css").read_text(encoding="utf-8")
COQUE = (HALL_DIR / "hall-v2.css").read_text(encoding="utf-8")
JS = (HALL_DIR / "hall-v2.js").read_text(encoding="utf-8")
RULES = (PKG / "debian" / "rules").read_text(encoding="utf-8")

PALETTE = {
    "--sbx-fond": "#070C1C", "--sbx-surface": "#0F1830", "--sbx-surface-2": "#0A1226",
    "--sbx-bordure": "#243457", "--sbx-bordure-2": "#1B2745",
    "--sbx-texte": "#E8EEFB", "--sbx-texte-attenue": "#8A9BC3",
    "--sbx-accent": "#2563EB", "--sbx-accent-2": "#60A5FA",
    "--sbx-ok": "#4ADE80", "--sbx-warn": "#FBBF24", "--sbx-off": "#FCA5A5", "--sbx-info": "#93C5FD",
    "--sbx-ok-fond": "#0F2E24", "--sbx-warn-fond": "#3A2A0C", "--sbx-off-fond": "#3B1A1A", "--sbx-info-fond": "#172554",
}


def _bloc(css, selecteur):
    i = css.index(selecteur)
    return css[css.index("{", i) + 1:css.index("}", i)]


# ── Fichiers, en-têtes, paquet ──────────────────────────────────────────────

def test_fichiers_sous_licence_et_installes():
    for nom in ("tokens.css", "hall-v2.css", "hall-v2.js"):
        assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in (HALL_DIR / nom).read_text(encoding="utf-8")
        assert f"www/hall/{nom} $(CURDIR)/debian/secubox-webos/usr/share/secubox/www/hall/{nom}" in RULES, nom


def test_index_charge_la_coque_sans_dependance_nouvelle():
    assert '<link rel="stylesheet" href="/tokens.css">' in SRC
    assert '<link rel="stylesheet" href="/hall-v2.css">' in SRC
    assert '<script src="/hall-v2.js" defer></script>' in SRC
    assert not re.findall(r'<(?:script|link)\b[^>]*(?:src|href)="(?:https?:)?//', SRC)
    # le choix v1/v2 est reposé AVANT tout rendu, comme le thème (anti-flash)
    tete = SRC.split("</head>", 1)[0]
    assert "sbx.hall.v2" in tete and 'data-hall' in tete


def test_budget_css_de_la_coque_sous_60_ko():
    assert (HALL_DIR / "tokens.css").stat().st_size + (HALL_DIR / "hall-v2.css").stat().st_size < 60 * 1024


# ── Jetons ──────────────────────────────────────────────────────────────────

def test_palette_du_brief_dans_les_jetons_sombres():
    racine = _bloc(TOKENS, ":root{")
    for jeton, valeur in PALETTE.items():
        assert re.search(re.escape(jeton) + r"\s*:\s*" + re.escape(valeur) + r"\s*;", racine, re.I), jeton
    for jeton in ("--sbx-rayon-s:10px", "--sbx-rayon-m:12px", "--sbx-rayon-l:16px",
                  "--sbx-e-1:4px", "--sbx-e-2:8px", "--sbx-e-3:12px", "--sbx-e-4:16px"):
        assert jeton.replace(":", ":") in racine.replace(" ", ""), jeton
    assert re.search(r"--sbx-police\s*:\s*Inter", racine) and re.search(r"--sbx-mono\s*:\s*\"JetBrains Mono\"", racine)


def test_theme_clair_ne_redefinit_que_des_jetons():
    clair = _bloc(TOKENS, ':root[data-theme="light"]')
    lignes = [x.strip() for x in clair.replace("\n", ";").split(";") if x.strip() and not x.strip().startswith("/*")]
    for ligne in lignes:
        assert ligne.startswith("--sbx-") or ligne.startswith("color-scheme"), ligne
    # chaque jeton de couleur du sombre a sa valeur claire
    for jeton in PALETTE:
        assert jeton + ":" in clair.replace(" ", ""), jeton
    # pas de règle de composant dupliquée sous le thème clair
    assert '[data-theme="light"] .' not in TOKENS and '[data-theme="light"] .' not in COQUE


def test_les_anciens_noms_du_hall_sont_rebranches_sur_les_jetons_en_v2_seulement():
    pont = _bloc(TOKENS, ':root[data-hall="v2"]{')
    for ancien, nouveau in (("--fond", "--sbx-fond"), ("--texte", "--sbx-texte"), ("--doux", "--sbx-texte-attenue"),
                            ("--trait", "--sbx-bordure"), ("--panel", "--sbx-surface"), ("--vert", "--sbx-ok"),
                            ("--orange", "--sbx-warn"), ("--rouge", "--sbx-off"), ("--police", "--sbx-police")):
        assert re.search(re.escape(ancien) + r"\s*:\s*var\(" + re.escape(nouveau) + r"\)", pont), ancien
    # hors v2, rien ne change : le :root de tokens.css ne touche aucun ancien nom
    racine = _bloc(TOKENS, ":root{")
    assert not re.search(r"(^|[;\s])--(fond|texte|trait|panel|police)\s*:", racine)


def test_points_de_rupture_du_brief():
    for bp in ("1180px", "980px", "720px"):
        assert f"@media(max-width:{bp})" in COQUE.replace(" ", ""), bp
    assert "flex:999 1 560px" in COQUE.replace("  ", " ")
    assert "min-width:0" in COQUE.replace(" ", "")


# ── API : le flag est lisible publiquement ────────────────────────────────────

def test_etat_public_expose_le_flag_et_la_version(monkeypatch):
    monkeypatch.setattr(m, "_flags", {"enabled": True, "registry_enabled": True, "hall_v2": True})
    monkeypatch.setattr(m, "_version", "1.15.0-1~bookworm1")
    r = TestClient(m.app).get("/public/etat")
    assert r.status_code == 200
    assert r.json() == {"hall_v2": True, "version": "1.15.0-1~bookworm1", "en_ligne": True}


def test_etat_public_sans_flag_reste_v1(monkeypatch):
    monkeypatch.setattr(m, "_flags", {"enabled": False, "registry_enabled": True, "hall_v2": False})
    monkeypatch.setattr(m, "_version", "")
    assert TestClient(m.app).get("/public/etat").json()["hall_v2"] is False


# ── Rendu (Playwright) ─────────────────────────────────────────────────────

playwright = pytest.importorskip("playwright.sync_api")
CAPTURES = os.environ.get("SBX_CAPTURES")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, largeur, v2=True, hall_v2_box=False, theme="dark"):
    ctx = nav.new_context(viewport={"width": largeur, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json",
                             body='{"hall_v2": %s, "version": "1.15.0-1~bookworm1", "en_ligne": true}' % ("true" if hall_v2_box else "false"))
        if u.startswith("/api/"):
            return r.fulfill(status=401, content_type="application/json", body="{}")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.add_init_script("try{localStorage.setItem('sbx.hall.invit-.theme','%s');localStorage.setItem('sbx.hall.anonyme.theme','%s')}catch(e){}" % (theme, theme))
    p.goto("http://sbx.test/" + ("?hall=v2" if v2 else ""))
    p.wait_for_selector(".fcard", state="attached")
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    return ctx, p, erreurs


def capture(p, nom):
    if CAPTURES:
        Path(CAPTURES).mkdir(parents=True, exist_ok=True)
        p.screenshot(path=str(Path(CAPTURES) / f"{nom}.png"), full_page=False)


def test_sans_flag_le_hall_v1_est_intact(nav):
    ctx, p, erreurs = ouvre(nav, 1440, v2=False)
    assert p.evaluate("document.documentElement.getAttribute('data-hall')") is None
    assert p.evaluate("document.querySelector('.sbx-side')") is None
    assert p.evaluate("getComputedStyle(document.querySelector('.mast')).position") == "sticky"
    assert erreurs == []
    ctx.close()


def test_le_flag_de_la_box_active_la_coque_sans_parametre(nav):
    ctx, p, erreurs = ouvre(nav, 1440, v2=False, hall_v2_box=True)
    p.wait_for_selector("html[data-hall='v2'] .sbx-side", state="attached")
    assert erreurs == []
    ctx.close()


def test_bureau_1440_sidebar_220_et_zone_principale(nav):
    ctx, p, erreurs = ouvre(nav, 1440)
    capture(p, "hall-v2-1440")
    assert p.evaluate("document.documentElement.getAttribute('data-hall')") == "v2"
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    side = p.evaluate("(()=>{const r=document.querySelector('.sbx-side').getBoundingClientRect();return [r.width,r.height]})()")
    assert round(side[0]) == 220 and side[1] > 400
    # les rubriques du brief, en vrais boutons, au clavier
    libelles = p.evaluate("[...document.querySelectorAll('.sbx-side nav button, .sbx-side nav a')].map(e=>e.textContent.trim())")
    for lib in ("Accueil", "Tableau de bord", "Réseau", "Sécurité", "Modules", "Stockage", "Média", "Communication", "IA", "Outils", "Système"):
        assert lib in libelles, lib
    assert p.evaluate("!!document.querySelector('.sbx-side .sbx-favoris')")
    assert p.evaluate("!!document.querySelector('.sbx-side .sbx-usager')")
    # topbar : menu, recherche, disposition, notifications, thème, pastille version
    for sel in ("#sbx-menu", "#q", "#sbx-dispo", "#sbx-notif", "#theme", "#sbx-version"):
        assert p.evaluate("(()=>{const e=document.querySelector('%s');return !!e&&getComputedStyle(e).display!=='none'})()" % sel), sel
    assert "1.15.0" in p.inner_text("#sbx-version") and "En ligne" in p.inner_text("#sbx-version")
    assert p.evaluate("getComputedStyle(document.querySelector('.sbx-tabbar')).display") == "none"
    # zone principale : flex 999 1 560px, min-width 0
    assert p.evaluate("getComputedStyle(document.querySelector('.shell')).flexGrow") == "999"
    assert p.evaluate("getComputedStyle(document.querySelector('.shell')).minWidth") == "0px"
    # contraste texte / fond ≥ 4,5:1 (brief)
    texte, fond = p.evaluate("[getComputedStyle(document.body).color, getComputedStyle(document.body).backgroundColor]")
    assert contraste(texte, fond) >= 4.5
    assert erreurs == []
    ctx.close()


def test_tablette_834_rail_horizontal_sans_favoris(nav):
    ctx, p, erreurs = ouvre(nav, 834)
    capture(p, "hall-v2-834")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    w, h = p.evaluate("(()=>{const r=document.querySelector('.sbx-side').getBoundingClientRect();return [r.width,r.height]})()")
    assert w > 600 and h < 120, (w, h)
    assert p.evaluate("getComputedStyle(document.querySelector('.sbx-side .sbx-favoris')).display") == "none"
    assert p.evaluate("getComputedStyle(document.querySelector('.sbx-tabbar')).display") == "none"
    # en colonne, la zone principale prend toute la largeur (régression : .shell réduit à 652 px)
    assert p.evaluate("document.querySelector('.main').getBoundingClientRect().width") >= 834 - 2
    assert erreurs == []
    ctx.close()


def test_mobile_390_barre_basse_et_cibles_tactiles(nav):
    ctx, p, erreurs = ouvre(nav, 390)
    capture(p, "hall-v2-390")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert p.evaluate("getComputedStyle(document.querySelector('.sbx-side')).display") == "none"
    tab = p.evaluate("getComputedStyle(document.querySelector('.sbx-tabbar'))['position']")
    assert tab == "fixed"
    onglets = p.evaluate("[...document.querySelectorAll('.sbx-tabbar button')].map(b=>[b.textContent.trim(),b.getBoundingClientRect().height,b.getBoundingClientRect().width])")
    assert [o[0] for o in onglets] == ["Accueil", "Modules", "Sécurité", "Réseau", "Système"]
    for nom, h, w in onglets:
        assert h >= 44 and w >= 44, (nom, h, w)
    assert p.evaluate("parseFloat(getComputedStyle(document.querySelector('.main')).paddingBottom)") >= 88
    # un onglet navigue réellement (Système = vue du parc)
    p.click(".sbx-tabbar button[data-nav='systeme']")
    assert not p.evaluate("document.getElementById('view-systeme').classList.contains('hidden')")
    assert erreurs == []
    ctx.close()


def test_le_menu_ouvre_la_sidebar_en_tiroir_sur_mobile(nav):
    ctx, p, erreurs = ouvre(nav, 390)
    p.click("#sbx-menu")
    assert p.evaluate("getComputedStyle(document.querySelector('.sbx-side')).display") != "none"
    assert p.evaluate("document.getElementById('sbx-menu').getAttribute('aria-expanded')") == "true"
    p.keyboard.press("Escape")
    assert p.evaluate("getComputedStyle(document.querySelector('.sbx-side')).display") == "none"
    assert erreurs == []
    ctx.close()


def test_theme_clair_en_v2_garde_le_contraste(nav):
    ctx, p, erreurs = ouvre(nav, 1440, theme="light")
    assert p.evaluate("document.documentElement.getAttribute('data-theme')") == "light"
    texte, fond = p.evaluate("[getComputedStyle(document.body).color, getComputedStyle(document.body).backgroundColor]")
    assert contraste(texte, fond) >= 4.5
    att, surf = p.evaluate("(()=>{const s=getComputedStyle(document.documentElement);return [s.getPropertyValue('--sbx-texte-attenue').trim(), s.getPropertyValue('--sbx-surface').trim()]})()")
    assert contraste(att, surf) >= 4.5
    assert erreurs == []
    ctx.close()


def test_carte_d_usager_avatar_et_liens_avec_identite(nav):
    ctx = nav.new_context(viewport={"width": 1440, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    image = (HALL_DIR / "dice" / "face-5.jpg").read_bytes()

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/api/v1/sbxid/moi":
            return r.fulfill(status=200, content_type="application/json", body='{"identite": {"pseudo": "gek"}, "liens": []}')
        if u == "/api/v1/avatar/par-nom/gek":
            return r.fulfill(status=200, content_type="image/jpeg", body=image)
        if u == "/api/v1/webos/public/services":
            return r.fulfill(status=200, content_type="application/json",
                             body='{"services": [{"id": "avatar", "name": "Avatar", "category": "mesh", "health": {"state": "online"}}], "computed_at": 1}')
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.15.0-1", "en_ligne": true}')
        if u.startswith("/api/"):
            return r.fulfill(status=401, content_type="application/json", body="{}")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.goto("http://sbx.test/?hall=v2")
    p.wait_for_selector(".sbx-usager .av img", state="attached")
    assert p.evaluate("document.querySelector('.sbx-usager .av img').src").endswith("/api/v1/avatar/par-nom/gek")
    assert p.evaluate("!!document.querySelector('#who .av img')")
    assert not p.evaluate("document.querySelector('.sbx-usager-liens').hidden")
    libelles = p.evaluate("[...document.querySelectorAll('.sbx-usager-liens .sbx-rub')].map(e=>e.textContent.trim())")
    assert libelles == ["Mes comptes", "Mon identité"]
    assert p.evaluate("document.querySelector('.sbx-usager-liens [data-open]').getAttribute('data-open')") == "comptes"
    assert p.evaluate("document.querySelector('.sbx-usager-liens a').getAttribute('href')") == "/identite/"
    assert erreurs == []
    ctx.close()


def test_sans_identite_initiales_et_liens_caches(nav):
    ctx, p, erreurs = ouvre(nav, 1440)
    p.wait_for_timeout(300)
    assert p.evaluate("!document.querySelector('.sbx-usager .av img')")
    assert p.inner_text(".sbx-usager .av") == "IN"
    assert p.evaluate("document.querySelector('.sbx-usager-liens').hidden")
    assert erreurs == []
    ctx.close()


def _lum(rgb):
    def c(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = rgb
    return 0.2126 * c(r) + 0.7152 * c(g) + 0.0722 * c(b)


def _rgb(css):
    css = css.strip()
    if css.startswith("#"):
        return [int(css[i:i + 2], 16) for i in (1, 3, 5)]
    return [float(x) for x in re.findall(r"[\d.]+", css)[:3]]


def contraste(a, b):
    la, lb = sorted([_lum(_rgb(a)), _lum(_rgb(b))], reverse=True)
    return (la + 0.05) / (lb + 0.05)
