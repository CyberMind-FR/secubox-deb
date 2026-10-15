# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2733 — mise en page des pages Aurora dans le cadre de l'administration : marge gauche, centrage, pleine largeur, iPhone.

MESURÉ (2026-10-15, 14 pages Aurora réelles dans /shared/sidebar.js + hybrid-skin, hôte `admin.*`) :
- écran large : contenu de la barre latérale + 50 px à (largeur - 50 px) : plein espace, symétrique, mais 40 px de `hybrid-main` + 10 du cadre ;
- écran étroit (390, 768) : la barre latérale est repliée hors écran mais `<main class="principal hybrid-main">` garde `margin-left: 220px !important`
  (hybrid-skin.css) et 40 px de marge intérieure : le contenu commence à 270 px, l'application tient dans 70 px, la page déborde. La règle mobile de
  sidebar.js ne remettait à zéro que `.main` et `.main-content` ;
- `sidebar.js` passe en mode mobile sur TOUT appareil tactile : sur un iPad large, même décalage de 220 px sans barre ;
- incrustations du Hall (cardlets) en `?embed=1` : 6 px de chaque côté — « pas de marge à gauche » sur un iPhone.

On charge de VRAIES pages du dépôt dans un navigateur et on mesure la géométrie."""
import http.server
import re
import shutil
import threading
from pathlib import Path

import pytest

PAQUETS = Path(__file__).resolve().parents[2]
SHARED = PAQUETS / "secubox-hub" / "www" / "shared"

# Pages Aurora qui chargent le cadre (/shared/sidebar.js) : (chemin servi, source dans le dépôt).
AVEC_CADRE = [
    ("/autoload/index.html", "secubox-autoload/www/autoload/index.html"),
    ("/dpi/index.html", "secubox-dpi/www/dpi/index.html"),
    ("/auth/index.html", "secubox-auth/www/auth/index.html"),
    ("/centers/index.html", "secubox-annuaire/www/centers/index.html"),
]
# Cardlets du Hall : autonomes, incrustées en ?embed=1.
CARDLETS = [
    ("/hall/cardlets/surf.html", "secubox-webos/www/hall/cardlets/surf.html"),
    ("/hall/cardlets/comptes.html", "secubox-webos/www/hall/cardlets/comptes.html"),
    ("/hall/cardlets/cumul.html", "secubox-webos/www/hall/cardlets/cumul.html"),
]

playwright = pytest.importorskip("playwright.sync_api")

LARGEURS_MOBILES = [390, 768]
LARGEURS_LARGES = [1400, 1920]
GOUTTIERE_MIN = 12          # px de chaque côté sur écran étroit : « une marge », pas un liseré


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    racine = tmp_path_factory.mktemp("site")
    shutil.copytree(SHARED, racine / "shared")
    for url, src in AVEC_CADRE + CARDLETS:
        dest = racine / url.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(PAQUETS / src, dest)

    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(racine), **k)

        def do_GET(self):
            if self.path.startswith("/api/"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")
                return
            super().do_GET()

        def log_message(self, *a):
            pass

    # Le Hall incruste une cardlet dans une iframe : certaines (cumul) ne se règlent qu'ainsi, pas sur le seul paramètre ?embed=1.
    (racine / "__hall__.html").write_text("<!doctype html><meta charset=utf-8><body style='margin:0'><script>"
                                          "var q=new URLSearchParams(location.search);var f=document.createElement('iframe');"
                                          "f.src=q.get('u');f.style.cssText='border:0;display:block;width:'+q.get('w')+'px;height:700px';document.body.appendChild(f);</script>")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_port
    srv.shutdown()


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch(args=["--host-resolver-rules=MAP admin.test 127.0.0.1"])
        yield b
        b.close()


MESURE = """()=>{
  const r=e=>{const b=e.getBoundingClientRect();return [Math.round(b.left),Math.round(b.right)]};
  const sb=document.querySelector('#sidebar')||document.querySelector('.sidebar');
  const app=document.querySelector('.app')||document.querySelector('.cadre');
  const rs=sb?r(sb):null;
  let minL=1e9,maxR=-1e9; document.querySelectorAll('.app *').forEach(e=>{const b=e.getBoundingClientRect(),cs=getComputedStyle(e);
    if(b.width>20&&b.height>4&&cs.visibility!=='hidden'&&cs.display!=='none'&&b.right>0&&b.left<innerWidth){minL=Math.min(minL,b.left);maxR=Math.max(maxR,b.right);}});
  return {W:innerWidth, scrollW:document.documentElement.scrollWidth, app:r(app), contenu:[Math.round(minL),Math.round(maxR)],
          cote: (rs && rs[0]>=0 && rs[1]>0 && rs[1]<innerWidth*0.6) ? rs[1] : 0}}"""


def mesure(navigateur, port, url, largeur, tactile=False):
    ctx = navigateur.new_context(viewport={"width": largeur, "height": 850}, has_touch=tactile, is_mobile=tactile)
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.goto(f"http://admin.test:{port}{url}")
    p.wait_for_timeout(1500)
    m = p.evaluate(MESURE)
    ctx.close()
    g, d = m["app"][0] - m["cote"], m["W"] - m["app"][1]
    return {**m, "gauche": g, "droite": d}


def mesure_incrustee(navigateur, port, url, largeur):
    """Comme le Hall : la cardlet est dans une iframe de `largeur` px, en ?embed=1."""
    ctx = navigateur.new_context(viewport={"width": max(largeur, 400), "height": 850})
    p = ctx.new_page()
    p.goto(f"http://admin.test:{port}/__hall__.html?w={largeur}&u={url}%3Fembed%3D1")
    p.wait_for_timeout(1800)
    fr = [f for f in p.frames if f != p.main_frame][0]
    m = fr.evaluate(MESURE)
    ctx.close()
    return {**m, "gauche": m["contenu"][0], "droite": m["W"] - m["contenu"][1]}


# ---------- écran étroit : la barre est repliée, le contenu ne garde pas son décalage ----------

@pytest.mark.parametrize("largeur", LARGEURS_MOBILES)
@pytest.mark.parametrize("url", [u for u, _ in AVEC_CADRE])
def test_ecran_etroit_pas_de_decalage_de_barre_repliee_et_une_gouttiere(navigateur, site, url, largeur):
    m = mesure(navigateur, site, url, largeur)
    assert m["gauche"] >= GOUTTIERE_MIN, m
    assert m["droite"] >= GOUTTIERE_MIN, m
    assert abs(m["gauche"] - m["droite"]) <= 2, f"mal centré : {m}"
    assert m["scrollW"] <= m["W"], f"la page déborde : {m}"


@pytest.mark.parametrize("url", [u for u, _ in AVEC_CADRE])
def test_un_appareil_tactile_large_n_a_pas_non_plus_le_decalage(navigateur, site, url):
    """sidebar.js passe en mode mobile sur tout appareil tactile : un iPad large perdait la barre mais gardait les 220 px."""
    m = mesure(navigateur, site, url, 1024, tactile=True)
    assert m["gauche"] <= 40 and abs(m["gauche"] - m["droite"]) <= 2, m


# ---------- écran large : plein espace, symétrique, gouttières raisonnables ----------

@pytest.mark.parametrize("largeur", LARGEURS_LARGES)
@pytest.mark.parametrize("url", [u for u, _ in AVEC_CADRE])
def test_ecran_large_le_contenu_est_centre_et_occupe_l_espace(navigateur, site, url, largeur):
    m = mesure(navigateur, site, url, largeur)
    assert abs(m["gauche"] - m["droite"]) <= 2, f"mal centré : {m}"
    assert 12 <= m["gauche"] <= 30, f"gouttière hors de 12-30 px : {m}"
    assert m["scrollW"] <= m["W"], m


# ---------- cardlets du Hall ----------

@pytest.mark.parametrize("url", [u for u, _ in CARDLETS])
def test_cardlet_incrustee_sur_iphone_a_une_marge_gauche_et_droite(navigateur, site, url):
    m = mesure_incrustee(navigateur, site, url, 390)
    assert m["gauche"] >= GOUTTIERE_MIN and m["droite"] >= GOUTTIERE_MIN, m
    assert abs(m["gauche"] - m["droite"]) <= 2 and m["scrollW"] <= m["W"], m


@pytest.mark.parametrize("url", [u for u, _ in CARDLETS])
def test_cardlet_incrustee_sur_grand_ecran_garde_sa_marge_compacte(navigateur, site, url):
    """Dans une carte du Hall, sur grand écran, la marge compacte est voulue (6 px) : on ne change que le cas étroit."""
    m = mesure_incrustee(navigateur, site, url, 700)
    assert m["gauche"] == m["droite"] and m["gauche"] <= 24, m


# ---------- les anciennes pages (hybrid-dark) ne bougent pas ----------

def test_la_regle_mobile_ne_vise_que_les_pages_aurora():
    """Une ancienne page « hybrid-dark » garde ses 32 px : la correction est conditionnée au marqueur Aurora, pas globale."""
    js = (SHARED / "sidebar.js").read_text(encoding="utf-8")
    assert re.search(r"sbx-aurora", js), "le cadre doit marquer les pages Aurora"
    css_mobile = re.findall(r"\.mobile-mode[^'\"]*margin-left:0!important", js)
    assert css_mobile
