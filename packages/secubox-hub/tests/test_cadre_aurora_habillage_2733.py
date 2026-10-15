# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2733 — le cadre de l'administration (barre latérale, menu du haut, barre du bas) prend le profil Aurora sur les pages Aurora, et SEULEMENT sur elles.

Avant : une page Aurora (bleu nuit, cyan) était encadrée par l'ancien cadre « hybrid-dark » (vert, monospace). Deux pièges mesurés :
- `sidebar.js` pose des styles EN LIGNE avec `!important` sur le fond de la page et la barre latérale : aucune feuille ne peut les battre, il faut ne pas les poser ;
- hybrid-skin.css pose ses teintes en `!important` : la feuille Aurora doit venir APRÈS elle, avec une spécificité supérieure (AURORA-REFERENCE §10)."""
import http.server
import re
import shutil
import threading
from pathlib import Path

import pytest

PAQUETS = Path(__file__).resolve().parents[2]
SHARED = PAQUETS / "secubox-hub" / "www" / "shared"
CSS = (SHARED / "cadre-aurora.css").read_text(encoding="utf-8")

VIEUX = """<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Vieille page - SecuBox</title></head>
<body><nav class="sidebar" id="sidebar"></nav><main class="main"><h1>Ancienne page hybrid-dark</h1><p>Sans cadre Aurora.</p></main><script src="/shared/sidebar.js"></script></body></html>"""

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    racine = tmp_path_factory.mktemp("site")
    shutil.copytree(SHARED, racine / "shared")
    (racine / "autoload").mkdir()
    shutil.copy(PAQUETS / "secubox-autoload/www/autoload/index.html", racine / "autoload" / "index.html")
    (racine / "vieux").mkdir()
    (racine / "vieux" / "index.html").write_text(VIEUX, encoding="utf-8")

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


def ouvre(navigateur, port, url, largeur=1400):
    ctx = navigateur.new_context(viewport={"width": largeur, "height": 850})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.goto(f"http://admin.test:{port}{url}")
    p.wait_for_timeout(1800)
    return ctx, p, erreurs


STYLE = """([sel,prop])=>{const e=document.querySelector(sel);return e?getComputedStyle(e)[prop]:null}"""


# ---------- sur une page Aurora ----------

def test_la_feuille_aurora_est_chargee_en_dernier_apres_hybrid_skin(navigateur, site):
    ctx, p, err = ouvre(navigateur, site, "/autoload/index.html")
    assert p.evaluate("document.documentElement.classList.contains('sbx-aurora')")
    liens = p.evaluate("Array.from(document.querySelectorAll('link[rel=stylesheet]')).map(l=>l.getAttribute('href'))")
    assert "/shared/cadre-aurora.css" in liens and "/shared/hybrid-skin.css" in liens
    assert liens.index("/shared/cadre-aurora.css") > liens.index("/shared/hybrid-skin.css")
    assert err == []
    ctx.close()


def test_les_styles_en_ligne_qui_bloquent_l_habillage_ne_sont_pas_poses(navigateur, site):
    ctx, p, _ = ouvre(navigateur, site, "/autoload/index.html")
    assert p.evaluate("document.body.style.background") == "" and p.evaluate("document.body.style.backgroundImage") == ""
    assert p.evaluate("(document.getElementById('sidebar')||document.querySelector('.sidebar')).style.background") == ""
    ctx.close()


def test_le_cadre_prend_les_couleurs_et_la_police_aurora(navigateur, site):
    ctx, p, _ = ouvre(navigateur, site, "/autoload/index.html")
    assert p.evaluate(STYLE, ["body", "backgroundColor"]) == "rgb(6, 13, 27)"                       # --fond
    assert "linear-gradient" in p.evaluate(STYLE, ["#sidebar", "backgroundImage"])
    assert p.evaluate(STYLE, ["#global-menu-bar", "backgroundColor"]).startswith("rgba(10, 22, 46")
    assert p.evaluate(STYLE, ["#global-status-bar", "backgroundColor"]).startswith("rgba(10, 22, 46")
    assert p.evaluate(STYLE, ["#global-menu-bar .menu-title", "color"]) == "rgb(234, 241, 255)"     # --texte
    assert p.evaluate(STYLE, ["#global-menu-bar .menu-btn", "borderRadius"]) == "10px"
    for sel in ("#sidebar .nav-item", "#global-menu-bar .menu-title", "#global-status-bar .status-value"):
        assert "IBM Plex Sans" in p.evaluate(STYLE, [sel, "fontFamily"]), sel
    ctx.close()


def test_plus_de_vert_hybrid_dark_dans_le_cadre(navigateur, site):
    """Le vert n'a qu'un sens en Aurora : sain/actif. Ni le logo ni le titre ni les entrées de menu ne le portent."""
    ctx, p, _ = ouvre(navigateur, site, "/autoload/index.html")
    for sel in ("#sidebar .logo", "#global-menu-bar .menu-title", "#sidebar .nav-item"):
        c = p.evaluate(STYLE, [sel, "color"])
        r, g, b = [int(x) for x in re.findall(r"\d+", c)[:3]]
        assert not (g > r + 60 and g > b + 20), f"{sel} est vert : {c}"
    ctx.close()


def test_le_titre_du_menu_du_haut_n_a_plus_de_tiret_en_tete(navigateur, site):
    """« SecuBox — Actor Intelligence » laissait « — Actor Intelligence » : le tiret long n'était pas retiré."""
    ctx, p, _ = ouvre(navigateur, site, "/autoload/index.html")
    titre = p.inner_text("#gmb-title").strip()
    assert titre and not re.match(r"^[-–—]", titre) and "SecuBox" not in titre, titre
    ctx.close()


@pytest.mark.parametrize("titre,attendu", [("SecuBox — Actor Intelligence", "Actor Intelligence"), ("SecuBox – WAF", "WAF"), ("DPI - SecuBox", "DPI"),
                                           ("SecuBox Guardian", "Guardian"), ("SecuBox", "Dashboard")])
def test_nettoyage_du_titre(navigateur, titre, attendu):
    """La logique vit dans le script servi : on évalue sa vraie expression sur le titre, sans dépendre d'une page."""
    js = (SHARED / "sidebar.js").read_text(encoding="utf-8")
    m = re.search(r"var pageTitle = (document\.title\.replace\(.*?\) \|\| 'Dashboard');", js)
    assert m
    ctx = navigateur.new_context()
    q = ctx.new_page()
    q.set_content("<title></title>")
    q.evaluate("t=>{document.title=t}", titre)
    assert q.evaluate("()=>" + m.group(1)) == attendu
    ctx.close()


# ---------- les anciennes pages ne bougent pas ----------

def test_une_ancienne_page_garde_son_cadre_hybrid_dark(navigateur, site):
    ctx, p, err = ouvre(navigateur, site, "/vieux/index.html")
    assert not p.evaluate("document.documentElement.classList.contains('sbx-aurora')")
    liens = p.evaluate("Array.from(document.querySelectorAll('link[rel=stylesheet]')).map(l=>l.getAttribute('href'))")
    assert "/shared/cadre-aurora.css" not in liens and "/shared/hybrid-skin.css" in liens
    assert p.evaluate("document.body.style.getPropertyPriority('background-image')") == "important"   # l'ancien fond forcé en ligne est conservé
    assert "rgba(17, 23, 32" in p.evaluate("(document.getElementById('sidebar')||document.querySelector('.sidebar')).style.background")
    assert err == []
    ctx.close()


def test_incruste_dans_le_hall_le_cadre_reste_masque(navigateur, site):
    """Encadrée par le Hall, la page masque SA coquille (#1187) : l'habillage n'y change rien."""
    ctx = navigateur.new_context(viewport={"width": 800, "height": 700})
    p = ctx.new_page()
    p.goto(f"http://admin.test:{site}/autoload/index.html")        # origine de la page parente
    p.set_content(f"<iframe src='http://admin.test:{site}/autoload/index.html' style='width:700px;height:600px;border:0'></iframe>")
    p.wait_for_timeout(1800)
    fr = [f for f in p.frames if f != p.main_frame][0]
    assert fr.evaluate("!document.getElementById('global-menu-bar') && !document.getElementById('global-status-bar')")
    ctx.close()


# ---------- la feuille elle-même ----------

def test_la_feuille_est_prefixee_pour_ne_toucher_que_les_pages_aurora():
    sans_commentaires = re.sub(r"/\*.*?\*/", "", CSS, flags=re.S)
    for bloc in re.finditer(r"([^{}]+)\{[^{}]*\}", sans_commentaires):
        for sel in bloc.group(1).split(","):
            assert sel.strip().startswith("html.sbx-aurora"), f"sélecteur sans préfixe Aurora : {sel.strip()}"


def test_la_feuille_est_autonome_et_porte_son_en_tete_de_licence():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in CSS
    assert not re.search(r"https?://|@import|url\(", CSS)


def luminance(h):
    r, g, b = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4  # noqa: E731
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


@pytest.mark.parametrize("texte,mini", [("#eaf1ff", 7), ("#9fb3d6", 4.5), ("#6f84a8", 4.5)])
def test_contraste_du_texte_sur_le_fond_aurora(texte, mini):
    fond = "#060d1b"
    a, b = sorted([luminance(texte), luminance(fond)], reverse=True)
    assert (a + 0.05) / (b + 0.05) >= mini, f"{texte} sur {fond}"


# ---------- sur iPhone ----------

BARRES = """()=>{const r=s=>{const e=document.querySelector(s);if(!e)return null;const b=e.getBoundingClientRect();return {g:Math.round(b.left),d:Math.round(b.right),h:Math.round(b.height)}};
  return {W:innerWidth, haut:r('#global-menu-bar'), bas:r('#global-status-bar'), titre:r('#gmb-title'), deco:r('#global-menu-bar .menu-btn.danger'),
          bascule:r('#sidebar-toggle'), scroll:document.documentElement.scrollWidth}}"""


@pytest.mark.parametrize("largeur", [390, 768])
def test_sur_iphone_les_barres_du_haut_et_du_bas_occupent_toute_la_largeur(navigateur, site, largeur):
    """MESURÉ : le menu du haut et la barre du bas commençaient à 220 px (place de la barre latérale, pourtant repliée) et sortaient de l'écran."""
    ctx = navigateur.new_context(viewport={"width": largeur, "height": 780}, has_touch=True, is_mobile=True)
    p = ctx.new_page()
    p.goto(f"http://admin.test:{site}/autoload/index.html")
    p.wait_for_timeout(1800)
    m = p.evaluate(BARRES)
    ctx.close()
    assert m["haut"]["g"] == 0 and m["haut"]["d"] <= m["W"], m
    assert m["bas"]["g"] == 0 and m["bas"]["d"] <= m["W"], m
    assert m["scroll"] <= m["W"], m


def test_sur_iphone_le_titre_et_la_deconnexion_restent_visibles_et_le_titre_ne_passe_pas_sous_la_bascule(navigateur, site):
    ctx = navigateur.new_context(viewport={"width": 390, "height": 780}, has_touch=True, is_mobile=True)
    p = ctx.new_page()
    p.goto(f"http://admin.test:{site}/autoload/index.html")
    p.wait_for_timeout(1800)
    m = p.evaluate(BARRES)
    ctx.close()
    assert m["titre"] and 0 <= m["titre"]["g"] and m["titre"]["d"] <= m["W"], m
    assert m["deco"] and m["deco"]["d"] <= m["W"], m
    if m["bascule"]:
        assert m["titre"]["g"] >= m["bascule"]["d"], f"le titre passe sous le bouton du menu : {m}"
