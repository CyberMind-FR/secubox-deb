# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2339 : un lien d'activité /bbs/t/<id> ouvert sur le Hall ne casse plus la page (références absolues) et mène au BBS de la box (redirection). Vrai navigateur, réseau simulé."""
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
HALL_DIR = Path(__file__).resolve().parents[1] / "www" / "hall"
HALL = HALL_DIR / "index.html"
HOTE = "https://hall.gk2.secubox.in"


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, chemin):
    p = nav.new_context().new_page()
    vus, naviguees = [], []
    p.on("request", lambda r: vus.append(r.url))
    p.on("framenavigated", lambda f: naviguees.append(f.url) if f == p.main_frame else None)

    def hall(r):
        u = r.request.url
        chemin_u = u.split(HOTE)[1].split("?")[0]
        if chemin_u == "/domaine.js":
            return r.fulfill(status=200, content_type="application/javascript", body=(HALL_DIR / "domaine.js").read_text(encoding="utf-8"))
        if chemin_u == chemin or chemin_u == "/":
            return r.fulfill(status=200, content_type="text/html", body=HALL.read_text(encoding="utf-8"))
        r.fulfill(status=404, content_type="text/html", body="<html>repli</html>")       # un chemin relatif mal résolu tomberait ici
    p.route(f"{HOTE}/**", hall)
    p.route("https://bbs.gk2.secubox.in/**", lambda r: r.fulfill(status=200, content_type="text/html", body="<title>bbs</title>"))
    p.goto(HOTE + chemin)
    p.wait_for_timeout(700)
    return p, vus, naviguees


def test_un_lien_bbs_t_ouvre_le_fil_sur_le_bbs_de_la_box(nav):
    p, vus, nav_ = ouvre(nav, "/bbs/t/1132")
    assert p.url == "https://bbs.gk2.secubox.in/t/1132"
    p.context.close()


def test_un_lien_bbs_f_ouvre_le_fichier_sur_le_bbs(nav):
    p, _, _ = ouvre(nav, "/bbs/f/98")
    assert p.url == "https://bbs.gk2.secubox.in/f/98"
    p.context.close()


def test_la_page_n_a_plus_de_reference_relative_qui_se_resout_sous_le_chemin_profond(nav):
    p, vus, _ = ouvre(nav, "/bbs/t/1132")
    assert not [u for u in vus if "/bbs/t/domaine.js" in u or "/bbs/t/lexie.js" in u or "/bbs/t/fonts/" in u]
    assert any(u == HOTE + "/domaine.js" for u in vus)
    p.context.close()


def test_un_chemin_bbs_hors_motif_ne_redirige_pas(nav):
    p, _, _ = ouvre(nav, "/bbs/t/1132/../../evil")
    assert "bbs.gk2.secubox.in" not in p.url
    p.context.close()


def test_la_racine_reste_la_racine(nav):
    p, _, _ = ouvre(nav, "/")
    assert p.url == HOTE + "/"
    p.context.close()


def test_aucune_reference_relative_de_script_de_police_ou_d_image_dans_l_index():
    h = HALL.read_text(encoding="utf-8")
    rel = re.findall(r'(?:src|href)="([a-zA-Z][^":]*\.(?:js|css|svg|webp|png|woff2))"', h) + re.findall(r'url\("([a-zA-Z][^":)"]*)"\)', h)
    assert not rel, rel
