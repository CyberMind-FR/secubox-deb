# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3126 L5 tâche 7 — panneau « Flotte » du maître, point d'entrée unique (R-L5-27) : chaque box s'ouvre depuis sa ligne.
Box « distante » : émission du code à usage unique sur le maître (GET /api/v1/pilotage/boxes/<box>/connexion-vhost) ;
box « locale » : lien direct actuel https://admin.<box>.secubox.in/. Nom hors motif : aucun lien (jamais d'URL forgée)."""
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from test_fleet_page_aurora_2487 import PAGE, _nav  # noqa: E402
from test_fleet_pilotage_3126 import BOITES  # noqa: E402

HTML = PAGE.read_text(encoding="utf-8")

LIGNES = [
    dict(BOITES[0], nom="gk5", cle="maillage:gk5", interface="distante"),
    dict(BOITES[0], nom="gk4", cle="maillage:gk4", interface="locale"),
    dict(BOITES[1], interface="locale"),                                  # nom forgé : pas de lien
    dict(BOITES[0], nom="gk6", cle="maillage:gk6"),                       # maître ancien : pas de champ, locale
]


def _api(r):
    if "/pilotage/boxes" in r.request.url:
        return r.fulfill(status=200, content_type="application/json", body=json.dumps(LIGNES))
    return r.fulfill(status=200, content_type="application/json", body=json.dumps({"nodes": []}))


def test_colonne_interface_dans_l_en_tete():
    m = re.search(r'<div class="pan" id="pil-pan".*?<!-- fin pil-pan -->', HTML, re.S)
    assert m and "<th>Interface</th>" in m.group(0)


def test_lien_distante_emission_du_code_lien_locale_direct():
    def sc(pg):
        pg.wait_for_selector("#pil-body tr")
        liens = pg.eval_on_selector_all("#pil-body tr", "trs => trs.map(tr => { const a = tr.querySelector('a.pil-ouvrir');"
                                        " return a ? [a.dataset.ouvrir, a.getAttribute('href'), a.getAttribute('rel'), a.textContent] : null; })")
        return liens
    liens, erreurs, natifs = _nav(sc, api=_api)
    assert erreurs == [] and natifs == []
    assert liens[0][0] == "/api/v1/pilotage/boxes/gk5/connexion-vhost"
    assert liens[0][1] == "#" and "noopener" in liens[0][2] and "noreferrer" in liens[0][2]   # href constant (règle de la page)
    assert "distante" in liens[0][3]
    assert liens[1][0] == "https://admin.gk4.secubox.in/" and "noopener" in liens[1][2]
    assert liens[2] is None
    assert liens[3][0] == "https://admin.gk6.secubox.in/"


def test_le_lien_n_ouvre_pas_la_page_de_la_box():
    """Le clic sur le lien ouvre l'interface de la box (nouvel onglet) sans basculer la page de la box en dessous."""
    def sc(pg):
        pg.wait_for_selector("#pil-body a.pil-ouvrir")
        pg.evaluate("window.__ouverts = []; window.open = (u, c, f) => { window.__ouverts.push([u, c, f]); return null; }; 0")   # « ; 0 » : sinon Playwright appelle la fonction rendue
        pg.click("#pil-body tr:nth-child(1) a.pil-ouvrir")
        pg.click("#pil-body tr:nth-child(2) a.pil-ouvrir")
        pg.wait_for_timeout(200)
        return pg.is_hidden("#pb-pan"), pg.evaluate("window.__ouverts")
    (cache, ouverts), erreurs, _ = _nav(sc, api=_api)
    assert cache is True and erreurs == []
    assert ouverts == [["/api/v1/pilotage/boxes/gk5/connexion-vhost", "_blank", "noopener,noreferrer"],
                       ["https://admin.gk4.secubox.in/", "_blank", "noopener,noreferrer"]]


def test_liens_construits_sans_innerhtml():
    m = re.search(r"// ===== pilotage =====(.*?)// ===== fin pilotage =====", HTML, re.S)
    js = m.group(1)
    assert "connexion-vhost" in js and "encodeURIComponent" in js and "/^[a-z0-9-]{1,40}$/" in js
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML", js)
