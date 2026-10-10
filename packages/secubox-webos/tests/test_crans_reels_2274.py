# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2274 : les six crans de la page « Renseignement » reflètent les mesures RÉELLES (nombre d'acteurs sous chaque cran) ; le Radar montre la mesure en cours."""
import json
import re
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
ACTOR = (RACINE / "www" / "hall" / "cardlets" / "actor.html").read_text()
RADAR = (RACINE / "www" / "hall" / "cardlets" / "radar.html").read_text()
VHOST = (RACINE / "nginx" / "hall.vhost.conf").read_text()


def test_le_hall_relaie_les_compteurs_de_mesures_en_vue_reduite_et_session_exigee():
    m = re.search(r"location ~ \^/api/v1/actor/\(([^)]*)\)\$", VHOST)
    assert m and "mesures" in m.group(1).split("|")
    assert "X-Sbx-Vue       reduite" in VHOST[m.start():m.start() + 700]


def test_la_page_lit_les_mesures_apres_la_session_et_n_affiche_plus_un_cran_factice():
    assert "/api/v1/actor/mesures" in ACTOR and ACTOR.index("sessionOk()") < ACTOR.index("/api/v1/actor/mesures")
    assert "PAR_NIVEAU" in ACTOR and "n>0" in ACTOR                              # un cran ne s'allume que sur un compte, plus par construction


def test_le_radar_montre_la_mesure_en_cours_de_chaque_acteur():
    assert "a.mesure" in RADAR and "reste_s" in RADAR


playwright = pytest.importorskip("playwright.sync_api")


def _ouvre(navigateur, par_niveau, session=True):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(route):
        u = route.request.url
        if u.endswith("/acces/session/etat"):
            corps = {"session": session}
        elif "/actor/mesures" in u:
            corps = {"par_niveau": par_niveau}
        elif "/actor/stats" in u:
            corps = {"actors": 3, "campaigns": 0, "events_24h": 10, "blocked_24h": 1, "mode": "observe", "shadow": False}
        elif "/actor/actors" in u:
            corps = []
        else:
            corps = {}
        route.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
    p.route("http://hall.test/api/**", api)
    p.route("http://hall.test/sonde.js", lambda r: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://hall.test/slicebar.js", lambda r: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://hall.test/slicebar.css", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
    p.route("http://hall.test/cardlets/actor.html", lambda r: r.fulfill(status=200, content_type="text/html",
            body=ACTOR.replace("../sonde.js", "/sonde.js").replace("../slicebar.js", "/slicebar.js").replace("../slicebar.css", "/slicebar.css")))
    p.goto("http://hall.test/cardlets/actor.html")
    return ctx, p, erreurs


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def test_chaque_cran_affiche_le_nombre_d_acteurs_sous_mesure(navigateur):
    ctx, p, erreurs = _ouvre(navigateur, {"DELAY": 2, "CHALLENGE": 0, "TARPIT": 1, "DENY": 3, "QUARANTINE": 0})
    p.wait_for_function("document.querySelector('#crans .cran.on') !== null", timeout=10000)
    def carte(nom):
        return p.locator(f"#crans .cran:has(b:text-is('{nom}'))")
    assert "2" in carte("Delay").text_content() and "on" in carte("Delay").get_attribute("class")
    assert "1" in carte("Tarpit").text_content()
    assert "3" in carte("Deny").text_content()
    assert "on" not in (carte("Challenge").get_attribute("class") or "").split() and "on" not in (carte("Quarantine").get_attribute("class") or "").split()
    assert not erreurs
    ctx.close()


def test_sans_session_les_crans_ne_prétendent_rien(navigateur):
    ctx, p, _ = _ouvre(navigateur, {"DELAY": 5}, session=False)
    p.wait_for_selector("#crans .cran", state="attached")
    assert p.locator("#crans .cran.on").count() <= 1                 # au plus « Observer », jamais un compte inventé
    assert "5" not in (p.text_content("#crans") or "")
    ctx.close()
