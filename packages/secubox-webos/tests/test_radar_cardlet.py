# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Radar des acteurs (Actor Intelligence 2.0, phase 5, #2240) : risque et confiance SÉPARÉS, scénario, décision proposée ; données réelles, pas d'invention."""
import json
import re
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
HTML = (RACINE / "www" / "hall" / "cardlets" / "radar.html").read_text()
INDEX = (RACINE / "www" / "hall" / "index.html").read_text()
VHOST = (RACINE / "nginx" / "hall.vhost.conf").read_text()


def test_le_radar_lit_la_synthese_apres_la_session_et_n_invente_rien():
    assert "/api/v1/actor/radar" in HTML and "sessionOk()" in HTML
    assert HTML.index("sessionOk().then") < HTML.index("jget('/api/v1/actor/radar")        # jamais à vide : sonde.js fermerait la carte
    assert "Math.random" not in HTML and 'src="../sonde.js"' in HTML
    assert "Ouvre une session" in HTML and "en démarrage ou injoignable" in HTML


def test_risque_et_confiance_sont_deux_axes_distincts_avec_quatre_zones():
    for ident in ('id="radar"', 'id="liste"', 'id="fiche"'):
        assert ident in HTML
    for zone in ("Agir", "Confirmer", "Surveiller", "Ignorer"):
        assert zone in HTML
    assert "Risque" in HTML and "Confiance" in HTML


def test_le_niveau_de_decision_et_les_refus_sont_affiches():
    for mot in ("OBSERVE", "MITIGATE", "BLOCK", "refus", "etapes", "facteurs"):
        assert mot in HTML


def test_les_valeurs_serveur_sont_echappees():
    assert "function esc(" in HTML and "&#39;" in HTML
    for brut in ("'+a.id+'", "'+f.libelle+'", "'+r+'</"):
        assert brut not in HTML
    assert "esc(a.id)" in HTML and "esc(f.libelle)" in HTML


def test_aucune_ressource_externe_et_themes_clair_sombre():
    assert "http://" not in HTML and "https://" not in HTML
    assert "prefers-color-scheme: dark" in HTML and 'data-theme="dark"' in HTML


def test_le_hall_declare_la_carte_et_le_relais_laisse_passer_le_radar():
    assert re.search(r'\{id:"radar"[^}]*carte:"/cardlets/radar\.html"[^}]*auth:true', INDEX)
    m = re.search(r"location ~ \^/api/v1/actor/\(([^)]*)\)\$", VHOST)
    assert m and "radar" in m.group(1).split("|")
    assert "X-Sbx-Vue       reduite" in VHOST[m.start():m.start() + 700]       # le radar passe TOUJOURS par la vue réduite


# ── Comportement réel, API simulée ──────────────────────────────────────────────────────────────────────────────────────────────────────────
playwright = pytest.importorskip("playwright.sync_api")

RADAR = {"genere_le": 1, "politique": "v2", "acteurs": [
    {"id": "ACT-0001", "niveau": "MITIGATE", "action_proposee": "mesure réversible", "raisons": ["balayage de ports (+20)"],
     "refus": ["BLOCK refusé : un seul capteur (2 requis)"], "capteurs": ["waf"], "evenements": 7, "scenario": "balayage → sondage",
     "risque": {"valeur": 82, "facteurs": [{"libelle": "balayage de ports", "points": 20}]},
     "confiance": {"valeur": 40, "facteurs": [{"libelle": "événements observés", "points": 25}]},
     "etapes": [{"etape": "reconnaissance", "libelle": "balayage", "evenements": 3, "capteurs": ["waf"]}]},
    {"id": "<img src=x onerror=window.__pwn=1>", "niveau": "OBSERVE", "action_proposee": "aucune", "raisons": [], "capteurs": [], "evenements": 1, "scenario": "",
     "risque": {"valeur": 10, "facteurs": []}, "confiance": {"valeur": 90, "facteurs": []}, "etapes": []}]}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, session=True):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(route):
        u = route.request.url
        if u.endswith("/acces/session/etat"):
            corps = {"session": session}
        elif "/actor/radar" in u:
            corps = RADAR
        else:
            corps = {}
        route.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
    p.route("http://hall.test/api/**", api)
    p.route("http://hall.test/sonde.js", lambda r: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://hall.test/slicebar.css", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
    p.route("http://hall.test/cardlets/radar.html", lambda r: r.fulfill(status=200, content_type="text/html", body=HTML.replace("../sonde.js", "/sonde.js").replace("../slicebar.css", "/slicebar.css")))
    p.goto("http://hall.test/cardlets/radar.html")
    return ctx, p, erreurs


def test_chaque_acteur_est_un_point_et_une_ligne(navigateur):
    ctx, p, erreurs = ouvre(navigateur)
    p.wait_for_selector("#liste .acteur", timeout=10000)
    assert p.locator("#liste .acteur").count() == 2 and p.locator("#radar circle.pt").count() == 2
    assert not erreurs
    ctx.close()


def test_un_identifiant_hostile_n_execute_rien(navigateur):
    ctx, p, _ = ouvre(navigateur)
    p.wait_for_selector("#liste .acteur")
    assert p.evaluate("window.__pwn") is None
    ctx.close()


def test_la_fiche_montre_risque_confiance_scenario_et_refus(navigateur):
    ctx, p, _ = ouvre(navigateur)
    p.wait_for_selector("#liste .acteur")
    p.locator("#liste .acteur").first.click()
    t = p.inner_text("#fiche")
    for attendu in ("MITIGATE", "balayage de ports", "+20", "événements observés", "BLOCK refusé : un seul capteur", "balayage"):
        assert attendu in t, attendu
    ctx.close()


def test_sans_session_aucun_chiffre(navigateur):
    ctx, p, _ = ouvre(navigateur, session=False)
    p.wait_for_selector("#fiche .vide, #liste .vide")
    assert "Ouvre une session" in p.inner_text("body") and p.locator("#liste .acteur").count() == 0
    ctx.close()
