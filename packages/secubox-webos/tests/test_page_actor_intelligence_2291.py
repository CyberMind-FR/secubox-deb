# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2291 : la page Actor Intelligence affiche les données d'actord, sépare risque et confiance, dit « — » sans mesure, échappe tout, n'appelle rien d'externe."""
import json
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "actor-intelligence" / "index.html"
STATS = {"posture": "Protégée", "mode": "observe", "blocked_24h": 1295, "attempts_24h": 31311, "actors": 1167, "campaigns": 58, "events_24h": 32606}
OVERVIEW = {"echantillon": 5000, "top_pays": [{"code": "HK", "n": 91}, {"code": "ZZ", "n": 3}], "activite_24h": [0] * 22 + [52, 196],
            "recents": [{"heure": "04:31", "acteur": "ACT-0002", "type": "<img src=x onerror=window.xss=1>", "module": "waf", "score": 40}],
            "techniques": {"ACT-0002": [{"nom": "recon-001", "n": 34}]}, "robots": [{"famille": "meta", "hits": 48275}]}
RADAR = {"acteurs": [{"id": "ACT-0002", "risque": {"valeur": 97}, "confiance": {"valeur": 90}, "niveau": "BLOCK", "evenements": 2286}]}


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, reponses, url="http://a.test/actor-intelligence/"):
    p = nav.new_context().new_page()
    externes, erreurs = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("request", lambda r: externes.append(r.url) if not r.url.startswith(("http://a.test", "data:")) else None)

    def api(r):
        corps = reponses.get(r.request.url.split("?")[0].split("a.test")[1])
        r.fulfill(status=200 if corps is not None else 401, content_type="application/json", body=json.dumps(corps if corps is not None else {}))
    p.route("http://a.test/api/**", api)
    p.route("http://a.test/actor-intelligence/**", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.goto(url)
    p.wait_for_timeout(600)
    return p, externes, erreurs


def test_les_chiffres_d_actord_sont_affiches_risque_et_confiance_separes(nav):
    p, externes, erreurs = ouvre(nav, {"/api/v1/actor/stats": STATS, "/api/v1/actor/overview": OVERVIEW, "/api/v1/actor/radar": RADAR})
    t = p.inner_text("body").replace(" ", " ")
    assert "1 295" in t and "31 311" in t and "32 606" in t and "Protégée" in t and "MODE : OBSERVE" in t
    assert "Risque 97" in t.replace("\n", " ") and "Confiance 0.90" in t.replace("\n", " ")
    assert p.evaluate("window.xss") is None and "<img" in t                        # le type d'événement reste du texte
    assert not externes and not erreurs
    p.context.close()


def test_sans_session_les_mesures_de_session_sont_des_tirets_pas_des_zeros(nav):
    p, _, _ = ouvre(nav, {"/api/v1/actor/stats": STATS})                          # overview/radar : 401
    t = p.inner_text("body")
    assert "Session requise" in t or "Ouvre une session" in t
    assert p.locator(".tuile.crit .v").inner_text() == "—"
    p.context.close()


def test_le_filtre_par_capteur_ne_garde_que_ce_capteur(nav):
    p, _, _ = ouvre(nav, {"/api/v1/actor/stats": STATS, "/api/v1/actor/overview": OVERVIEW, "/api/v1/actor/radar": RADAR})
    p.click("#onglets button[data-f=DPI]")
    assert "Aucun événement pour ce capteur" in p.inner_text("#events")
    p.click("#onglets button[data-f=WAF]")
    assert "ACT-0002" in p.inner_text("#events")
    p.context.close()


def test_le_mode_demo_est_annonce(nav):
    p, _, _ = ouvre(nav, {}, "http://a.test/actor-intelligence/?demo=1")
    assert p.locator("#demo").is_visible()
    p.context.close()


def test_aucune_ressource_externe_dans_la_source():
    assert not re.search(r"(src|href)=[\"']https?://|url\(\s*[\"']?https?://|@import", PAGE.read_text(encoding="utf-8"))


def test_le_mode_affiche_est_celui_de_l_application_des_decisions_pas_celui_de_l_analyse(nav):
    p, _, _ = ouvre(nav, {"/api/v1/actor/stats": STATS, "/api/v1/waf/enforcement/mode": {"mode": "ACTIVE", "detail": {"campagnes": "ACTIVE", "acteurs": "ACTIVE"}}})
    assert p.inner_text("#mode") == "MODE : ACTIVE"                                   # actord dit « observe » (analyse), mais les bans sont réellement appliqués
    actifs = p.eval_on_selector_all("#modes button[aria-current=true]", "bs => bs.map(b => b.textContent)")
    assert actifs == ["MITIGATE", "BLOCK"]
    assert "jamais d’ici" in p.inner_text("#modes")
    p.context.close()


def test_sans_mode_du_waf_on_retombe_sur_celui_d_actord(nav):
    p, _, _ = ouvre(nav, {"/api/v1/actor/stats": STATS})
    assert p.inner_text("#mode") == "MODE : OBSERVE"
    assert p.eval_on_selector_all("#modes button[aria-current=true]", "bs => bs.map(b => b.textContent)") == ["PASSIVE"]
    p.context.close()
