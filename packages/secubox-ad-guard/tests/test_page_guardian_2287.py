# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2287 : la page Guardian affiche les données réelles de l'API, dit honnêtement quand elle n'en a pas, échappe tout, n'appelle aucune ressource externe."""
import json
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "guardian" / "index.html"
DONNEES = {"actif": True, "appareils": {"connectes": 7, "total": 9}, "dns": {"requetes": 12345, "bloquees": 2469, "taux": 20, "libelle": "Requêtes DNS (aujourd'hui)", "sous": "hier : 11 000"},
           "menaces": None, "serie": [{"x": "lun", "a": 100, "b": 20}, {"x": "mar", "a": 150, "b": 40}, {"x": "mer", "a": 120, "b": 30}],
           "types": [{"nom": "Publicité", "pct": 60, "c": "bleu"}, {"nom": "Autres", "pct": 40, "c": "cyan"}],
           "cats": [{"nom": "Réseaux sociaux", "pct": 30, "c": "cyan"}],
           "top": [{"nom": "<img src=x onerror=window.xss=1>", "type": "tv", "req": 900, "blq": 300, "pct": 33, "c": "rouge"}]}


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, statut=200, corps=DONNEES, url="http://g.test/guardian/"):
    p = nav.new_context().new_page()
    externes, erreurs = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("request", lambda r: externes.append(r.url) if not r.url.startswith(("http://g.test", "data:")) else None)
    p.route("http://g.test/api/**", lambda r: r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps)))
    p.route("http://g.test/guardian/**", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.goto(url)
    p.wait_for_timeout(600)
    return p, externes, erreurs


def test_la_page_affiche_les_chiffres_de_l_api_et_echappe_les_noms(nav):
    p, externes, erreurs = ouvre(nav)
    t = p.inner_text("body").replace("\u202f", " ")
    assert "12 345" in t and "2 469" in t and "20 % des requêtes" in t and "sur 9 connus" in t
    assert p.evaluate("window.xss") is None and "<img" in t                      # le nom d'appareil reste du texte
    assert "mesure indisponible" in t                                            # menaces absentes : « — », jamais 0
    assert not externes and not erreurs
    p.context.close()


def test_sans_session_la_page_le_dit_et_n_invente_rien(nav):
    p, _, _ = ouvre(nav, 401, {"detail": "x"})
    t = p.inner_text("body").replace("\u202f", " ")
    assert "Ouvre une session" in t and "12 345" not in t
    p.context.close()


def test_le_mode_demo_est_annonce(nav):
    p, _, _ = ouvre(nav, url="http://g.test/guardian/?demo=1")
    assert p.locator("#demo").is_visible()
    p.context.close()


def test_aucune_ressource_externe_dans_la_source():
    s = PAGE.read_text(encoding="utf-8")
    assert not re.search(r"(src|href)=[\"']https?://|url\(\s*[\"']?https?://|@import", s)
