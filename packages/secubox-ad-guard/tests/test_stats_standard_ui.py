# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1963 : cartes et panneau d'auto-apprentissage de la partie standard, dans un vrai navigateur, API simulée : jamais de zéro trompeur."""
import json
import re
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "ad-guard" / "index.html"

STATS = {"blocklist_domains": 656704, "monitored_devices": 14, "detections_24h": 7109, "pending_delayed_blocks": 0, "dns_requetes_jour": 38000, "dns_bloquees_jour": 7109,
         "dns_taux_blocage": 19, "dns_fenetre": "aujourd'hui (UTC)", "dns_lisible": True, "toolbox_lisible": False}
APPRENTISSAGE_ILLISIBLE = {"learned": None, "pure": None, "allowlist": None, "lisible": False, "autolearn": True, "ad_learn": None, "thresholds": {}}
APPRENTISSAGE_OK = {"learned": 1200, "pure": 40, "allowlist": 3, "lisible": True, "autolearn": False, "ad_learn": True, "thresholds": {}}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _page(navigateur, stats=STATS, appr=APPRENTISSAGE_ILLISIBLE):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(route):
        chemin = re.sub(r"^.*?/api/v1/ad-guard", "", route.request.url).split("?")[0]
        r = {"/stats": stats, "/learn/status": appr}.get(chemin, {})
        route.fulfill(status=200, content_type="application/json", body=json.dumps(r))
    p.route("http://sbx.test/**", lambda r: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://sbx.test/api/v1/ad-guard/**", api)
    p.route("http://sbx.test/", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.goto("http://sbx.test/")
    p.evaluate("document.getElementById('avance').open = true")                  # contenu d'origine sous « Avancé » (#2174)
    return ctx, p, erreurs


def test_les_cartes_montrent_les_chiffres_dns_et_leur_source(navigateur):
    ctx, p, erreurs = _page(navigateur)
    p.wait_for_function("document.getElementById('blocked-24h').textContent.trim() !== '-'")
    assert re.sub(r"\s| ", "", p.inner_text("#blocklist-count")) == "656704"
    assert p.inner_text("#devices-count") == "14" and re.sub(r"\s| ", "", p.inner_text("#blocked-24h")) == "7109" and p.inner_text("#pending-count") == "0"
    assert "DNS" in p.inner_text(".stat-card:has(#blocked-24h) .stat-label") and "DNS" in p.inner_text(".stat-card:has(#devices-count) .stat-label")
    note = p.inner_text("#stats-note")
    assert "38" in note and "19 %" in note and "toolbox" in note and "illisible" in note.lower()
    assert not [e for e in erreurs if "stat" in e.lower()]
    ctx.close()


def test_une_source_absente_donne_un_tiret_jamais_zero(navigateur):
    stats = {"blocklist_domains": 656704, "dns_lisible": False, "toolbox_lisible": False, "pending_delayed_blocks": 0}      # ni detections_24h ni monitored_devices
    ctx, p, erreurs = _page(navigateur, stats)
    p.wait_for_function("document.getElementById('blocklist-count').textContent.trim() !== '-'")
    assert p.inner_text("#devices-count") == "—" and p.inner_text("#blocked-24h") == "—"
    assert "illisible" in p.inner_text("#stats-note").lower() and "DNS" in p.inner_text("#stats-note")
    ctx.close()


def test_apprentissage_illisible_tirets_message_et_pastille_inconnue(navigateur):
    ctx, p, erreurs = _page(navigateur)
    p.wait_for_function("document.getElementById('learn-status').textContent.indexOf('Chargement') < 0")
    t = p.inner_text("#learn-status")
    assert t.count("—") >= 3 and "illisibles" in t.lower() and "permissions" in t.lower()
    assert not re.findall(r"\b\d+\b", t)                                                                       # aucun chiffre : pas de compteur à 0 affiché comme vrai
    assert "⚪" in p.inner_html("#learn-status")                                                              # ad-learn inconnu : pastille neutre, pas verte
    ctx.close()


def test_apprentissage_lisible_compteurs_et_pastilles_reelles(navigateur):
    ctx, p, erreurs = _page(navigateur, appr=APPRENTISSAGE_OK)
    p.wait_for_function("document.getElementById('learn-status').textContent.indexOf('Chargement') < 0")
    t = p.inner_text("#learn-status")
    assert re.sub(r"\s| ", "", t).count("1200") == 1 and "illisibles" not in t.lower()
    h = p.inner_html("#learn-status")
    assert "🔴" in h and "🟢" in h                                                                              # autolearn faux, ad-learn vrai
    ctx.close()
