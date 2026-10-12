# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2514 — la pastille d'état de /dns-guard/ ne dit « HORS LIGNE » que d'une vraie panne.

Un 401/403 (pas de session) n'est pas une panne du module : on ne sait pas. La page est servie sur une origine simulée (fetch() refuse file://)."""
import concurrent.futures
import json
import pathlib

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "dns-guard" / "index.html"
ORIGINE = "http://t.test"
STATUS_OK = {"queries_24h": 1000, "blocked_24h": 100, "alerts_24h": 0, "fenetre": "aujourd'hui (UTC)"}


def _pastille(code_status, corps=None):
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e))
            pg = nav.new_page()
            html = PAGE.read_text(encoding="utf-8")

            def api(route):
                if route.request.url.endswith("/status"):
                    route.fulfill(status=code_status, content_type="application/json", body=json.dumps(corps or {"detail": "x"}))
                else:
                    route.fulfill(status=code_status if code_status != 200 else 404, content_type="application/json", body="{}")
            pg.route(ORIGINE + "/api/**", api)
            pg.route(ORIGINE + "/", lambda r: r.fulfill(status=200, content_type="text/html", body=html))
            pg.goto(ORIGINE + "/")
            pg.wait_for_function("document.getElementById('pGarde').textContent.indexOf('…') === -1", timeout=10000)
            r = pg.inner_text("#pGarde")
            nav.close()
            return ("ok", r)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1]


def test_sans_session_la_pastille_ne_dit_pas_hors_ligne():
    for code in (401, 403):
        assert _pastille(code) == "SESSION REQUISE"


def test_erreur_serveur_reste_hors_ligne():
    assert _pastille(500) == "HORS LIGNE"


def test_module_actif():
    assert _pastille(200, STATUS_OK) == "GARDE ACTIVE"
