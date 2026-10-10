# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""La page /ndpid/ restait vide : elle appelait /api/ndpid/… (404 : l'API est sous /api/v1/ndpid/…) et n'envoyait aucun jeton aux routes protégées.
Elle doit parler à la bonne route, présenter le jeton `sbx_token`, et dire pourquoi elle est vide au lieu de se taire."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "composants" / "ndpid" / "www" / "ndpid" / "index.html"
FLUX = {"count": 1, "flows": [{"src_ip": "10.64.0.7", "src_port": 51000, "dst_ip": "93.184.216.34", "dst_port": 443, "l7_protocol": "TLS", "application": "TLS.Google",
                               "bytes_sent": 1200, "bytes_recv": 5000, "risk_score": 10}]}
STATUT = {"module": "ndpid", "daemon": {"running": True, "source": "ndpiReader/dpi"},
          "database": {"total_flows": 10, "total_fingerprints": 0, "risks_24h": 0, "source": "ndpiReader/dpi"}}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, jeton, exige_jeton=True):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    appels, entetes = [], []

    def api(route):
        u = route.request.url
        appels.append(u.split("http://sbx.test", 1)[1])
        entetes.append(route.request.headers.get("authorization", ""))
        if "/api/v1/ndpid/status" in u:
            return route.fulfill(status=200, content_type="application/json", body=json.dumps(STATUT))
        if exige_jeton and not route.request.headers.get("authorization"):
            return route.fulfill(status=401, content_type="application/json", body=json.dumps({"detail": "Token Bearer ou session manquant"}))
        corps = FLUX if "/flows" in u else {"protocols": [], "applications": [], "fingerprints": [], "risks": []}
        route.fulfill(status=200, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/**", api)
    p.route("http://sbx.test/ndpid/", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.route("http://sbx.test/shared/**", lambda r: r.fulfill(status=200, content_type="text/css", body=""))
    p.add_init_script(f"try {{ localStorage.setItem('sbx_token', {json.dumps(jeton)}) }} catch (e) {{}}" if jeton else "")
    p.goto("http://sbx.test/ndpid/")
    return ctx, p, appels, entetes


def test_la_page_parle_a_la_bonne_route_et_presente_le_jeton(navigateur):
    ctx, p, appels, entetes = ouvre(navigateur, "jeton-admin")
    p.wait_for_function("document.getElementById('flows-table').innerText.includes('93.184.216.34')", timeout=10000)
    assert appels and all(a.startswith("/api/v1/ndpid/") for a in appels), appels            # jamais /api/ndpid/…
    assert any(e == "Bearer jeton-admin" for e in entetes)
    ctx.close()


def test_sans_jeton_la_page_dit_qu_il_faut_se_connecter_au_lieu_de_rester_vide(navigateur):
    ctx, p, _, _ = ouvre(navigateur, None)
    p.wait_for_selector("#ndpid-erreur:not([hidden])", timeout=10000)
    assert "connexion requise" in p.inner_text("#ndpid-erreur").lower()
    ctx.close()


def test_source_ndpireader_explique_pourquoi_empreintes_et_risques_sont_vides(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "jeton-admin")
    p.wait_for_selector("#ndpid-source:not([hidden])", timeout=10000)
    t = p.inner_text("#ndpid-source")
    assert "ndpiReader" in t and "JA3" in t
    ctx.close()
