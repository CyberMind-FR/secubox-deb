# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Panneau DNS Guard dans un vrai navigateur, API simulée (#1978) : jamais un zéro trompeur, jamais de HTML venu de l'API."""
import json
import re
from pathlib import Path
from urllib.parse import unquote

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "dns-guard" / "index.html"

STATUS = {"module": "dns-guard", "queries_24h": 38000, "blocked_24h": 7109, "malware_blocked": None, "phishing_blocked": None, "blocklist_size": 656704,
          "fenetre": "aujourd'hui (UTC)", "sources": {"dns": True, "puits": True}, "blocklist_count": 0, "alerts_24h": 1}
TOP = {"domains": [{"domain": "pub.example.com", "category": "advertising", "hits": 1234}, {"domain": "trk.example.net", "category": "tracking", "hits": 7}],
       "fenetre": "aujourd'hui (UTC)"}
ALERTES = {"alerts": [{"id": "a1", "type": "dga", "severity": "high", "domain": "xkqzp.example.com", "client_ip": "192.0.2.5", "description": "d", "details": {}, "timestamp": "2026-10-04T05:00:00Z", "blocked": True}], "count": 1}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _page(navigateur, rep=None):
    rep = {("GET", "/status"): STATUS, ("GET", "/top-blocked"): TOP, ("GET", "/alerts"): ALERTES, **(rep or {})}
    ctx = navigateur.new_context()
    p = ctx.new_page()
    erreurs, requetes = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(route):
        brut = unquote(re.sub(r"^.*?/api/v1/dns-guard", "", route.request.url))
        chemin = brut.split("?")[0]
        requetes.append((route.request.method, brut))
        route.fulfill(status=200, content_type="application/json", body=json.dumps(rep.get((route.request.method, chemin), {})))
    p.route("http://sbx.test/**", lambda r: r.fulfill(status=200, content_type="application/javascript", body=""))
    p.route("http://sbx.test/api/v1/dns-guard/**", api)
    p.route("http://sbx.test/", lambda r: r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8")))
    p.goto("http://sbx.test/")
    return ctx, p, erreurs, requetes


def chiffres(texte):
    return re.sub(r"\s| ", "", texte)


def test_les_tuiles_montrent_les_vrais_chiffres(navigateur):
    ctx, p, erreurs, _ = _page(navigateur)
    p.wait_for_function("document.querySelector('.tuile .v') && document.querySelector('.tuile .v').textContent.trim() !== '—'")
    t = chiffres(p.inner_text("#tuiles"))
    assert "38000" in t and "7109" in t
    assert not erreurs
    ctx.close()


def test_aucune_source_donne_des_tirets(navigateur):
    ctx, p, _, _ = _page(navigateur, rep={("GET", "/status"): dict(STATUS, queries_24h=None, blocked_24h=None)})
    p.wait_for_selector("#suspects code, #suspects td")
    assert p.locator(".tuile .v").first.inner_text().strip() == "—"
    ctx.close()


def test_top_et_suspects(navigateur):
    ctx, p, _, _ = _page(navigateur)
    p.wait_for_selector("#suspects td.m")
    assert "xkqzp.example.com" in p.text_content("#suspects")
    assert "pub.example.com" in p.text_content("#top") and chiffres(p.text_content("#top")).count("1234") == 1
    ctx.close()


def test_autoriser_demande_confirmation_puis_poste_la_vraie_route(navigateur):
    ctx, p, _, requetes = _page(navigateur)
    p.wait_for_selector("#suspects button[data-act=allow]")
    p.click("#suspects button[data-act=allow]")
    p.wait_for_timeout(200)
    assert not [r for r in requetes if r[0] == "POST"]                                  # rien avant la confirmation
    p.click("#confOui")
    p.wait_for_timeout(300)
    assert ("POST", "/whitelist?domain=xkqzp.example.com") in requetes
    ctx.close()


def test_annuler_ne_poste_rien(navigateur):
    ctx, p, _, requetes = _page(navigateur)
    p.wait_for_selector("#suspects button[data-act=allow]")
    p.click("#suspects button[data-act=allow]")
    p.click("#confNon")
    p.wait_for_timeout(200)
    assert not [r for r in requetes if r[0] == "POST"]
    ctx.close()


def test_aucun_html_venu_de_l_api_n_est_execute(navigateur):
    mal = "<img src=x onerror=window.__pwned=1>"
    al = {"alerts": [{"id": "a", "type": mal, "severity": mal, "domain": mal, "client_ip": mal, "description": "", "details": {}, "timestamp": "2026-10-04T05:00:00Z", "blocked": True}]}
    ctx, p, _, _ = _page(navigateur, rep={("GET", "/alerts"): al, ("GET", "/top-blocked"): {"domains": [{"domain": mal, "category": mal, "hits": 1}]}})
    p.wait_for_selector("#suspects td.m")
    p.wait_for_timeout(300)
    assert p.evaluate("window.__pwned") is None and p.locator("#suspects img, #top img, #clients img").count() == 0
    assert mal in p.text_content("#suspects")
    ctx.close()
