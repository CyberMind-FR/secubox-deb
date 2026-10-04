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
MENACES = {"threats": [{"timestamp": "2026-10-04T05:00:00Z", "domain": "xkqzp.example.com", "type": "dga", "client_ip": "192.168.1.5", "blocked": True}]}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _page(navigateur, rep=None):
    rep = {("GET", "/status"): STATUS, ("GET", "/top-blocked"): TOP, ("GET", "/threats"): MENACES, **(rep or {})}
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


def test_les_cartes_montrent_les_vrais_chiffres(navigateur):
    ctx, p, erreurs, _ = _page(navigateur)
    p.wait_for_function("document.getElementById('queries-24h').textContent.trim() !== '-'")
    assert chiffres(p.inner_text("#queries-24h")) == "38000" and chiffres(p.inner_text("#blocked-24h")) == "7109" and chiffres(p.inner_text("#blocklist-size")) == "656704"
    assert not erreurs
    ctx.close()


def test_malware_et_phishing_absents_sont_un_tiret_pas_un_zero(navigateur):
    ctx, p, _, _ = _page(navigateur)
    p.wait_for_function("document.getElementById('malware-blocked').textContent.trim() !== '-'")
    assert p.inner_text("#malware-blocked") == "—" and p.inner_text("#phishing-blocked") == "—"
    note = p.inner_text("#stats-note")
    assert "ad-guard" in note and "aujourd'hui" in note and "ne distingue pas" in note
    ctx.close()


def test_aucune_source_donne_des_tirets_partout(navigateur):
    vide = dict(STATUS, queries_24h=None, blocked_24h=None, blocklist_size=0, sources={"dns": False, "puits": False})
    ctx, p, _, _ = _page(navigateur, rep={("GET", "/status"): vide})
    p.wait_for_function("document.getElementById('queries-24h').textContent.trim() !== '-'")
    assert p.inner_text("#queries-24h") == "—" and p.inner_text("#blocked-24h") == "—" and "indisponibles" in p.inner_text("#stats-note")
    ctx.close()


def test_top_des_domaines_bloques(navigateur):
    ctx, p, _, _ = _page(navigateur)
    p.wait_for_selector("#top-blocked-table code")
    texte = p.text_content("#top-blocked-table")
    assert "pub.example.com" in texte and "advertising" in texte and chiffres(texte).count("1234") == 1
    assert "192.168" not in texte
    ctx.close()


def test_top_vide_dit_aucune_donnee(navigateur):
    ctx, p, _, _ = _page(navigateur, rep={("GET", "/top-blocked"): {"domains": []}})
    p.wait_for_selector("#top-blocked-table .empty-state")
    assert "Aucune donnée" in p.inner_text("#top-blocked-table")
    ctx.close()


def test_menaces_recentes_et_bouton_allow(navigateur):
    ctx, p, _, requetes = _page(navigateur)
    p.on("dialog", lambda d: d.accept())
    p.wait_for_selector("#threats-table code")
    assert "xkqzp.example.com" in p.text_content("#threats-table") and "dga" in p.text_content("#threats-table")
    p.click("#threats-table button")
    p.wait_for_timeout(300)
    assert ("POST", "/whitelist?domain=xkqzp.example.com") in requetes                  # la VRAIE route du module
    ctx.close()


def test_aucune_menace_garde_le_message(navigateur):
    ctx, p, _, _ = _page(navigateur, rep={("GET", "/threats"): {"threats": []}})
    p.wait_for_selector("#threats-table .empty-state")
    assert "No threats detected" in p.inner_text("#threats-table")
    ctx.close()


def test_aucun_html_venu_de_l_api_n_est_execute(navigateur):
    mal = "<img src=x onerror=window.__pwned=1>"
    top = {"domains": [{"domain": mal, "category": mal, "hits": 1}]}
    men = {"threats": [{"timestamp": "2026-10-04T05:00:00Z", "domain": mal, "type": mal, "client_ip": mal, "blocked": True}]}
    ctx, p, _, _ = _page(navigateur, rep={("GET", "/top-blocked"): top, ("GET", "/threats"): men})
    p.wait_for_selector("#top-blocked-table code")
    p.wait_for_selector("#threats-table code")
    p.wait_for_timeout(300)
    assert p.evaluate("window.__pwned") is None and p.locator("#top-blocked-table img, #threats-table img").count() == 0
    assert mal in p.text_content("#top-blocked-table") and mal in p.text_content("#threats-table")
    ctx.close()
