# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2212 : la page /apercu/ affiche l'agrégat, échappe le contenu des alertes, et signale une API illisible."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
WWW = Path(__file__).resolve().parents[1] / "www"
DONNEES = {"etat": "degrade", "uptime": 90061, "espaces": [
    {"id": "protection", "nom": "Protection", "icone": "🛡️", "total": 2, "actifs": 1, "arretes": ["fw"], "etat": "degrade"},
    {"id": "systeme", "nom": "Système", "icone": "⚙️", "total": 1, "actifs": 1, "arretes": [], "etat": "ok"}],
    "ressources": {"cpu": 12.5, "memoire": 40.0, "disque": None, "charge": [0.5, 0.4, 0.3]},
    "alertes": {"total": 1, "recentes": [{"title": "<img src=x onerror=window.__xss=1>"}]}}


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, statut=200, corps=DONNEES):
    ctx = navigateur.new_context()
    p = ctx.new_page()

    def fichier(r):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        f = WWW / chemin
        if f.is_dir():
            f = f / "index.html"
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif f.exists():
            r.fulfill(status=200, content_type={"html": "text/html", "js": "application/javascript", "css": "text/css"}[f.suffix[1:]], body=f.read_text(encoding="utf-8"))
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    p.route("http://sbx.test/api/v1/hub/apercu", lambda r: r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps)))
    p.goto("http://sbx.test/apercu/")
    return ctx, p


def test_la_page_affiche_etat_espaces_ressources_et_alertes(navigateur):
    ctx, p = ouvre(navigateur)
    p.wait_for_selector("#espaces .carte")
    assert "attention" in p.inner_text("#etat-titre") and "1 j 1 h 1 min" in p.inner_text("#etat-sous")
    t = p.inner_text("#espaces")
    assert "1 / 2" in t and "fw" in t and "Tous les services actifs" in t
    r = p.inner_text("#ressources")
    assert "13 %" in r and "40 %" in r and "—" in r
    ctx.close()


def test_le_contenu_des_alertes_n_est_jamais_interprete(navigateur):
    ctx, p = ouvre(navigateur)
    p.wait_for_selector("#alertes li")
    assert p.evaluate("window.__xss") is None and "<img" in p.inner_text("#alertes")
    ctx.close()


def test_api_illisible_affiche_une_erreur_claire(navigateur):
    ctx, p = ouvre(navigateur, 503, {})
    p.wait_for_selector("#erreur:not([hidden])")
    assert "HTTP 503" in p.inner_text("#erreur")
    ctx.close()
