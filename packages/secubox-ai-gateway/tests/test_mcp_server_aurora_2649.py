# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2649 — /mcp-server/ au profil Aurora : page statique + vrai navigateur, API simulée (données factices)."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "composants/mcp-server/www/mcp-server/index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "hybrid-dark" not in SRC and "crt-" not in SRC and "fonts.googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "onsubmit="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'mcp-server'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "localStorage.getItem('sbx_token')" in SRC and "'Bearer ' + t" in SRC


def test_aucun_secret_ni_stockage():
    assert "setItem" not in SRC and "Math.random" not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "mcp-server":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/mcp-server", 1)[1]
        appels.append((r.request.method, chemin, r.request.post_data))
        cle = chemin.split("?")[0]
        if r.request.method == "GET":
            statut, corps = routes.get(chemin, routes.get(cle, (404, {})))
        else:
            statut, corps = routes.get(cle, (200, {"success": True}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/mcp-server/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


STATUS = {"module": "mcp-server", "status": "ok", "version": "1.0.0", "mcp_version": "2024-11-05", "tools": 2, "resources": 5}
STATS = {"sessions": 3, "tools": 2, "resources": 5, "prompts": 4}
TOOLS = {"tools": [{"name": "outil_a", "description": "Premier outil", "inputSchema": {"type": "object", "properties": {"x": {}, "y": {}}}},
                   {"name": "outil_b", "description": "<b>pas du html</b>", "inputSchema": {"type": "object", "properties": {}}}]}
REQS = {"requests": [{"timestamp": "2026-10-14T10:00:00Z", "client": "cli-1", "tool": "outil_a", "latency_ms": 42, "success": True},
                     {"timestamp": "2026-10-14T10:01:00Z", "client": "cli-2", "tool": "outil_b", "latency_ms": 7, "success": False}]}
API = {"/status": (200, STATUS), "/stats": (200, STATS), "/tools": (200, TOOLS), "/requests?limit=10": (200, REQS)}
URL = "http://sbx.test/mcp-server/"


def test_routes_lues_et_aucune_ecriture():
    for r in ("'/status'", "'/stats'", "'/tools'", "'/requests?limit=10'"):
        assert r in SRC
    assert "'POST'" not in SRC and "'DELETE'" not in SRC


def test_tuiles_outils_et_requetes_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL, API)
    p.wait_for_selector("#lOutils .elt")
    assert [p.inner_text(i) for i in ("#tClients", "#tOutils", "#tRes", "#tPrompts", "#tReq", "#tLat")] == ["3", "2", "5", "4", "—", "—"]
    assert p.inner_text("#etat") == "EN LIGNE" and p.inner_text("#dMcp") == "2024-11-05"
    t = p.inner_text("#lOutils")
    assert "outil_a" in t and "Paramètres : x, y" in t and "<b>pas du html</b>" in t       # texte, pas du HTML
    assert p.locator("#lOutils b").count() == 0
    r = p.inner_text("#bReq")
    assert "cli-1" in r and "42 ms" in r and "ÉCHEC" in r and "RÉUSSIE" in r
    assert err == []
    ctx.close()


def test_journal_absent_est_dit_sans_inventer(navigateur):
    routes = {k: v for k, v in API.items() if k != "/requests?limit=10"}
    ctx, p, err, _ = ouvre(navigateur, URL, routes)
    p.wait_for_selector("#lOutils .elt")
    assert "n’existe pas" in p.inner_text("#nReq") and p.locator("#bReq tr").count() == 1
    assert p.is_hidden("#session") and err == []
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, URL, refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tClients", "#tOutils", "#tRes", "#tPrompts", "#tReq", "#tLat")] == ["—"] * 6 and err == []
    ctx.close()


def test_demonstration_annoncee_sans_appel(navigateur):
    ctx, p, err, appels = ouvre(navigateur, URL + "?demo=1", {})
    p.wait_for_selector("#lOutils .elt")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, URL + "?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#lOutils .elt")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
