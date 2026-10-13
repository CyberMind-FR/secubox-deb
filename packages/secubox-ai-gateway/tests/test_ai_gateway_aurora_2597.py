# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2597 — /ai-gateway/ au profil Aurora : test statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
PAGE = RACINE / "www" / "ai-gateway" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "/shared/crt-engine.js" not in SRC and "hybrid-dark" not in SRC and "fonts.googleapis" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'ai-gateway'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_lecture_seule_et_aucune_cle_manipulee():
    # l'ancienne page n'écrivait rien : la nouvelle non plus
    assert "method:" not in SRC.replace("method: 'GET'", "") and "POST" not in SRC and "DELETE" not in SRC
    assert "localStorage.setItem" not in SRC
    # ne lit que le jeton de session de l'administrateur, jamais une clé de fournisseur
    assert re.findall(r"localStorage\.getItem\('([^']+)'\)", SRC) == ["sbx_token"]
    assert not re.search(r"(?<!has_)api_key", SRC)  # seul has_api_key (booléen) est lu


def test_routes_reelles_uniquement():
    # /stats, /config et /requests n'ont jamais existé côté API
    for r in ("/status", "/providers", "/audit/stats?hours=24", "/cache/stats", "/rate-limits"):
        assert "'" + r + "'" in SRC
    for fantome in ("'/stats'", "'/config'", "/requests", "gpt-4", "cost_estimate", "tokens_used"):
        assert fantome not in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"module": "ai-gateway", "status": "ok", "version": "1.0.0", "offline_mode": True}
PROVS = {"providers": [
    {"name": "localai", "enabled": True, "priority": 1, "classification": "local_only", "model": "m-local", "status": "available", "has_api_key": None},
    {"name": "mistral", "enabled": True, "priority": 2, "classification": "sanitized", "model": "m-eu", "status": "configured", "has_api_key": True},
    {"name": "openai", "enabled": False, "priority": 4, "classification": "cloud_direct", "model": "m-x", "status": "disabled", "has_api_key": False}]}
AUDIT = {"total_requests": 40, "by_classification": {"local_only": 25, "sanitized": 10, "cloud_direct": 5}, "by_provider": {"localai": 25, "mistral": 15}, "errors": 3}
CACHE = {"memory_entries": 4, "file_entries": 6, "max_age_seconds": 3600}
LIM = {"limits": {"local_only": 100, "sanitized": 30, "cloud_direct": 20}}
API = {"/status": (200, STATUS), "/providers": (200, PROVS), "/audit/stats": (200, AUDIT), "/cache/stats": (200, CACHE), "/rate-limits": (200, LIM)}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "ai-gateway":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/ai-gateway", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get(chemin, (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/ai-gateway/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableau_viennent_de_l_api(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/ai-gateway/", API)
    p.wait_for_selector("#bProv tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tMode", "#tReq", "#tErr", "#tProv")] == ["ACTIF", "40", "3", "2"]
    assert p.inner_text("#tCache") == "10" and p.inner_text("#etat") == "EN LIGNE"
    tab = p.inner_text("#bProv")
    assert "DISPONIBLE" in tab and "CONFIGURÉ" in tab and "DÉSACTIVÉ" in tab
    assert "CONFIGURÉE" in tab and "ABSENTE" in tab and "SANS OBJET" in tab
    assert "25" in p.inner_text("#lClasse") and "localai" in p.inner_text("#lFourn")
    assert "100 req/min" in p.inner_text("#kRl1") and "60 min" in p.inner_text("#kAge")
    assert err == [] and all(a[0] == "GET" for a in appels)
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/ai-gateway/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tMode", "#tReq", "#tErr", "#tProv", "#tCache")] == ["—"] * 5 and err == []
    ctx.close()


def test_jeton_session_envoye(navigateur):
    ctx = navigateur.new_context()
    p = ctx.new_page()
    entetes = []
    p.route("http://sbx.test/api/v1/ai-gateway/**", lambda r, *_: (entetes.append(r.request.headers.get("authorization")), r.fulfill(status=404, body="{}")))
    p.route("http://sbx.test/ai-gateway/", lambda r, *_: r.fulfill(status=200, content_type="text/html", body=SRC))
    p.route("http://sbx.test/shared/**", lambda r, *_: r.fulfill(status=200, body=""))
    p.goto("http://sbx.test/ai-gateway/")
    p.evaluate("localStorage.setItem('sbx_token','jeton-factice')")
    p.click("#rafraichir")
    p.wait_for_timeout(300)
    assert "Bearer jeton-factice" in entetes
    ctx.close()


def test_demonstration_annoncee_et_inerte(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/ai-gateway/?demo=1", {})
    p.wait_for_selector("#bProv tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert re.sub(r"\D", "", p.inner_text("#tReq")) == "1248"
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/ai-gateway/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bProv tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
