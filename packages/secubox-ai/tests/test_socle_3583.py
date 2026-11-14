# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Socle du module secubox-ai (#3583) : application, garde de toutes les routes, /health."""
from fastapi.testclient import TestClient
from fastapi.routing import APIRoute

from secubox_core.auth import require_jwt
from api.main import app


def _routes_api():
    return [r for r in app.routes if isinstance(r, APIRoute)]


def test_toute_route_est_gardee():
    routes = _routes_api()
    assert routes, "aucune route"
    for route in routes:
        if route.path == "/health":
            continue
        appels = [d.call for d in route.dependant.dependencies]
        assert require_jwt in appels, f"route non gardée : {route.methods} {route.path}"


def test_health():
    rep = TestClient(app).get("/health")
    assert rep.status_code == 200
    assert rep.json() == {"status": "ok", "module": "ai"}


def test_status_refuse_sans_jeton():
    assert TestClient(app).get("/status").status_code in (401, 403)


def test_status_garde_et_forme(monkeypatch):
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    try:
        rep = TestClient(app).get("/status")
    finally:
        app.dependency_overrides.clear()
    assert rep.status_code == 200
    corps = rep.json()
    assert corps["module"] == "ai" and "version" in corps and "moteur" in corps


def test_documentation_automatique_fermee():
    # Ni /docs, ni /redoc, ni /openapi.json : la carte de l'API n'est pas servie (même derrière require_jwt de nginx).
    assert app.docs_url is None and app.redoc_url is None and app.openapi_url is None
    client = TestClient(app)
    for chemin in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(chemin).status_code == 404, chemin
