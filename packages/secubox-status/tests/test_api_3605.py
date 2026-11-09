# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3605 — l'API Status ne sert rien sans garde (arbitrage §11.1), seule la sonde /health est publique."""
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api import main  # noqa: E402

LECTURE = {"/api/v1/status/status", "/api/v1/status/summary", "/api/v1/status/history"}
ADMIN = {"/api/v1/status/admin/snapshot", "/api/v1/status/admin/sources"}


def _gardes(chemin):
    for r in main.app.routes:
        if getattr(r, "path", None) == chemin:
            return {d.call.__name__ for d in r.dependant.dependencies}
    raise AssertionError(chemin)


def test_sonde_publique_et_chaque_route_gardee():
    assert TestClient(main.app).get("/api/v1/status/health").json() == {"status": "ok", "module": "status"}
    for c in LECTURE:
        assert "require_lecture" in _gardes(c), c
    for c in ADMIN:
        assert "require_jwt" in _gardes(c), c
    chemins = {r.path for r in main.app.routes if r.path.startswith("/api/v1/status/")}
    assert chemins == LECTURE | ADMIN | {"/api/v1/status/health"}


def test_admin_refuse_sans_jeton():
    c = TestClient(main.app)
    for chemin in ADMIN:
        assert c.get(chemin).status_code in (401, 403), chemin


def test_aucune_route_mutante():
    for route in main.app.routes:
        assert not (set(getattr(route, "methods", set()) or set()) - {"GET", "HEAD"}), route.path
