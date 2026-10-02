# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1857 : la sonde de session du Hall, et plus d'accès délégués."""
from fastapi.testclient import TestClient

from api.main import app, require_session


def test_session_exige_une_session_et_rend_qui_et_etiquette():
    c = TestClient(app)
    assert c.get("/session").status_code in (401, 403)
    app.dependency_overrides[require_session] = lambda: {"sub": "sbx-abc123"}
    try:
        j = c.get("/session").json()
        assert j["qui"] and "etiquette" in j
        assert "accordes" not in j and "demandes" not in j   # plus de délégation
    finally:
        app.dependency_overrides.clear()


def test_les_routes_d_acces_delegues_n_existent_plus():
    chemins = {r.path for r in app.routes}
    assert not [p for p in chemins if p.startswith("/acces")]
