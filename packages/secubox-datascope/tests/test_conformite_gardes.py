# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3853 — gardes par route et absence de route mutante."""
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from api import main  # noqa: E402
from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

P = "/api/v1/datascope"
TOPOLOGIE = ["/entities", "/entities/device:aa", "/entities/device:aa/context", "/entities/device:aa/neighbors",
             "/graph", "/paysage", "/paysage/chronologie", "/paysage/instantane/2026-11-24T10:00:00.000000Z",
             "/paysage/difference", "/paysage/tendance/pop:x"]


def _refuse():
    raise HTTPException(status_code=403, detail="administrateur requis")


@pytest.fixture
def lecteur():
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "lecteur"}
    main.app.dependency_overrides[require_jwt] = _refuse
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def test_lecteur_refuse_sur_topologie(lecteur):
    for chemin in TOPOLOGIE:
        assert lecteur.get(P + chemin).status_code in (401, 403), chemin
    assert lecteur.get(P + "/overview").status_code == 200


def test_aucune_route_mutante():
    for r in main.app.routes:
        methodes = getattr(r, "methods", None) or set()
        assert methodes <= {"GET", "HEAD"}, (r.path, methodes)


def test_chaque_route_a_sa_garde():
    attendu = {"/health": None, "/status": require_lecture, "/overview": require_lecture,
               "/sources": require_lecture}
    for c in TOPOLOGIE:
        c = c.replace("device:aa", "{id}").replace("/2026-11-24T10:00:00.000000Z", "/{ts}")
        attendu[c.replace("/tendance/pop:x", "/tendance/{id}")] = require_jwt
    vus = {}
    for r in main.app.routes:
        if isinstance(r, APIRoute):
            vus[r.path.removeprefix(P)] = [d.call for d in r.dependant.dependencies]
    for chemin, garde in attendu.items():
        assert vus[chemin] == ([garde] if garde else []), chemin
