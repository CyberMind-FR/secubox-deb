# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""La voix est ouverte aux personnes, débit borné ; l'administration reste admin (#1615)."""
from fastapi.testclient import TestClient

import api.main as m
from secubox_core.auth import require_personne, require_jwt


def test_sans_session_refuse():
    c = TestClient(m.app)
    assert c.post("/tts", json={"texte": "bonjour"}).status_code == 401
    assert c.post("/asr", files={"fichier": ("a.wav", b"x")}).status_code == 401


def test_administration_reste_admin():
    routes = {r.path: r for r in m.router.routes}
    for chemin in ("/moteur", "/profils"):
        deps = [d.dependency for d in routes[chemin].dependencies]
        assert require_jwt in deps, chemin


def test_debit_par_personne():
    m._DEBIT.clear()
    qui = {"sub": "alice"}
    assert all(m._debit(qui, "asr", 12) is None for _ in range(12))
    assert m._debit(qui, "asr", 12).status_code == 429
    assert m._debit({"sub": "bob"}, "asr", 12) is None


def test_personne_passe_la_garde(monkeypatch):
    m._DEBIT.clear()
    m.app.dependency_overrides[require_personne] = lambda: {"sub": "alice"}
    try:
        r = TestClient(m.app).post("/tts", json={"texte": "   "})
        assert r.status_code == 400          # garde franchie, texte vide refusé
    finally:
        m.app.dependency_overrides.clear()
