# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 — GET /par-nom/{username} : l'avatar d'une identité par son nom d'usager, pour la carte d'usager du Hall."""
from fastapi.testclient import TestClient

import api.main as m

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


def _prepare(monkeypatch, tmp_path):
    monkeypatch.setattr(m, "IMAGES_DIR", tmp_path)
    monkeypatch.setattr(m, "_load_identities", lambda: {
        "u-1": {"id": "u-1", "username": "gek", "display_name": "Gérald"},
        "u-2": {"id": "u-2", "username": "sans-image", "display_name": "Personne"},
    })
    (tmp_path / "u-1.png").write_bytes(PNG)
    m.app.dependency_overrides[m.require_lecture] = lambda: {"sub": None, "tableau_de_bord": True}
    return TestClient(m.app)


def test_image_par_nom_d_usager(monkeypatch, tmp_path):
    c = _prepare(monkeypatch, tmp_path)
    r = c.get("/par-nom/gek")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png" and r.content == PNG
    assert r.headers["cache-control"] == "private, max-age=300"
    m.app.dependency_overrides.clear()


def test_404_sans_image_inconnu_ou_nom_invalide(monkeypatch, tmp_path):
    c = _prepare(monkeypatch, tmp_path)
    assert c.get("/par-nom/sans-image").status_code == 404
    assert c.get("/par-nom/inconnu").status_code == 404
    assert c.get("/par-nom/..%2Fu-1").status_code == 404
    assert c.get("/par-nom/a").status_code == 404
    m.app.dependency_overrides.clear()


def test_la_garde_de_lecture_s_applique_hors_tableau_de_bord(monkeypatch, tmp_path):
    import secubox_core.auth as auth
    _prepare(monkeypatch, tmp_path)
    m.app.dependency_overrides.clear()
    # sans jeton ni cookie, et sans le mode tableau de bord du LAN : refus
    monkeypatch.setattr(auth, "mode_tableau_de_bord_actif", lambda: False)
    assert TestClient(m.app).get("/par-nom/gek").status_code == 401
