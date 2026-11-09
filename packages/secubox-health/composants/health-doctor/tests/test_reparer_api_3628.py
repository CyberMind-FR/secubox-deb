# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Bouton « Réparer » (#3628) : la route dépose une demande sûre, gardée par require_jwt."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api import main  # noqa: E402
from secubox_core.auth import require_jwt  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    spool = tmp_path / "spool"
    spool.mkdir()
    monkeypatch.setattr(main, "REPARER_SPOOL", spool)
    monkeypatch.setattr(main, "REPARER_ETAT", tmp_path / "reparer.json")
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "gk2;$(id)"}
    yield TestClient(main.app), spool
    main.app.dependency_overrides.clear()


def test_depot_de_la_demande(client):
    c, spool = client
    r = c.post("/reparer/majauto")
    assert r.status_code == 202
    (f,) = list(spool.iterdir())
    assert f.name.endswith("-majauto.demande")
    assert f.read_text() == "reparer majauto gk2id\n"


@pytest.mark.parametrize("mauvais", ["Hub", "a.b", "-x", "x" * 70, "a_b"])
def test_identifiant_invalide(client, mauvais):
    c, spool = client
    assert c.post(f"/reparer/{mauvais}").status_code == 400
    assert not list(spool.iterdir())


def test_suivi_vide_puis_lu(client, tmp_path):
    c, _ = client
    assert c.get("/reparer").json() == {"modules": {}}
    (tmp_path / "reparer.json").write_text('{"modules": {"majauto": {"ok": true, "phase": "fini"}}}')
    assert c.get("/reparer").json()["modules"]["majauto"]["ok"] is True


def test_garde_jwt_posee():
    for route in main.app.routes:
        if getattr(route, "path", "").startswith("/reparer"):
            deps = [d.call for d in route.dependant.dependencies]
            assert require_jwt in deps, route.path


def test_deuxieme_demande_refusee_409(client, tmp_path):
    c, spool = client
    assert c.post("/reparer/majauto").status_code == 202
    assert c.post("/reparer/majauto").status_code == 409        # demande encore dans le dossier
    for f in spool.iterdir():
        f.unlink()
    (tmp_path / "reparer.json").write_text('{"modules": {"majauto": {"phase": "en_cours"}}}')
    assert c.post("/reparer/majauto").status_code == 409        # réparation en cours
    assert c.post("/reparer/hub").status_code == 202


def test_aucun_fichier_cache_ne_reste(client):
    c, spool = client
    c.post("/reparer/majauto")
    assert not [f for f in spool.iterdir() if f.name.startswith(".")]
