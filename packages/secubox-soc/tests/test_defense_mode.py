# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3839 — mode et politique SADE : persistance, audit, liste blanche amorcée, modes différés."""
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient  # noqa: E402

from api import defense_etat, main  # noqa: E402
from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

LECTURE = {"Authorization": "Bearer lecteur"}
ADMIN = {"Authorization": "Bearer admin"}


class Audit:
    def __init__(self, chemin):
        self.chemin = chemin

    def derniere(self):
        return self.chemin.read_text(encoding="utf-8").splitlines()[-1]


@pytest.fixture(autouse=True)
def isole(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_SOC_DEFENSE_DB", str(tmp_path / "defense.db"))
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")  # le harnais racine arme sinon le mode tableau de bord


@pytest.fixture
def audit(tmp_path):
    return Audit(tmp_path / "audit.log")


@pytest.fixture
def client():
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": "lecteur"}
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "gerald"}
    yield TestClient(main.app)
    main.app.dependency_overrides.pop(require_lecture, None)
    main.app.dependency_overrides.pop(require_jwt, None)


def test_mode_par_defaut_observe(client):
    j = client.get("/defense/policies", headers=LECTURE).json()
    assert j["mode"] == "observe" and j["modes_ouverts"] == ["observe", "reactive"]
    assert [b["nom"] for b in j["bandes"]] == ["observer", "reactive", "contenir", "usager", "incident"]


@pytest.mark.parametrize("m", ["active", "aggressive"])
def test_modes_differes_refuses(client, m):
    r = client.post("/defense/mode", json={"mode": m}, headers=ADMIN)
    assert r.status_code == 409 and r.json()["cause"] == "gestes_non_livres" and r.json()["error"]
    assert defense_etat.mode_courant() == "observe"


def test_mode_inconnu_400(client):
    assert client.post("/defense/mode", json={"mode": "x"}, headers=ADMIN).status_code == 400


def test_lecture_ne_change_pas_le_mode(monkeypatch):
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "secret-de-test-seulement")
    r = TestClient(main.app).post("/defense/mode", json={"mode": "reactive"}, headers=LECTURE)
    assert r.status_code in (401, 403)


def test_changement_audite_et_persistant(client, audit):
    assert client.post("/defense/mode", json={"mode": "reactive"}, headers=ADMIN).status_code == 200
    assert defense_etat.mode_courant() == "reactive"
    d = audit.derniere()
    assert "sade-mode" in d and "reactive" in d and "observe" in d and "gerald" in d
    assert client.get("/defense/policies", headers=LECTURE).json()["mode"] == "reactive"


def test_liste_blanche_amorcee_non_supprimable(client):
    lb = client.get("/defense/policies", headers=LECTURE).json()["liste_blanche"]
    cidrs = {e["cidr"] for e in lb}
    assert {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
            "::1/128", "fc00::/7", "fe80::/10"} <= cidrs
    assert all(e["supprimable"] is False for e in lb)


def test_migration_idempotente_et_tables():
    defense_etat.mode_courant()
    defense_etat.mode_courant()
    db = sqlite3.connect(defense_etat._chemin_db())
    assert db.execute("SELECT version FROM schema_migrations").fetchall() == [(1,)]
    assert db.execute("SELECT COUNT(*) FROM liste_blanche").fetchone()[0] == 9
    assert {t for (t,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'")} >= {
        "mode", "seuils", "liste_blanche", "decisions"}
    assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
