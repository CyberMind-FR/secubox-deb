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


def test_audit_en_echec_laisse_le_mode_et_repond_503(client, monkeypatch, tmp_path):
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "absent" / "audit.log"))
    r = client.post("/defense/mode", json={"mode": "reactive"}, headers=ADMIN)
    assert r.status_code == 503 and r.json()["cause"] == "audit_indisponible"
    assert defense_etat.mode_courant() == "observe"


def test_deux_changements_chainent_l_audit(client, audit):
    client.post("/defense/mode", json={"mode": "reactive"}, headers=ADMIN)
    client.post("/defense/mode", json={"mode": "observe"}, headers=ADMIN)
    l = audit.chemin.read_text(encoding="utf-8").splitlines()
    assert len(l) == 2
    assert "ancien=observe nouveau=reactive" in l[0] and "ancien=reactive nouveau=observe" in l[1]
    assert defense_etat.mode_courant() == "observe"
    client.post("/defense/mode", json={"mode": "observe"}, headers=ADMIN)  # inchangé : pas de ligne
    assert len(audit.chemin.read_text(encoding="utf-8").splitlines()) == 2


def test_liste_blanche_amorcee_protegee_en_base():
    defense_etat.mode_courant()
    db = sqlite3.connect(defense_etat._chemin_db())
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("DELETE FROM liste_blanche WHERE cidr = '10.0.0.0/8'")
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("UPDATE liste_blanche SET motif = 'x' WHERE cidr = '10.0.0.0/8'")


def test_status_montre_le_mode_vivant(client):
    from api import defense
    defense._CACHE.clear()
    assert client.get("/defense/status", headers=LECTURE).json()["mode"] == "observe"
    client.post("/defense/mode", json={"mode": "reactive"}, headers=ADMIN)
    assert client.get("/defense/status", headers=LECTURE).json()["mode"] == "reactive"


def test_operateur_assaini(client, audit):
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "x\n2026 sade-mode forge " + "a" * 100}
    client.post("/defense/mode", json={"mode": "reactive"}, headers=ADMIN)
    d = audit.chemin.read_text(encoding="utf-8")
    assert d.count("\n") == 1 and len(d.split("operateur=")[1].strip()) <= 64 and " forge" not in d


def test_base_indisponible_degrade_sans_500(client, monkeypatch, tmp_path):
    f = tmp_path / "fichier"
    f.write_text("x")
    monkeypatch.setenv("SECUBOX_SOC_DEFENSE_DB", str(f / "sous" / "defense.db"))  # parent = fichier : mkdir échoue
    j = client.get("/defense/policies", headers=LECTURE).json()
    assert j["mode"] == "observe" and j["etat_base"] == "indisponible"
    assert client.post("/defense/mode", json={"mode": "reactive"}, headers=ADMIN).status_code == 503


def test_insert_or_replace_sur_cidr_amorce_refuse():
    defense_etat.mode_courant()
    db = sqlite3.connect(defense_etat._chemin_db())
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("INSERT OR REPLACE INTO liste_blanche(cidr, motif, par, ts, amorcee) VALUES ('10.0.0.0/8','x','y','t',0)")
    assert db.execute("SELECT amorcee FROM liste_blanche WHERE cidr = '10.0.0.0/8'").fetchone() == (1,)
    db.execute("INSERT INTO liste_blanche(cidr, motif, par, ts, amorcee) VALUES ('203.0.113.0/24','test','op','t',0)")
    assert db.execute("SELECT COUNT(*) FROM liste_blanche").fetchone() == (10,)
