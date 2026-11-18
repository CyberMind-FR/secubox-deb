# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3794 — squelette de secubox-garde : schéma de la base et réglages."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from garde import base  # noqa: E402

TABLES = {"decisions", "positions", "liberations", "file_notifs", "recidives"}
DEFAUTS = {"automatique": True, "courriel": "", "sms_utilisateur": "", "sms_bans": False,
           "quarantaines_max": 3, "rafale_bans": 50}


def _tables(cx):
    return {r[0] for r in cx.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def test_schema_cree_et_idempotent(tmp_path):
    chemin = tmp_path / "g.db"
    cx = base.ouvrir(chemin)
    assert TABLES <= _tables(cx)
    assert cx.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    cx.close()
    cx = base.ouvrir(chemin)
    assert TABLES <= _tables(cx)
    cx.close()


def test_contraintes_menace_et_etat(tmp_path):
    import sqlite3
    import pytest
    cx = base.ouvrir(tmp_path / "g.db")
    cx.execute("INSERT INTO decisions(id, menace, etat) VALUES ('a', 'infection', 'active')")
    with pytest.raises(sqlite3.IntegrityError):
        cx.execute("INSERT INTO decisions(id, menace, etat) VALUES ('b', 'inconnue', 'active')")
    with pytest.raises(sqlite3.IntegrityError):
        cx.execute("INSERT INTO decisions(id, menace, etat) VALUES ('c', 'evasion', 'autre')")
    cx.close()


def test_reglages_defauts_et_fichier_absent(tmp_path):
    assert base.reglages(tmp_path / "absent.toml") == DEFAUTS
    partiel = tmp_path / "p.toml"
    partiel.write_text('courriel = "a@b.fr"\nquarantaines_max = 5\n', encoding="utf-8")
    r = base.reglages(partiel)
    assert r == {**DEFAUTS, "courriel": "a@b.fr", "quarantaines_max": 5}


def test_reglages_illisible_rend_les_defauts(tmp_path):
    p = tmp_path / "x.toml"
    p.write_text("pas = du toml [[[", encoding="utf-8")
    assert base.reglages(p) == DEFAUTS


def test_api_gardes():
    from api import main
    from fastapi.testclient import TestClient
    assert TestClient(main.app).get("/api/v1/garde/health").json() == {"status": "ok", "module": "garde"}
    for r in main.app.routes:
        if getattr(r, "path", None) == "/api/v1/garde/etat":
            assert "require_lecture" in {d.call.__name__ for d in r.dependant.dependencies}
            return
    raise AssertionError("route /etat absente")
