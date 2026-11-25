# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3921 — instantanés du paysage : migration 0002, écriture, éclaircissement, budget."""
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE))

from secubox_datascope import paysage_store as ps  # noqa: E402
from secubox_datascope import store  # noqa: E402

NOW = 1795000000.0


@pytest.fixture
def db(tmp_path):
    d = store.ouvrir(tmp_path / "d.db")
    yield d
    d.close()


def graphe(n=2):
    return {"noeuds": [{"id": f"n{i}"} for i in range(n)], "aretes": [{"src": "n0", "dst": "n1"}]}


def test_migration_0002_appliquee(db):
    assert db.execute("SELECT count(*) FROM sqlite_master WHERE name='paysage_instantanes'").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM schema_migrations WHERE version=2").fetchone()[0] == 1


def test_ecrire_lire_aller_retour(db):
    g = graphe(5)
    assert ps.ecrire(db, NOW, False, g, {"noeuds": 5}, {"ajoutes": 1}) is True
    d = ps.dernier(db)
    assert d["epoch"] == NOW and d["partiel"] is False and d["compteurs"] == {"noeuds": 5}
    assert ps.lire(db, d["ts"])["graphe"] == g
    taille = db.execute("SELECT octets, length(graphe) FROM paysage_instantanes").fetchone()
    assert taille[0] == taille[1]
    assert ps.lire(db, "absent") is None


def test_ecrire_refuse_doublon_et_recul(db):
    assert ps.ecrire(db, NOW, False, graphe(), {}, {})
    assert ps.ecrire(db, NOW, False, graphe(), {}, {}) is False
    assert ps.ecrire(db, NOW - 60, False, graphe(), {}, {}) is False
    assert ps.ecrire(db, NOW + 1800, True, graphe(), {}, {}) is True
    assert ps.dernier(db)["partiel"] is True


def test_chronologie_sans_graphe(db):
    for k in range(3):
        ps.ecrire(db, NOW + k * 1800, False, graphe(), {"k": k}, {})
    c = ps.chronologie(db, NOW + 1, NOW + 3600)
    assert [x["compteurs"]["k"] for x in c] == [1, 2]
    assert "graphe" not in c[0]


def test_eclaircir_horaire(db):
    for k in range(6):
        ps.ecrire(db, NOW - 50 * 3600 + k * 600, False, graphe(), {}, {})
    for k in range(4):
        ps.ecrire(db, NOW - 3600 + k * 600, False, graphe(), {}, {})
    assert ps.eclaircir(db, NOW) == 5
    assert db.execute("SELECT count(*) FROM paysage_instantanes").fetchone()[0] == 5


def test_eclaircir_retention(db):
    ps.ecrire(db, NOW - 31 * 86400, False, graphe(), {}, {})
    ps.ecrire(db, NOW - 10, False, graphe(), {}, {})
    assert ps.eclaircir(db, NOW) == 1
    assert ps.dernier(db)["epoch"] == NOW - 10


def test_budget_evince_anciens(db, monkeypatch):
    for k in range(10):
        ps.ecrire(db, NOW - 600 + k * 10, False, graphe(30), {}, {})
    un = db.execute("SELECT octets FROM paysage_instantanes").fetchone()[0]
    monkeypatch.setattr(ps, "BUDGET_OCTETS", un * 3)
    ps.eclaircir(db, NOW)
    restes = [r[0] for r in db.execute("SELECT epoch FROM paysage_instantanes ORDER BY epoch")]
    assert len(restes) == 3 and restes[-1] == NOW - 600 + 90
    monkeypatch.setattr(ps, "BUDGET_OCTETS", 1)
    ps.eclaircir(db, NOW)
    assert [r[0] for r in db.execute("SELECT epoch FROM paysage_instantanes")] == [NOW - 600 + 90]
