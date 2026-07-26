# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os, sys
from pathlib import Path
ANNUAIRE = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
RELEASE_LIB = str(Path(__file__).resolve().parent.parent)
CORE = str(Path(__file__).resolve().parents[2].parent / "common")
sys.path.insert(0, ANNUAIRE)
sys.path.insert(0, RELEASE_LIB)
sys.path.insert(0, CORE)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("ANNUAIRE_JOURNAL", "/tmp/release-test-journal.db")
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_status_public():
    r = client.get("/status")
    assert r.status_code == 200
    body = r.json()
    assert body["module"] == "release"


def test_health_public():
    r = client.get("/health")
    assert r.status_code == 200


def test_evolutions_requires_jwt():
    r = client.get("/evolutions")
    assert r.status_code in (401, 403)


def test_box_ring_requires_jwt():
    r = client.get("/box-ring")
    assert r.status_code in (401, 403)


def test_publish_requires_jwt():
    r = client.post("/publish", json={"artifacts": [], "notes": "x"})
    assert r.status_code in (401, 403)


def test_promote_requires_jwt():
    r = client.post("/promote", json={"evo_id": "evo-x"})
    assert r.status_code in (401, 403)


def test_demote_requires_jwt():
    r = client.post("/demote", json={"evo_id": "evo-x"})
    assert r.status_code in (401, 403)


def test_assign_requires_jwt():
    r = client.post("/assign", json={"box_did": "did:x", "ring": "internal"})
    assert r.status_code in (401, 403)
