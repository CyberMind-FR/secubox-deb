# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os, sys
from pathlib import Path
ANNUAIRE = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
CORE = str(Path(__file__).resolve().parents[2].parent / "common")
sys.path.insert(0, ANNUAIRE)
sys.path.insert(0, CORE)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("ANNUAIRE_JOURNAL", "/tmp/assist-test-journal.db")
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


def test_status_public():
    r = client.get("/status")
    assert r.status_code == 200
    body = r.json()
    assert body["module"] == "assist"
    assert "has_active_session" in body


def test_sessions_requires_jwt():
    r = client.get("/sessions")
    assert r.status_code in (401, 403)
