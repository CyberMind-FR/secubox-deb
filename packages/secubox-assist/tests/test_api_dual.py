# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: assist API — marketplace endpoints, JWT gating smoke tests."""
import os
import sys
from pathlib import Path

ANNUAIRE = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
CORE = str(Path(__file__).resolve().parents[2].parent / "common")
sys.path.insert(0, ANNUAIRE)
sys.path.insert(0, CORE)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("ANNUAIRE_JOURNAL", "/tmp/assist-dual-test-journal.db")

from fastapi.testclient import TestClient  # noqa: E402

from api.main import app  # noqa: E402

client = TestClient(app)


def test_matches_requires_jwt():
    r = client.get("/matches")
    assert r.status_code in (401, 403)


def test_offer_requires_jwt():
    r = client.post("/offer", json={"tags": ["lora"], "ttl_s": 600})
    assert r.status_code in (401, 403)


def test_offers_requires_jwt():
    r = client.get("/offers")
    assert r.status_code in (401, 403)


def test_requests_open_requires_jwt():
    r = client.get("/requests/open")
    assert r.status_code in (401, 403)


def test_offer_revoke_requires_jwt():
    r = client.post("/offer/revoke", json={"offer_id": "off-x"})
    assert r.status_code in (401, 403)


def test_request_open_requires_jwt():
    r = client.post("/request/open", json={"tags": ["lora"], "ttl_s": 600, "reason": "x"})
    assert r.status_code in (401, 403)


def test_match_accept_requires_jwt():
    r = client.post("/match/accept", json={"offer_id": "o", "req_id": "r", "side": "offer"})
    assert r.status_code in (401, 403)


def test_joinlink_requires_jwt():
    r = client.post("/joinlink", json={"ref": "match-x", "ttl_s": 300})
    assert r.status_code in (401, 403)


def test_status_and_health_still_public():
    assert client.get("/status").status_code == 200
    assert client.get("/health").status_code == 200
