# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: /health + /api/v1/health smoke tests (issue #197).

The Round UI dashboard (remote-ui/round/index.html) probes the host API
on first OTG connect:

    fetch http://10.55.0.1:8000/api/v1/health  timeout=2s

A 200 here is the signal that flips the badge from offline / SIM → OTG.
"""
from fastapi.testclient import TestClient

from api.main import app


def test_health_root_returns_200():
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "secubox-eye-remote"


def test_health_v1_returns_200():
    """Round dashboard probe path — must succeed for OTG online state."""
    client = TestClient(app)
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"


def test_health_root_and_v1_return_same_payload():
    """The two routes must alias to the same handler so any client that
    reads the response body sees identical fields."""
    client = TestClient(app)
    a = client.get("/health").json()
    b = client.get("/api/v1/health").json()
    assert a == b
