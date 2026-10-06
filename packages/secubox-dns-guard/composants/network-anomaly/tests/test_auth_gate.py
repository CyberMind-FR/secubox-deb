# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-network-anomaly — auth-gate regression test (#817
Task 7). `/status` used to be public; it now requires a JWT like every
other data route on this module. `/health` stays open (liveness).

No mocking of `require_jwt` is needed: the real dependency already
raises 401 when no Bearer token / session cookie is present, before it
ever touches the user store.
"""
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_status_requires_auth():
    resp = client.get("/status")
    assert resp.status_code == 401


def test_health_stays_open():
    resp = client.get("/health")
    assert resp.status_code == 200


def test_metrics_requires_auth():
    resp = client.get("/metrics")
    assert resp.status_code == 401


def test_detect_requires_auth():
    resp = client.post("/detect")
    assert resp.status_code == 401


def test_alerts_requires_auth():
    resp = client.get("/alerts")
    assert resp.status_code == 401


def test_baselines_requires_auth():
    resp = client.get("/baselines")
    assert resp.status_code == 401


def test_stats_requires_auth():
    resp = client.get("/stats")
    assert resp.status_code == 401
