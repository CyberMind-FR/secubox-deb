# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-iot-guard — retirement redirect tests (#817 Task 7).

secubox-iot-guard is retired: its api/main.py is now a thin shim whose
routes 308-redirect to the secubox-nac equivalents. `/health` stays a
plain 200 so liveness probes never 308-loop.
"""
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app, follow_redirects=False)


def test_health_is_not_redirected():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_devices_redirects_to_nac_clients():
    resp = client.get("/devices")
    assert resp.status_code == 308
    assert resp.headers["location"] == "/api/v1/nac/clients"
    assert resp.headers["x-secubox-deprecated"] == "use /api/v1/nac"


def test_status_redirects_to_nac_status():
    resp = client.get("/status")
    assert resp.status_code == 308
    assert resp.headers["location"] == "/api/v1/nac/status"


def test_device_mac_redirects_to_nac_client():
    resp = client.get("/device/aa:bb:cc:dd:ee:ff")
    assert resp.status_code == 308
    assert resp.headers["location"] == "/api/v1/nac/client/aa:bb:cc:dd:ee:ff"


def test_whitelist_redirects_to_nac_allow():
    resp = client.post("/whitelist")
    assert resp.status_code == 308
    assert resp.headers["location"] == "/api/v1/nac/allow"


def test_blacklist_redirects_to_nac_deny():
    resp = client.post("/blacklist")
    assert resp.status_code == 308
    assert resp.headers["location"] == "/api/v1/nac/deny"


def test_export_redirects_to_nac_export():
    resp = client.get("/export/csv")
    assert resp.status_code == 308
    assert resp.headers["location"] == "/api/v1/nac/export/csv"


def test_unmapped_path_falls_back_to_same_path_under_nac():
    resp = client.get("/alerts")
    assert resp.status_code == 308
    assert resp.headers["location"] == "/api/v1/nac/alerts"


def test_redirect_is_308_so_post_body_and_method_are_preserved():
    resp = client.post("/scan", json={"target": "10.0.0.0/24"})
    assert resp.status_code == 308
