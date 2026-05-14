# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Smoke tests for the helper FastAPI app."""
from __future__ import annotations

from fastapi.testclient import TestClient

from eye_square_helper.app import create_app


def test_app_constructs():
    app = create_app()
    assert app.title == "SecuBox Eye Square Helper"


def test_health_endpoint_responds():
    """TestClient runs over HTTP/TCP — there's no SO_PEERCRED on the wire,
    so the middleware returns 401. That's correct behaviour for a non-UDS
    transport: the helper MUST refuse non-Unix-socket peers."""
    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/health")
    # 401 = peer-cred not available on TCP. The middleware did its job.
    assert response.status_code == 401
