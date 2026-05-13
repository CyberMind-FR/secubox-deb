# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for helper /service/restart route — allow-listed systemd units only."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from eye_square_helper.app import create_app


@pytest.fixture
def client():
    return TestClient(create_app(), raise_server_exceptions=False)


def _auth_patches():
    """Mock both peer-cred extraction and UID lookup so requests pass middleware."""
    class _FakeSocket:
        pass
    sock_patch = patch("eye_square_helper.app._extract_peer_socket", return_value=_FakeSocket())
    uid_patch = patch("eye_square_helper.app.get_peer_uid", return_value=0)
    return sock_patch, uid_patch


def test_restart_allowed_unit(client):
    sock_p, uid_p = _auth_patches()
    with sock_p, uid_p, patch("eye_square_helper.routes.service._run_systemctl") as mock_sysctl:
        mock_sysctl.return_value = ("", 0)
        response = client.post("/service/restart", json={"unit": "secubox-hub"})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["unit"] == "secubox-hub"
        assert body["verb"] == "restart"
        assert body["exit_code"] == 0


def test_restart_rejects_arbitrary_unit(client):
    sock_p, uid_p = _auth_patches()
    with sock_p, uid_p:
        # nginx is a real unit name but not in our allow-list
        response = client.post("/service/restart", json={"unit": "nginx"})
        assert response.status_code == 403


def test_restart_validation_rejects_injection_attempt(client):
    sock_p, uid_p = _auth_patches()
    with sock_p, uid_p:
        # Semicolons / shell metacharacters MUST fail Pydantic pattern
        response = client.post("/service/restart", json={"unit": "secubox-hub; rm -rf /"})
        assert response.status_code == 422


def test_restart_propagates_systemctl_failure(client):
    sock_p, uid_p = _auth_patches()
    with sock_p, uid_p, patch("eye_square_helper.routes.service._run_systemctl") as mock_sysctl:
        mock_sysctl.return_value = ("unit not found", 1)
        response = client.post("/service/restart", json={"unit": "secubox-hub"})
        assert response.status_code == 500
