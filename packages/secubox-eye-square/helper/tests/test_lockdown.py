# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for helper /lockdown route — atomic nft ruleset swap."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from eye_square_helper.app import create_app


@pytest.fixture
def client():
    return TestClient(create_app(), raise_server_exceptions=False)


def _auth_patches():
    class _FakeSocket:
        pass
    sock_patch = patch("eye_square_helper.app._extract_peer_socket", return_value=_FakeSocket())
    uid_patch = patch("eye_square_helper.app.get_peer_uid", return_value=0)
    return sock_patch, uid_patch


def test_lockdown_applies_when_confirmed(client):
    sock_p, uid_p = _auth_patches()
    with sock_p, uid_p, patch("eye_square_helper.routes.lockdown._apply_lockdown") as mock_apply:
        mock_apply.return_value = ("ruleset applied", 0)
        response = client.post("/lockdown", json={"confirm": "lockdown"})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["applied"] is True
        assert body["exit_code"] == 0


def test_lockdown_requires_exact_confirm_string(client):
    sock_p, uid_p = _auth_patches()
    with sock_p, uid_p:
        response = client.post("/lockdown", json={"confirm": "yes"})
        assert response.status_code == 422  # Pydantic Literal rejection


def test_lockdown_propagates_nft_failure(client):
    sock_p, uid_p = _auth_patches()
    with sock_p, uid_p, patch("eye_square_helper.routes.lockdown._apply_lockdown") as mock_apply:
        mock_apply.return_value = ("nft: syntax error", 1)
        response = client.post("/lockdown", json={"confirm": "lockdown"})
        assert response.status_code == 500
