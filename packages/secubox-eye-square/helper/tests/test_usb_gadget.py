# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for helper /usb-gadget routes."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from eye_square_helper.app import create_app


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def _auth_patches():
    """Return the pair of patches that let a test request pass the middleware.

    _extract_peer_socket normally returns None for TestClient (TCP), which
    causes an immediate 401. We patch it to return a dummy socket object so
    the middleware proceeds to call get_peer_uid. Then we patch get_peer_uid
    to return 0 (root), which is always in ALLOWED_UIDS.
    """
    mock_sock = MagicMock()
    patch_socket = patch("eye_square_helper.app._extract_peer_socket", return_value=mock_sock)
    patch_uid = patch("eye_square_helper.app.get_peer_uid", return_value=0)
    return patch_socket, patch_uid


def test_usb_gadget_state_returns_current_mode(client):
    """GET /usb-gadget/state returns the current gadget mode."""
    patch_socket, patch_uid = _auth_patches()
    with patch_socket, patch_uid, \
         patch("eye_square_helper.routes.usb_gadget._run_gadget_script") as mock_run:
        mock_run.return_value = ("Mode: normal\nUDC: 20980000.usb", 0)
        response = client.get("/usb-gadget/state")
        assert response.status_code == 200
        body = response.json()
        assert body["mode"] == "normal"
        assert body["exit_code"] == 0


def test_usb_gadget_mode_accepts_valid_modes(client):
    valid_modes = ["normal", "flash", "debug", "tty", "auth"]
    for mode in valid_modes:
        patch_socket, patch_uid = _auth_patches()
        with patch_socket, patch_uid, \
             patch("eye_square_helper.routes.usb_gadget._run_gadget_script") as mock_run:
            mock_run.return_value = ("", 0)
            response = client.post("/usb-gadget/mode", json={"mode": mode})
            assert response.status_code == 200, f"mode {mode} rejected: {response.text}"


def test_usb_gadget_mode_rejects_unknown(client):
    patch_socket, patch_uid = _auth_patches()
    with patch_socket, patch_uid:
        response = client.post("/usb-gadget/mode", json={"mode": "blorp"})
        # Pydantic Literal validation → 422 Unprocessable Entity
        assert response.status_code == 422


def test_usb_gadget_mode_propagates_script_failure(client):
    """If the gadget script returns nonzero, the endpoint should 500."""
    patch_socket, patch_uid = _auth_patches()
    with patch_socket, patch_uid, \
         patch("eye_square_helper.routes.usb_gadget._run_gadget_script") as mock_run:
        mock_run.return_value = ("ERROR: configfs not mounted", 1)
        response = client.post("/usb-gadget/mode", json={"mode": "normal"})
        assert response.status_code == 500
