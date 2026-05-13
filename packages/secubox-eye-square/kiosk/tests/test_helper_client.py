# packages/secubox-eye-square/kiosk/tests/test_helper_client.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for helper_client.py — sync httpx UDS to the helper FastAPI."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

from secubox_eye_square_kiosk.helper_client import HelperClient


def test_set_usb_mode_calls_correct_endpoint():
    c = HelperClient("/tmp/test.sock")
    with patch.object(c, "_post") as mock_post:
        mock_post.return_value = {"mode": "normal", "exit_code": 0}
        result = c.set_usb_mode("normal")
        mock_post.assert_called_once_with("/usb-gadget/mode", {"mode": "normal"})
        assert result["mode"] == "normal"


def test_get_usb_state_calls_correct_endpoint():
    c = HelperClient("/tmp/test.sock")
    with patch.object(c, "_get") as mock_get:
        mock_get.return_value = {"mode": "normal"}
        result = c.get_usb_state()
        mock_get.assert_called_once_with("/usb-gadget/state")


def test_restart_service_calls_correct_endpoint():
    c = HelperClient("/tmp/test.sock")
    with patch.object(c, "_post") as mock_post:
        mock_post.return_value = {"unit": "secubox-hub", "exit_code": 0}
        c.restart_service("secubox-hub")
        mock_post.assert_called_once_with("/service/restart", {"unit": "secubox-hub"})


def test_lockdown_sends_confirm_string():
    c = HelperClient("/tmp/test.sock")
    with patch.object(c, "_post") as mock_post:
        mock_post.return_value = {"applied": True, "exit_code": 0}
        c.lockdown()
        mock_post.assert_called_once_with("/lockdown", {"confirm": "lockdown"})
