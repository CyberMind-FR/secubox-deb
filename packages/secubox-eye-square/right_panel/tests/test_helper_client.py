# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for HelperClient — calls the eye-square-helper over its Unix socket."""
from __future__ import annotations

from unittest.mock import patch, AsyncMock

import pytest

from secubox_eye_square_right_panel.helper_client import HelperClient


@pytest.mark.asyncio
async def test_set_usb_mode_calls_correct_endpoint():
    client = HelperClient("/tmp/test.sock")
    with patch.object(client, "_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = {"mode": "normal", "exit_code": 0}
        result = await client.set_usb_mode("normal")
        assert result["mode"] == "normal"
        mock_post.assert_called_once_with("/usb-gadget/mode", {"mode": "normal"})


@pytest.mark.asyncio
async def test_get_usb_state_calls_correct_endpoint():
    client = HelperClient("/tmp/test.sock")
    with patch.object(client, "_get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = {"mode": "normal", "exit_code": 0}
        result = await client.get_usb_state()
        mock_get.assert_called_once_with("/usb-gadget/state")
        assert result["mode"] == "normal"


@pytest.mark.asyncio
async def test_restart_service_calls_correct_endpoint():
    client = HelperClient("/tmp/test.sock")
    with patch.object(client, "_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = {"unit": "secubox-hub", "exit_code": 0}
        result = await client.restart_service("secubox-hub")
        mock_post.assert_called_once_with("/service/restart", {"unit": "secubox-hub"})


@pytest.mark.asyncio
async def test_lockdown_sends_confirm_string():
    client = HelperClient("/tmp/test.sock")
    with patch.object(client, "_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = {"applied": True, "exit_code": 0}
        result = await client.lockdown()
        mock_post.assert_called_once_with("/lockdown", {"confirm": "lockdown"})
