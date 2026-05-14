# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for helper /console/stream WebSocket route."""
from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from eye_square_helper.app import create_app
from eye_square_helper.routes.console import _select_source


def test_select_source_satellite_returns_tty():
    """When TM state is OTG and /dev/ttyACM0 exists, return that path."""
    with patch("eye_square_helper.routes.console._read_transport", return_value="OTG"), \
         patch("os.path.exists", return_value=True):
        assert _select_source() == "/dev/ttyACM0"


def test_select_source_kiosk_returns_journalctl():
    """When TM state is not OTG, return journalctl."""
    with patch("eye_square_helper.routes.console._read_transport", return_value="WiFi"):
        assert _select_source() == "journalctl"


def test_select_source_sim_returns_journalctl():
    with patch("eye_square_helper.routes.console._read_transport", return_value="SIM"):
        assert _select_source() == "journalctl"


def test_select_source_otg_but_no_tty_returns_journalctl():
    """If OTG but the tty device is missing, fall back to journalctl."""
    with patch("eye_square_helper.routes.console._read_transport", return_value="OTG"), \
         patch("os.path.exists", return_value=False):
        assert _select_source() == "journalctl"


def test_console_ws_streams_lines():
    """WS connects, mocked tail yields 2 lines, client receives them."""
    async def fake_tail(source):
        yield "line A"
        yield "line B"

    app = create_app()
    client = TestClient(app)
    with patch("eye_square_helper.routes.console._spawn_tail", fake_tail), \
         patch("eye_square_helper.routes.console._select_source", return_value="journalctl"):
        with client.websocket_connect("/console/stream") as ws:
            received = []
            for _ in range(2):
                received.append(ws.receive_text())
            assert received == ["line A", "line B"]
