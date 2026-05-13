# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for the Mode Controls tab."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


def test_mode_controls_constructs(app):
    from secubox_eye_square_right_panel.tabs.mode_controls import ModeControlsTab
    helper = MagicMock()
    tab = ModeControlsTab(helper)
    # 6 USB modes, 4 service buttons
    assert set(tab.usb_buttons.keys()) == {"normal", "flash", "debug", "tty", "auth", "stop"}
    assert set(tab.service_buttons.keys()) == {"secubox-hub", "secubox-auth", "restart-all", "lockdown"}


def test_mode_controls_update_transport(app):
    from secubox_eye_square_right_panel.tabs.mode_controls import ModeControlsTab
    helper = MagicMock()
    tab = ModeControlsTab(helper)
    tab.update_transport("OTG")
    assert "OTG" in tab.transport_label.text()
    assert "●" in tab.transport_label.text()
    tab.update_transport("SIM")
    assert "○" in tab.transport_label.text()


def test_needs_confirm_for_destructive(app):
    from secubox_eye_square_right_panel.tabs.mode_controls import ModeControlsTab
    helper = MagicMock()
    tab = ModeControlsTab(helper)
    assert tab._needs_confirm("flash") is True
    assert tab._needs_confirm("stop") is True
    assert tab._needs_confirm("normal") is False
    assert tab._needs_confirm("restart-all") is True
    assert tab._needs_confirm("lockdown") is True
    assert tab._needs_confirm("secubox-hub") is False
