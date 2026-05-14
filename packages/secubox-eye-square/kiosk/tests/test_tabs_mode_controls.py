# packages/secubox-eye-square/kiosk/tests/test_tabs_mode_controls.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for the Mode Controls tab — Pillow button grid."""
from __future__ import annotations

from unittest.mock import MagicMock

from PIL import Image

from secubox_eye_square_kiosk.tabs.mode_controls import ModeControlsTab


def test_constructs_with_helper_client():
    helper = MagicMock()
    tab = ModeControlsTab(helper)
    assert tab.helper is helper
    assert tab.transport_active == "SIM"


def test_update_transport_changes_indicator():
    tab = ModeControlsTab(MagicMock())
    tab.update_transport("OTG")
    assert tab.transport_active == "OTG"


def test_tap_normal_mode_calls_set_usb_mode():
    helper = MagicMock()
    tab = ModeControlsTab(helper)
    # Normal mode button is in the USB section (top of the panel)
    # Calculate position from grid: row 0, col 0 → roughly (10, 40)
    tab.handle_tap(40, 60)
    helper.set_usb_mode.assert_called_once_with("normal")


def test_tap_destructive_button_does_not_fire_without_confirm():
    """Flash is destructive — needs explicit confirm. First tap shows confirm overlay."""
    helper = MagicMock()
    tab = ModeControlsTab(helper)
    # Find flash button position (row 0, col 1)
    tab.handle_tap(110, 60)  # press
    # First press: pending_confirm should be set, helper not called yet
    assert tab.pending_confirm == "flash"
    helper.set_usb_mode.assert_not_called()
    # Confirm tap fires it
    tab.confirm_pending()
    helper.set_usb_mode.assert_called_once_with("flash")
