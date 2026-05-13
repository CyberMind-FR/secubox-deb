# packages/secubox-eye-square/kiosk/tests/test_right_panel.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for RightPanel — tab bar + content router for the 320x480 right column."""
from __future__ import annotations

from unittest.mock import MagicMock

from PIL import Image

from secubox_eye_square_kiosk.right_panel import RightPanel


def test_constructs_with_4_tabs():
    panel = RightPanel(MagicMock())
    assert set(panel.tabs.keys()) == {"alerts", "module_detail", "console", "mode_controls"}
    assert panel.active_tab == "alerts"


def test_set_active_tab_changes_current():
    panel = RightPanel(MagicMock())
    panel.set_active_tab("console")
    assert panel.active_tab == "console"


def test_on_module_tap_switches_to_detail_tab():
    panel = RightPanel(MagicMock())
    panel.on_module_tap("AUTH")
    assert panel.active_tab == "module_detail"
    assert panel.tabs["module_detail"].module_name == "AUTH"


def test_tap_on_tab_bar_switches_tabs():
    panel = RightPanel(MagicMock())
    # Tab bar is at top 56px; 4 tabs each 80px wide
    panel.handle_tap(120, 30)  # within tab 1 (module_detail)
    assert panel.active_tab == "module_detail"
    panel.handle_tap(200, 30)  # within tab 2 (console)
    assert panel.active_tab == "console"


def test_tap_below_tab_bar_routes_to_active_tab():
    panel = RightPanel(MagicMock())
    panel.set_active_tab("console")
    # Tap on Freeze button (relative coord 280, 400+56=456 since tab bar adds 56)
    panel.handle_tap(280, 456)
    assert panel.tabs["console"].frozen is True


def test_draw_renders_320x480():
    panel = RightPanel(MagicMock())
    region = Image.new("RGBA", (320, 480), (0, 0, 0, 255))
    panel.draw(region)
    assert region.size == (320, 480)
