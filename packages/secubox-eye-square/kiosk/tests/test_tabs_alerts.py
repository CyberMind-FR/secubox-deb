# packages/secubox-eye-square/kiosk/tests/test_tabs_alerts.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for the Alerts tab — Pillow-drawn scrollable list."""
from __future__ import annotations

from PIL import Image

from secubox_eye_square_kiosk.tabs.alerts import AlertItem, AlertsTab


def test_alerts_tab_constructs():
    tab = AlertsTab()
    assert tab.items == []
    assert tab.scroll_offset == 0


def test_set_alerts_replaces_items():
    tab = AlertsTab()
    tab.set_alerts([AlertItem("crit", "14:32:07", "AUTH", "cpu hit")])
    assert len(tab.items) == 1


def test_draw_renders_320x424_image():
    """Draw onto a region; verify image size."""
    tab = AlertsTab()
    tab.set_alerts([AlertItem("warn", "14:33:01", "MIND", "load 3.2")])
    region = Image.new("RGBA", (320, 424), (0, 0, 0, 255))
    tab.draw(region)
    assert region.size == (320, 424)


def test_handle_tap_within_row_fires_callback():
    """A tap inside a row should fire the on_row_tap callback."""
    tab = AlertsTab()
    item = AlertItem("crit", "14:32:07", "AUTH", "cpu hit")
    tab.set_alerts([item])
    received = []
    tab.on_row_tap = lambda i: received.append(i)
    # First row spans (0, 0..32) — tap at (100, 16) should hit row 0
    tab.handle_tap(100, 16)
    assert received == [item]


def test_handle_drag_scrolls_offset():
    tab = AlertsTab()
    tab.set_alerts([AlertItem("info", f"00:00:{i:02d}", "AUTH", "x") for i in range(20)])
    tab.handle_drag(dx=0, dy=-50)
    assert tab.scroll_offset == 50  # scroll down (drag up)
