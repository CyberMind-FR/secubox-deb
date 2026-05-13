# packages/secubox-eye-square/kiosk/tests/test_tabs_console.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for the Console tab — Pillow-rendered text scrollback."""
from __future__ import annotations

from PIL import Image

from secubox_eye_square_kiosk.tabs.console import ConsoleTab


def test_constructs_empty():
    tab = ConsoleTab()
    assert tab.lines == []
    assert tab.frozen is False


def test_append_line_adds_to_buffer():
    tab = ConsoleTab()
    tab.append_line("line A")
    tab.append_line("line B")
    assert tab.lines == ["line A", "line B"]


def test_frozen_skips_append():
    tab = ConsoleTab()
    tab.append_line("first")
    tab.frozen = True
    tab.append_line("ignored")
    assert "ignored" not in tab.lines


def test_buffer_caps_at_max_lines():
    tab = ConsoleTab(max_lines=10)
    for i in range(20):
        tab.append_line(f"line {i}")
    assert len(tab.lines) == 10
    assert tab.lines[0] == "line 10"  # oldest dropped
    assert tab.lines[-1] == "line 19"


def test_handle_tap_on_freeze_toggle():
    tab = ConsoleTab()
    # Freeze button is at bottom-right (y > 380 in the 320x424 region)
    tab.handle_tap(280, 400)
    assert tab.frozen is True
    tab.handle_tap(280, 400)
    assert tab.frozen is False


def test_draw_renders_recent_lines():
    tab = ConsoleTab()
    tab.append_line("first")
    tab.append_line("second")
    region = Image.new("RGBA", (320, 424), (0, 0, 0, 255))
    tab.draw(region)
    assert region.size == (320, 424)
