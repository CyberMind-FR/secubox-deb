# packages/secubox-eye-square/kiosk/tests/test_tabs_module_detail.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for the Module Detail tab — title + gauge + sparkline."""
from __future__ import annotations

from PIL import Image

from secubox_eye_square_kiosk.tabs.module_detail import ModuleDetailTab


def test_constructs_with_default_state():
    tab = ModuleDetailTab()
    assert tab.module_name == ""
    assert tab.value == 0.0
    assert tab.history == []


def test_load_module_updates_state():
    tab = ModuleDetailTab()
    tab.load_module("AUTH", "cpu_percent", value=47.2, history=[10, 20, 30, 40, 47.2])
    assert tab.module_name == "AUTH"
    assert tab.metric == "cpu_percent"
    assert tab.value == 47.2
    assert tab.history == [10, 20, 30, 40, 47.2]


def test_clamps_value_for_gauge():
    tab = ModuleDetailTab()
    tab.load_module("WALL", "mem_percent", value=150.0, history=[])
    region = Image.new("RGBA", (320, 424), (0, 0, 0, 255))
    tab.draw(region)
    # Gauge fill is clamped to 100% — no crash, image rendered
    assert region.size == (320, 424)


def test_draw_handles_empty_history():
    tab = ModuleDetailTab()
    tab.load_module("ROOT", "cpu_temp", value=44.2, history=[])
    region = Image.new("RGBA", (320, 424), (0, 0, 0, 255))
    tab.draw(region)
    # No crash on empty history
