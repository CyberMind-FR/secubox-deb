# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for the Module Detail tab."""
from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


def test_module_detail_tab_constructs(app):
    from secubox_eye_square_right_panel.tabs.module_detail import ModuleDetailTab
    tab = ModuleDetailTab()
    assert tab.title_label is not None
    assert tab.metric_label is not None
    assert tab.gauge is not None
    assert tab.spark_view is not None
    assert tab.service_label is not None


def test_module_detail_load_module(app):
    from secubox_eye_square_right_panel.tabs.module_detail import ModuleDetailTab
    tab = ModuleDetailTab()
    tab.load_module("AUTH", "cpu_percent", value=47.2, history=[10, 20, 30, 40, 47.2])
    assert "AUTH" in tab.title_label.text()
    assert tab.metric_label.text() == "cpu_percent"
    assert tab.gauge_value == 47.2
    # gauge.value() is clamped to int 0-100
    assert tab.gauge.value() == 47


def test_module_detail_clamps_gauge_range(app):
    from secubox_eye_square_right_panel.tabs.module_detail import ModuleDetailTab
    tab = ModuleDetailTab()
    tab.load_module("WALL", "mem_percent", value=150, history=[])
    assert tab.gauge.value() == 100  # clamped to range
    tab.load_module("WALL", "mem_percent", value=-5, history=[])
    assert tab.gauge.value() == 0


def test_module_detail_handles_empty_history(app):
    """Empty history list should not crash the sparkline."""
    from secubox_eye_square_right_panel.tabs.module_detail import ModuleDetailTab
    tab = ModuleDetailTab()
    tab.load_module("MIND", "load_avg_1", value=0.5, history=[])
    # Should not raise


def test_module_detail_handles_single_history_point(app):
    """Single-point history should be drawn safely (no line possible)."""
    from secubox_eye_square_right_panel.tabs.module_detail import ModuleDetailTab
    tab = ModuleDetailTab()
    tab.load_module("ROOT", "cpu_temp", value=44.2, history=[44.2])
