# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""E2E: RightPanelWindow construction, tab routing on module:tap, transport update."""
from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


def test_right_panel_constructs(app):
    from secubox_eye_square_right_panel.app import RightPanelWindow
    win = RightPanelWindow()
    assert win.tabs.count() == 4


def test_module_tap_event_routes_to_detail_tab(app):
    from secubox_eye_square_right_panel.app import RightPanelWindow
    win = RightPanelWindow()
    # Simulate a Chromium-side TM.onModuleTap dispatch
    win._on_module_tap_event("AUTH")
    assert win.tabs.currentWidget() is win.module_tab


def test_transport_change_updates_mode_tab(app):
    from secubox_eye_square_right_panel.app import RightPanelWindow
    win = RightPanelWindow()
    win._on_transport_change_event("WiFi")
    assert "WiFi" in win.mode_tab.transport_label.text()


def test_alert_tap_routes_to_detail_tab(app):
    from secubox_eye_square_right_panel.app import RightPanelWindow
    from secubox_eye_square_right_panel.tabs.alerts import AlertItem
    win = RightPanelWindow()
    item = AlertItem(severity="crit", time="14:32:07", module="ROOT", message="overheat")
    win._on_alert_tapped(item)
    assert win.tabs.currentWidget() is win.module_tab
