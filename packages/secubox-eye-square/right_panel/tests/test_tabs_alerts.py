# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for the Alerts tab — QListView + QAbstractListModel."""
from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


def test_alerts_tab_constructs(app):
    from secubox_eye_square_right_panel.tabs.alerts import AlertsTab
    tab = AlertsTab()
    assert tab.list_view is not None
    assert tab.model is not None
    assert tab.model.rowCount() == 0


def test_alerts_tab_renders_alerts(app):
    from secubox_eye_square_right_panel.tabs.alerts import AlertsTab, AlertItem
    tab = AlertsTab()
    items = [
        AlertItem(severity="crit", time="14:32:07", module="AUTH", message="cpu hit"),
        AlertItem(severity="warn", time="14:33:01", module="MIND", message="load 3.2"),
    ]
    tab.set_alerts(items)
    assert tab.model.rowCount() == 2


def test_alerts_tab_replaces_items_on_subsequent_set(app):
    from secubox_eye_square_right_panel.tabs.alerts import AlertsTab, AlertItem
    tab = AlertsTab()
    tab.set_alerts([AlertItem(severity="warn", time="00:00:00", module="WALL", message="x")])
    assert tab.model.rowCount() == 1
    # Replacing with a different list should reset
    tab.set_alerts([])
    assert tab.model.rowCount() == 0


def test_alerts_tab_on_row_tapped_callback(app):
    from secubox_eye_square_right_panel.tabs.alerts import AlertsTab, AlertItem
    captured: list[AlertItem] = []
    tab = AlertsTab(on_row_tapped=lambda item: captured.append(item))
    item = AlertItem(severity="crit", time="00:00:00", module="ROOT", message="overheat")
    tab.set_alerts([item])
    # Simulate clicking row 0
    tab._on_row_clicked(tab.model.index(0))
    assert captured == [item]
