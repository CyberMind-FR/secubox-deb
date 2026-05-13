# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for the Console tab."""
from __future__ import annotations

import pytest
from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


def test_console_tab_constructs(app):
    from secubox_eye_square_right_panel.tabs.console import ConsoleTab
    tab = ConsoleTab()
    assert tab.text_edit is not None
    assert tab.freeze_button is not None
    assert tab.frozen is False


def test_console_append_line(app):
    from secubox_eye_square_right_panel.tabs.console import ConsoleTab
    tab = ConsoleTab()
    tab.append_line("line A")
    tab.append_line("line B")
    text = tab.text_edit.toPlainText()
    assert "line A" in text
    assert "line B" in text


def test_console_frozen_does_not_append(app):
    from secubox_eye_square_right_panel.tabs.console import ConsoleTab
    tab = ConsoleTab()
    tab.append_line("first")
    tab.frozen = True
    tab.append_line("ignored")
    assert "ignored" not in tab.text_edit.toPlainText()
    assert "first" in tab.text_edit.toPlainText()


def test_console_freeze_button_toggles(app):
    from secubox_eye_square_right_panel.tabs.console import ConsoleTab
    tab = ConsoleTab()
    assert tab.frozen is False
    tab.freeze_button.click()
    assert tab.frozen is True
    assert tab.freeze_button.text() == "Resume"
    tab.freeze_button.click()
    assert tab.frozen is False
    assert tab.freeze_button.text() == "Freeze"
