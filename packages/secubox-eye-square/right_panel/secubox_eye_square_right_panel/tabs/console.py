# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Console tab — read-only tail with a Freeze button."""
from __future__ import annotations

from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QHBoxLayout, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)


class ConsoleTab(QWidget):
    """Tab 3: read-only console tail. Streamed lines arrive via append_line()."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.text_edit = QPlainTextEdit()
        self.text_edit.setReadOnly(True)
        font = QFont("Monospace")
        font.setStyleHint(QFont.TypeWriter)
        self.text_edit.setFont(font)
        self.text_edit.setStyleSheet("background: #000; color: #00ff41;")

        self.freeze_button = QPushButton("Freeze")
        self.freeze_button.setCheckable(True)
        self.freeze_button.clicked.connect(self._on_freeze_clicked)
        self.frozen = False

        controls = QHBoxLayout()
        controls.addStretch()
        controls.addWidget(self.freeze_button)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.text_edit)
        layout.addLayout(controls)

    def append_line(self, line: str):
        """Append a line. No-op when frozen."""
        if self.frozen:
            return
        self.text_edit.appendPlainText(line)
        sb = self.text_edit.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_freeze_clicked(self):
        # QPushButton.checked state follows toggle; sync `self.frozen` to it
        self.frozen = self.freeze_button.isChecked()
        self.freeze_button.setText("Resume" if self.frozen else "Freeze")
