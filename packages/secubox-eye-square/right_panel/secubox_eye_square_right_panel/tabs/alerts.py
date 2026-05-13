# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Alerts tab — QListView of recent system alerts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from PySide6.QtCore import QAbstractListModel, QModelIndex, Qt
from PySide6.QtWidgets import QListView, QVBoxLayout, QWidget


@dataclass
class AlertItem:
    severity: str  # 'info' | 'warn' | 'crit'
    time: str
    module: str
    message: str


class _AlertModel(QAbstractListModel):
    def __init__(self):
        super().__init__()
        self._items: list[AlertItem] = []

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._items)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._items)):
            return None
        item = self._items[index.row()]
        if role == Qt.DisplayRole:
            return f"[{item.severity[:4]}] {item.time}  {item.module}  {item.message}"
        return None

    def replace(self, items: list[AlertItem]):
        self.beginResetModel()
        self._items = list(items)
        self.endResetModel()

    def at(self, row: int) -> AlertItem | None:
        if 0 <= row < len(self._items):
            return self._items[row]
        return None


class AlertsTab(QWidget):
    """Tab 1: scrolling list of recent alerts."""

    def __init__(self, on_row_tapped: Callable[[AlertItem], None] | None = None, parent=None):
        super().__init__(parent)
        self.model = _AlertModel()
        self.list_view = QListView(self)
        self.list_view.setModel(self.model)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.list_view)
        self._on_row_tapped = on_row_tapped or (lambda item: None)
        self.list_view.clicked.connect(self._on_row_clicked)

    def set_alerts(self, items: list[AlertItem]):
        self.model.replace(items)

    def _on_row_clicked(self, index: QModelIndex):
        item = self.model.at(index.row())
        if item is not None:
            self._on_row_tapped(item)
