# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Module Detail tab — title + gauge + sparkline + service status."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPen
from PySide6.QtWidgets import (
    QGraphicsScene, QGraphicsView, QLabel, QProgressBar, QVBoxLayout, QWidget,
)


class ModuleDetailTab(QWidget):
    """Tab 2: detail view for a single module. Loaded via load_module()."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.title_label = QLabel("(no module selected)")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("font-weight: bold; font-size: 14px; padding: 6px;")

        self.metric_label = QLabel("")
        self.metric_label.setAlignment(Qt.AlignCenter)

        self.gauge = QProgressBar()
        self.gauge.setRange(0, 100)
        self.gauge.setValue(0)
        self.gauge_value: float = 0.0

        self.spark_scene = QGraphicsScene(0, 0, 300, 80)
        self.spark_view = QGraphicsView(self.spark_scene)
        self.spark_view.setStyleSheet("background: #080808;")
        self.spark_view.setFixedHeight(90)

        self.service_label = QLabel("Service: —")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(self.title_label)
        layout.addWidget(self.metric_label)
        layout.addWidget(self.gauge)
        layout.addWidget(self.spark_view)
        layout.addWidget(self.service_label)
        layout.addStretch()

    def load_module(self, name: str, metric: str, value: float, history: list[float]):
        """Populate the tab with a module's current state."""
        self.title_label.setText(name)
        self.metric_label.setText(metric)
        clamped = int(min(100, max(0, value)))
        self.gauge.setValue(clamped)
        self.gauge_value = value
        self._draw_sparkline(history)

    def set_service_status(self, status_line: str):
        """Update the service-status label (e.g. 'secubox-auth · active · up 3h17')."""
        self.service_label.setText(status_line)

    def _draw_sparkline(self, history: list[float]):
        self.spark_scene.clear()
        if len(history) < 2:
            return
        w, h = 300, 80
        max_v = max(history) or 1.0
        step = w / (len(history) - 1)
        pen = QPen(QColor("#00d4ff"))
        pen.setWidth(2)
        prev_x = 0
        prev_y = h - (history[0] / max_v) * h
        for i, v in enumerate(history[1:], start=1):
            x = i * step
            y = h - (v / max_v) * h
            self.spark_scene.addLine(prev_x, prev_y, x, y, pen)
            prev_x, prev_y = x, y
