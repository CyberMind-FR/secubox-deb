# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/module_detail.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Module Detail tab — title + gauge + sparkline + service status."""
from __future__ import annotations

from PIL import Image, ImageDraw

from .. import theme

TITLE_Y = 16
METRIC_Y = 48
GAUGE_Y = 80
GAUGE_HEIGHT = 24
SPARK_Y = 140
SPARK_HEIGHT = 100
SERVICE_Y = 280


class ModuleDetailTab:
    """Detail view for a single module. Loaded via load_module()."""

    def __init__(self):
        self.module_name = ""
        self.metric = ""
        self.value = 0.0
        self.history: list[float] = []
        self.service_status = "—"

    def load_module(self, name: str, metric: str, value: float,
                    history: list[float]) -> None:
        self.module_name = name
        self.metric = metric
        self.value = value
        self.history = list(history)

    def set_service_status(self, status: str) -> None:
        self.service_status = status

    def draw(self, region: Image.Image) -> None:
        draw = ImageDraw.Draw(region)
        w, h = region.size
        if not self.module_name:
            draw.text((w // 2 - 50, h // 2), "(no module)",
                      fill=theme.TEXT_MUTED, font=theme.DEFAULT_FONT)
            return

        # Title bar
        draw.text((w // 2 - 30, TITLE_Y), self.module_name,
                  fill=theme.GOLD_HERMETIC, font=theme.DEFAULT_FONT)
        draw.text((10, METRIC_Y), self.metric, fill=theme.TEXT_PRIMARY,
                  font=theme.DEFAULT_FONT)

        # Gauge (clamped 0..100)
        clamped = max(0.0, min(100.0, self.value))
        fill_w = int((w - 20) * clamped / 100.0)
        draw.rectangle((10, GAUGE_Y, w - 10, GAUGE_Y + GAUGE_HEIGHT),
                       outline=theme.TEXT_MUTED, width=1)
        draw.rectangle((10, GAUGE_Y, 10 + fill_w, GAUGE_Y + GAUGE_HEIGHT),
                       fill=theme.CYBER_CYAN)
        draw.text((10, GAUGE_Y + GAUGE_HEIGHT + 4), f"{self.value:.1f}",
                  fill=theme.TEXT_PRIMARY, font=theme.DEFAULT_FONT)

        # Sparkline
        if len(self.history) >= 2:
            spark_w = w - 20
            max_v = max(self.history) or 1.0
            step = spark_w / (len(self.history) - 1)
            points = []
            for i, v in enumerate(self.history):
                x = 10 + int(i * step)
                y = SPARK_Y + SPARK_HEIGHT - int((v / max_v) * SPARK_HEIGHT)
                points.append((x, y))
            for a, b in zip(points, points[1:]):
                draw.line([a, b], fill=theme.CYBER_CYAN, width=2)

        # Service status
        draw.text((10, SERVICE_Y), f"Service: {self.service_status}",
                  fill=theme.TEXT_PRIMARY, font=theme.DEFAULT_FONT)
