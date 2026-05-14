# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/alerts.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Alerts tab — Pillow-drawn scrollable list of recent system alerts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from PIL import Image, ImageDraw

from .. import theme

ROW_HEIGHT = 32
DOT_RADIUS = 4
TEXT_PAD_LEFT = 24
TEXT_PAD_RIGHT = 8


@dataclass
class AlertItem:
    severity: str  # "info" | "warn" | "crit"
    time: str
    module: str
    message: str


class AlertsTab:
    """Scrollable list. Tap a row to drill into module detail."""

    def __init__(self):
        self.items: list[AlertItem] = []
        self.scroll_offset = 0
        self.on_row_tap: Callable[[AlertItem], None] = lambda _: None

    def set_alerts(self, items: list[AlertItem]) -> None:
        self.items = list(items)
        self.scroll_offset = 0

    def handle_tap(self, x: int, y: int) -> None:
        """Convert a tap at (x, y) (region-local coords) to a row hit."""
        row_index = (y + self.scroll_offset) // ROW_HEIGHT
        if 0 <= row_index < len(self.items):
            self.on_row_tap(self.items[row_index])

    def handle_drag(self, dx: int, dy: int) -> None:
        """Drag down scrolls list up (negative dy = scroll up)."""
        self.scroll_offset = max(
            0,
            min(
                max(0, len(self.items) * ROW_HEIGHT - 424),
                self.scroll_offset - dy,
            ),
        )

    def draw(self, region: Image.Image) -> None:
        """Render alerts into the region (320x424 RGBA image)."""
        draw = ImageDraw.Draw(region)
        if not self.items:
            draw.text((10, 10), "● NOMINAL", fill=theme.MATRIX_GREEN,
                      font=theme.DEFAULT_FONT)
            return
        w, h = region.size
        for i, item in enumerate(self.items):
            y = i * ROW_HEIGHT - self.scroll_offset
            if y + ROW_HEIGHT < 0 or y > h:
                continue
            dot = theme.SEVERITY.get(item.severity, theme.TEXT_MUTED)
            draw.ellipse(
                (8, y + 12, 8 + 2 * DOT_RADIUS, y + 12 + 2 * DOT_RADIUS),
                fill=dot,
            )
            txt = f"{item.time} {item.module}  {item.message}"
            draw.text((TEXT_PAD_LEFT, y + 8), txt[:38],
                      fill=theme.TEXT_PRIMARY, font=theme.DEFAULT_FONT)
            # divider line
            draw.line((0, y + ROW_HEIGHT - 1, w, y + ROW_HEIGHT - 1),
                      fill=theme.TEXT_MUTED)
