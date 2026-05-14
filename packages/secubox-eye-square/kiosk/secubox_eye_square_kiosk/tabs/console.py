# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/console.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Console tab — text scrollback with a Freeze toggle."""
from __future__ import annotations

from PIL import Image, ImageDraw

from .. import theme

LINE_HEIGHT = 14
TOP_MARGIN = 8
BUTTON_Y = 380
BUTTON_HEIGHT = 32
BUTTON_X = 240


class ConsoleTab:
    """Read-only console tail. append_line() is no-op when frozen."""

    def __init__(self, max_lines: int = 200):
        self.lines: list[str] = []
        self.frozen = False
        self.max_lines = max_lines

    def append_line(self, line: str) -> None:
        if self.frozen:
            return
        self.lines.append(line)
        if len(self.lines) > self.max_lines:
            self.lines = self.lines[-self.max_lines:]

    def handle_tap(self, x: int, y: int) -> None:
        """Tap on the Freeze button (bottom-right)?"""
        if BUTTON_X <= x <= 320 and BUTTON_Y <= y <= BUTTON_Y + BUTTON_HEIGHT:
            self.frozen = not self.frozen

    def draw(self, region: Image.Image) -> None:
        draw = ImageDraw.Draw(region)
        w, h = region.size
        # Background — solid black for readability
        draw.rectangle((0, 0, w, h), fill=(0, 0, 0, 255))
        # Render the last N lines that fit
        visible_rows = (h - 50) // LINE_HEIGHT
        for i, line in enumerate(self.lines[-visible_rows:]):
            y = TOP_MARGIN + i * LINE_HEIGHT
            draw.text((4, y), line[:48], fill=theme.MATRIX_GREEN,
                      font=theme.DEFAULT_FONT)
        # Freeze button
        btn_label = "Resume" if self.frozen else "Freeze"
        btn_fill = theme.GOLD_HERMETIC if self.frozen else theme.TEXT_MUTED
        draw.rectangle((BUTTON_X, BUTTON_Y, w - 4, BUTTON_Y + BUTTON_HEIGHT),
                       outline=btn_fill, width=1)
        draw.text((BUTTON_X + 8, BUTTON_Y + 8), btn_label, fill=btn_fill,
                  font=theme.DEFAULT_FONT)
