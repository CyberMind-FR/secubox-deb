# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Cursor sprite — drawn as the last overlay each frame when the pointer
has moved within the AUTO_HIDE_S window."""
from __future__ import annotations

from PIL import Image, ImageDraw

# 12×16 arrow: gold outline (GOLD_HERMETIC) + black fill. Hand-drawn
# polygon, top-left origin.
_OUTLINE = (0xC9, 0xA8, 0x4C, 255)
_FILL = (0x00, 0x00, 0x00, 255)

_POLY = [
    (0, 0), (10, 6), (5, 6), (8, 14), (5, 15), (3, 8), (0, 11),
]


def draw_cursor(img: Image.Image, x: int, y: int) -> None:
    """Draw the cursor sprite with hot-spot at (x, y).

    Sprite extends 0..11 px right and 0..15 px down from the hot-spot.
    Partial off-canvas placement is fine — Pillow's polygon clips itself.
    Coordinates with x < 0 or y < 0 fully off-canvas: no-op."""
    if x + 12 < 0 or y + 16 < 0 or x >= img.size[0] or y >= img.size[1]:
        return
    draw = ImageDraw.Draw(img)
    shifted = [(x + px, y + py) for (px, py) in _POLY]
    draw.polygon(shifted, fill=_FILL, outline=_OUTLINE)
