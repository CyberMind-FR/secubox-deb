# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for cursor.draw_cursor — overlay sprite."""
from PIL import Image

from secubox_eye_square_kiosk.cursor import draw_cursor


def test_cursor_pixels_at_origin():
    img = Image.new("RGBA", (100, 100), (0, 0, 0, 255))
    draw_cursor(img, 50, 50)
    # At least one non-black pixel near (50, 50).
    nonblack = sum(1 for dy in range(0, 16) for dx in range(0, 12)
                   if img.getpixel((50 + dx, 50 + dy))[:3] != (0, 0, 0))
    assert nonblack > 0


def test_cursor_clamped_to_image_bounds():
    img = Image.new("RGBA", (100, 100), (0, 0, 0, 255))
    draw_cursor(img, 95, 95)
    # Must not raise. Sprite is partially drawn within bounds.


def test_cursor_negative_coords_dont_crash():
    img = Image.new("RGBA", (100, 100), (0, 0, 0, 255))
    draw_cursor(img, -10, -10)  # off-canvas — should be a no-op
