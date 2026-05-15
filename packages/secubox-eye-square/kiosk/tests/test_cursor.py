# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for cursor.draw_cursor — overlay sprite."""
import sys
from pathlib import Path

# secubox_common ships at /var/www/common/python/ on the image; tests
# pick up the dev checkout via this path injection.
_DEV = Path(__file__).resolve().parents[4] / "remote-ui" / "common" / "python"
if str(_DEV) not in sys.path:
    sys.path.insert(0, str(_DEV))

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
    """Sprite at (95, 95) on a 100×100 canvas — Pillow clips the partial
    polygon; verify at least one pixel in the clipped 5×5 corner changed."""
    img = Image.new("RGBA", (100, 100), (0, 0, 0, 255))
    draw_cursor(img, 95, 95)
    nonblack = sum(1 for y in range(95, 100) for x in range(95, 100)
                   if img.getpixel((x, y))[:3] != (0, 0, 0))
    assert nonblack > 0, "expected partial sprite to draw at least 1 px"


def test_cursor_negative_coords_dont_crash():
    """Fully off-canvas: early return, canvas untouched."""
    img = Image.new("RGBA", (100, 100), (0, 0, 0, 255))
    draw_cursor(img, -10, -10)
    # Canvas must be untouched — sample a few pixels to prove it.
    assert img.getpixel((0, 0)) == (0, 0, 0, 255)
    assert img.getpixel((50, 50)) == (0, 0, 0, 255)
