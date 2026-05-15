# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for secubox_common.canvas — DashboardCanvas primitives."""
from PIL import Image

from secubox_common import theme
from secubox_common.canvas import DashboardCanvas


def test_paint_background_fills_with_colour(blank_round):
    canvas = DashboardCanvas()
    canvas.paint_background(blank_round, colour=(255, 0, 0))
    assert blank_round.getpixel((0, 0))[:3] == (255, 0, 0)
    assert blank_round.getpixel((239, 239))[:3] == (255, 0, 0)


def test_paint_background_default_is_cosmos_black(blank_round):
    canvas = DashboardCanvas()
    canvas.paint_background(blank_round)
    assert blank_round.getpixel((100, 100))[:3] == theme.COSMOS_BLACK


def test_dashboard_canvas_layout_is_abstract():
    canvas = DashboardCanvas()
    try:
        canvas.layout({})
    except NotImplementedError:
        return
    assert False, "DashboardCanvas.layout() must raise NotImplementedError"


def test_paint_rainbow_ring_pixels_in_band_are_colored(blank_round):
    """A pixel exactly on the rainbow band radius is non-black; pixels
    inside the band are erased to COSMOS_BLACK, pixels outside the band
    are untouched (still the fixture's initial (0, 0, 0))."""
    canvas = DashboardCanvas()
    canvas.paint_rainbow_ring(blank_round, center=(240, 240),
                              radius_outer=235, radius_inner=220)

    # Centre pixel = inside the inner radius, erased to COSMOS_BLACK by default.
    assert blank_round.getpixel((240, 240))[:3] == theme.COSMOS_BLACK

    # Pixel at radius 230 (between inner=220 and outer=235): coloured.
    px = blank_round.getpixel((240 + 230, 240))
    assert px[:3] != theme.COSMOS_BLACK and px[:3] != (0, 0, 0), \
        f"expected coloured pixel at band radius 230, got {px[:3]}"

    # Pixel at radius 238 (just outside outer=235, x=478 is in-bounds for the
    # 480-wide canvas): never touched by paint_rainbow_ring → stays at the
    # fixture's initial (0, 0, 0).
    assert blank_round.getpixel((240 + 238, 240))[:3] == (0, 0, 0)


def test_paint_rainbow_ring_spans_hue_around_circle(blank_round):
    """Sample 4 points on the band at 0°, 90°, 180°, 270° — they should
    differ in colour (rainbow hue rotates with angle)."""
    import math
    canvas = DashboardCanvas()
    canvas.paint_rainbow_ring(blank_round, center=(240, 240),
                              radius_outer=235, radius_inner=220)

    R = 227  # middle of the band
    samples = []
    for angle_deg in (0, 90, 180, 270):
        rad = math.radians(angle_deg)
        x = int(240 + R * math.cos(rad))
        y = int(240 + R * math.sin(rad))
        samples.append(blank_round.getpixel((x, y))[:3])

    # All 4 samples must be different colours.
    assert len(set(samples)) == 4, f"rainbow band hue is not rotating: {samples}"
