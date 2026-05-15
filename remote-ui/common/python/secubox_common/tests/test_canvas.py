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
