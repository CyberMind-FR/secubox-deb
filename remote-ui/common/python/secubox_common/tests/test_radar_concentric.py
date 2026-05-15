# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for secubox_common.painters.radar_concentric."""
from __future__ import annotations

import pytest
from PIL import Image

from secubox_common.modules import MODULES
from secubox_common.painters import radar_concentric


METRICS = {
    "cpu_percent": 60.0,
    "mem_percent": 45.0,
    "disk_percent": 30.0,
    "load_avg_1": 0.8,
    "cpu_temp": 55.0,
    "wifi_rssi": -55,
}


def _frame() -> Image.Image:
    return Image.new("RGBA", (480, 480), (0, 0, 0, 255))


def test_paint_modifies_canvas():
    """Painting at any phase must change the canvas from solid black."""
    img = _frame()
    radar_concentric.paint(img, (240, 240), MODULES, METRICS, phase=0.0)
    # At least one pixel outside the inner hub must have changed.
    sample = img.getpixel((240, 30))  # near outer ring
    assert sample != (0, 0, 0, 255), \
        "outer ring area should have radar pixels painted"


def test_paint_differs_across_phases():
    """phase=0.0 and phase=0.5 must produce different sweep positions."""
    a = _frame()
    b = _frame()
    radar_concentric.paint(a, (240, 240), MODULES, METRICS, phase=0.0)
    radar_concentric.paint(b, (240, 240), MODULES, METRICS, phase=0.5)
    assert a.tobytes() != b.tobytes(), \
        "frames at phase 0.0 vs 0.5 should differ (sweep rotated 180°)"


def test_paint_wraps_at_phase_one():
    """phase=0.0 and phase=1.0 produce the same frame (period = 1)."""
    a = _frame()
    b = _frame()
    radar_concentric.paint(a, (240, 240), MODULES, METRICS, phase=0.0)
    radar_concentric.paint(b, (240, 240), MODULES, METRICS, phase=1.0)
    assert a.tobytes() == b.tobytes(), \
        "phase=1.0 must wrap back to phase=0.0"


def test_paint_uses_default_radii_when_none():
    """radii=None must fall back to DEFAULT_RADII (6 entries)."""
    img = _frame()
    # 6 modules + 6 default radii must match.
    radar_concentric.paint(img, (240, 240), MODULES, METRICS, radii=None)
    sample = img.getpixel((240, 30))
    assert sample != (0, 0, 0, 255)


def test_paint_rejects_mismatched_radii():
    """A radii list of wrong length must raise."""
    img = _frame()
    with pytest.raises(ValueError, match="length mismatch"):
        radar_concentric.paint(
            img, (240, 240), MODULES, METRICS, radii=[200, 180, 160]
        )


def test_paint_hub_toggle():
    """draw_hub=False must leave the centre area unfilled by the painter
    (so callers can composite their own central button + icons)."""
    a = _frame()
    b = _frame()
    radar_concentric.paint(a, (240, 240), MODULES, METRICS,
                           phase=0.0, draw_hub=True)
    radar_concentric.paint(b, (240, 240), MODULES, METRICS,
                           phase=0.0, draw_hub=False)
    # Sample a point well inside the hub (radius ~85). With draw_hub=True
    # the colour is the hub fill (12, 12, 22, 255). With False it remains
    # the canvas background.
    assert a.getpixel((240, 240)) == (12, 12, 22, 255)
    assert b.getpixel((240, 240)) == (0, 0, 0, 255)


def test_sweep_accent_in_rgb_range():
    """sweep_accent returns valid RGB tuples for any phase."""
    for p in [0.0, 0.25, 0.5, 0.75, 0.999]:
        r, g, b = radar_concentric.sweep_accent(p)
        for chan in (r, g, b):
            assert 0 <= chan <= 255


def test_canvas_method_delegates():
    """DashboardCanvas.paint_radar_concentric must produce the same frame
    as calling the painter directly — proves the canvas helper is a
    thin wrapper, not divergent code."""
    from secubox_common.canvas import DashboardCanvas

    direct = _frame()
    via_canvas = _frame()
    radar_concentric.paint(direct, (240, 240), MODULES, METRICS, phase=0.25)
    DashboardCanvas().paint_radar_concentric(
        via_canvas, (240, 240), MODULES, METRICS, phase=0.25,
    )
    assert direct.tobytes() == via_canvas.tobytes(), \
        "canvas helper should delegate verbatim to painters.radar_concentric.paint"
