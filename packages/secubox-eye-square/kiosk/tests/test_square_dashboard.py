# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for SquareDashboard — composes round-style dashboard + right_panel."""
import sys
from pathlib import Path

# secubox_common is at <repo>/remote-ui/common/python/ on dev hosts and
# at /var/www/common/python/ on the image. Add the dev path for tests.
_DEV = Path(__file__).resolve().parents[4] / "remote-ui" / "common" / "python"
if str(_DEV) not in sys.path:
    sys.path.insert(0, str(_DEV))

from PIL import Image

from secubox_eye_square_kiosk.square_dashboard import SquareDashboard


class _FakeRightPanel:
    """Stand-in for right_panel.RightPanel."""
    def __init__(self):
        self.draw_called_with = None

    def draw(self, region: Image.Image) -> None:
        self.draw_called_with = region.size
        # Paint a known-colour pixel so test can detect that right panel ran.
        region.putpixel((10, 10), (0xAA, 0xBB, 0xCC, 255))


def test_square_dashboard_size_is_800x480():
    sd = SquareDashboard(right_panel=_FakeRightPanel())
    assert sd.SIZE == (800, 480)


def test_square_dashboard_layout_calls_right_panel():
    panel = _FakeRightPanel()
    sd = SquareDashboard(right_panel=panel)
    img = sd.layout({})
    assert panel.draw_called_with == (320, 480)
    # The fake right panel painted (0xAA, 0xBB, 0xCC) at panel-local (10, 10);
    # in the composed image that lands at (480 + 10, 10).
    assert img.getpixel((490, 10))[:3] == (0xAA, 0xBB, 0xCC)


def test_square_dashboard_layout_paints_left_dashboard_region():
    """The 480×480 left region must have non-black pixels (rainbow ring etc.)."""
    sd = SquareDashboard(right_panel=_FakeRightPanel())
    img = sd.layout({})
    # Sample at 12 o'clock on the rainbow ring (around y=10, x=240).
    nonblack = 0
    for x in range(200, 280):
        if img.getpixel((x, 10))[:3] != (0, 0, 0):
            nonblack += 1
    assert nonblack > 0, "no non-black pixels at top of left dashboard"


def test_square_dashboard_output_is_rgba_image():
    sd = SquareDashboard(right_panel=_FakeRightPanel())
    img = sd.layout({})
    assert img.mode == "RGBA"
    assert img.size == (800, 480)
