# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for RoundDashboard — Pi Zero W 480×480 layout via secubox_common."""
import sys
from pathlib import Path

_DEV = Path(__file__).resolve().parents[3] / "remote-ui" / "common" / "python"
if str(_DEV) not in sys.path:
    sys.path.insert(0, str(_DEV))

# Also add the round/ directory itself so round_dashboard imports work.
_ROUND = Path(__file__).resolve().parents[1]
if str(_ROUND) not in sys.path:
    sys.path.insert(0, str(_ROUND))

from round_dashboard import RoundDashboard
from secubox_common.canvas import DashboardCanvas


def test_round_dashboard_subclasses_canvas():
    assert issubclass(RoundDashboard, DashboardCanvas)


def test_round_dashboard_size_is_480():
    rd = RoundDashboard()
    assert rd.SIZE == (480, 480)


def test_round_dashboard_layout_returns_rgba_480x480():
    rd = RoundDashboard()
    img = rd.layout({})
    assert img.mode == "RGBA"
    assert img.size == (480, 480)


def test_round_dashboard_layout_paints_rainbow_ring():
    rd = RoundDashboard()
    img = rd.layout({})
    # Rainbow ring is at radius 220-235; sample at radius 227 angle 0.
    px = img.getpixel((240 + 227, 240))
    assert px[:3] != (0, 0, 0), "rainbow ring not painted at 3 o'clock"
