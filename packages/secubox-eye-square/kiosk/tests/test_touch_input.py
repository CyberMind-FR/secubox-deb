# packages/secubox-eye-square/kiosk/tests/test_touch_input.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for touch_input.py — synthetic evdev events → tap/drag dispatch."""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from secubox_eye_square_kiosk.touch_input import TouchEvent, classify


def test_classify_short_press_returns_tap():
    """Press + release within 250ms at same coord = tap."""
    press = TouchEvent(kind="press", x=100, y=100, t=0.0)
    release = TouchEvent(kind="release", x=100, y=100, t=0.1)
    result = classify(press, release)
    assert result.kind == "tap"
    assert result.x == 100
    assert result.y == 100


def test_classify_long_press_returns_long_tap():
    press = TouchEvent(kind="press", x=240, y=240, t=0.0)
    release = TouchEvent(kind="release", x=240, y=240, t=1.5)
    result = classify(press, release)
    assert result.kind == "long_tap"


def test_classify_drag_returns_drag():
    """Release > 10px from press = drag with delta."""
    press = TouchEvent(kind="press", x=100, y=100, t=0.0)
    release = TouchEvent(kind="release", x=100, y=200, t=0.2)
    result = classify(press, release)
    assert result.kind == "drag"
    assert result.dx == 0
    assert result.dy == 100
