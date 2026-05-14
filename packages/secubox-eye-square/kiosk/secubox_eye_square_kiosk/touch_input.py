# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/touch_input.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Touch input via python-evdev.

Reads /dev/input/event* devices, filters for touchscreen devices (ABS_X +
BTN_TOUCH), groups press+release events into taps and drags, and exposes
a non-blocking read_event() generator for the kiosk event loop.

A real device opens evdev.InputDevice. A test or headless run can feed
synthetic TouchEvent objects directly to classify().
"""
from __future__ import annotations

import glob
import logging
import select
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("secubox_eye_square_kiosk.touch_input")

TAP_MAX_DURATION_S = 0.4
LONG_TAP_MIN_DURATION_S = 1.0
DRAG_MIN_DISTANCE_PX = 10


@dataclass
class TouchEvent:
    """Single touch lifecycle event (press or release)."""
    kind: str   # "press" | "release"
    x: int
    y: int
    t: float    # event timestamp in seconds


@dataclass
class GestureEvent:
    """Classified gesture: tap, long_tap, or drag."""
    kind: str   # "tap" | "long_tap" | "drag"
    x: int      # press location
    y: int
    dx: int = 0
    dy: int = 0


def classify(press: TouchEvent, release: TouchEvent) -> GestureEvent:
    """Classify a press+release pair as tap / long_tap / drag."""
    dx = release.x - press.x
    dy = release.y - press.y
    distance_sq = dx * dx + dy * dy
    duration = release.t - press.t
    if distance_sq > DRAG_MIN_DISTANCE_PX * DRAG_MIN_DISTANCE_PX:
        return GestureEvent(kind="drag", x=press.x, y=press.y, dx=dx, dy=dy)
    if duration >= LONG_TAP_MIN_DURATION_S:
        return GestureEvent(kind="long_tap", x=press.x, y=press.y)
    return GestureEvent(kind="tap", x=press.x, y=press.y)


def find_touch_devices() -> list:
    """Locate evdev devices with ABS_X capability (touchscreens + mice + touchpads)."""
    try:
        from evdev import InputDevice, ecodes
    except ImportError:
        log.warning("python-evdev not installed; touch input disabled")
        return []
    devices = []
    for path in sorted(glob.glob("/dev/input/event*")):
        try:
            dev = InputDevice(path)
        except OSError:
            continue
        caps = dev.capabilities()
        if ecodes.EV_ABS in caps or ecodes.EV_KEY in caps:
            devices.append(dev)
    return devices


def read_events(devices: list, timeout_s: float = 0.0):
    """Non-blocking generator yielding raw evdev events. timeout_s=0 = poll only."""
    if not devices:
        return
    try:
        from evdev import ecodes
    except ImportError:
        return
    r, _, _ = select.select(devices, [], [], timeout_s)
    for dev in r:
        for event in dev.read():
            yield event
