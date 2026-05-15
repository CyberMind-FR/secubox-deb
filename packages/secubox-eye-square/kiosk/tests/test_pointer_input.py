# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Tests for PointerInput — mouse + touchpad → InputEvent."""
import time

import pytest

from secubox_eye_square_kiosk.pointer_input import PointerInput, InputEvent


@pytest.fixture
def pointer():
    p = PointerInput(fb_size=(800, 480))
    return p


def _feed_evdev(pointer, events: list[tuple]):
    """Inject (code_name, value) events as if from a single evdev device."""
    pointer._inject_for_tests(events)


def test_initial_cursor_at_centre(pointer):
    assert pointer.cursor_xy == (400, 240)


def test_relative_motion_updates_cursor(pointer):
    _feed_evdev(pointer, [("EV_REL_X", 10), ("EV_REL_Y", -5), ("EV_SYN", 0)])
    events = pointer.poll()
    assert pointer.cursor_xy == (410, 235)
    assert any(e.kind == "motion" for e in events)


def test_relative_motion_clamps_to_fb_bounds(pointer):
    _feed_evdev(pointer, [("EV_REL_X", -1000), ("EV_REL_Y", -1000), ("EV_SYN", 0)])
    pointer.poll()
    assert pointer.cursor_xy == (0, 0)
    _feed_evdev(pointer, [("EV_REL_X", 9999), ("EV_REL_Y", 9999), ("EV_SYN", 0)])
    pointer.poll()
    assert pointer.cursor_xy == (799, 479)


def test_btn_left_emits_tap_at_cursor(pointer):
    _feed_evdev(pointer, [("EV_REL_X", 50), ("EV_REL_Y", 50)])
    pointer.poll()  # consume motion
    _feed_evdev(pointer, [("EV_KEY_BTN_LEFT", 1), ("EV_SYN", 0)])
    events = pointer.poll()
    taps = [e for e in events if e.kind == "tap"]
    assert len(taps) == 1
    assert taps[0].x == 450 and taps[0].y == 290


def test_absolute_motion_sets_cursor_directly(pointer):
    _feed_evdev(pointer, [("EV_ABS_X", 600), ("EV_ABS_Y", 300), ("EV_SYN", 0)])
    pointer.poll()
    assert pointer.cursor_xy == (600, 300)


def test_btn_touch_emits_tap(pointer):
    _feed_evdev(pointer, [
        ("EV_ABS_X", 100), ("EV_ABS_Y", 100),
        ("EV_KEY_BTN_TOUCH", 1), ("EV_SYN", 0),
    ])
    events = pointer.poll()
    taps = [e for e in events if e.kind == "tap"]
    assert len(taps) == 1
    assert taps[0].x == 100 and taps[0].y == 100


def test_cursor_visible_after_motion(pointer):
    _feed_evdev(pointer, [("EV_REL_X", 5), ("EV_SYN", 0)])
    pointer.poll()
    assert pointer.cursor_visible is True


def test_cursor_auto_hides_after_timeout(pointer, monkeypatch):
    _feed_evdev(pointer, [("EV_REL_X", 5), ("EV_SYN", 0)])
    pointer.poll()
    assert pointer.cursor_visible is True

    # Advance the clock by AUTO_HIDE_S + 1.
    real_time = time.time
    monkeypatch.setattr(time, "time",
                        lambda: real_time() + PointerInput.AUTO_HIDE_S + 1.0)
    assert pointer.cursor_visible is False


def test_oserror_in_poll_does_not_propagate(pointer):
    """Simulated USB unplug (read raises OSError) is swallowed."""
    pointer._mark_device_gone_for_tests()
    pointer.poll()  # should not raise
