# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""PointerInput — mouse + touchpad via python-evdev.

Reads /dev/input/event* devices that expose BTN_LEFT or BTN_TOUCH,
emits InputEvent("motion"/"tap", x, y) at the current cursor position.

The cursor position is clamped to the framebuffer bounds passed in at
construction. Mouse devices send relative motion (REL_X/Y); touchpads
send absolute (ABS_X/Y). Both are mapped through to (cursor_x, cursor_y).

Auto-hide: `cursor_visible` returns False if no motion in the last
AUTO_HIDE_S seconds. The kiosk overlay logic uses this to skip drawing
the cursor sprite when idle.

USB unplug: OSError on read marks the device gone; `poll()` keeps
running and re-tries device discovery every 30 s.
"""
from __future__ import annotations

import fcntl
import logging
import os
import time
from dataclasses import dataclass

log = logging.getLogger("secubox_eye_square_kiosk.pointer_input")

try:
    from evdev import InputDevice, list_devices, ecodes
    HAS_EVDEV = True
except ImportError:
    HAS_EVDEV = False


@dataclass
class InputEvent:
    kind: str  # "tap" | "motion"
    x: int
    y: int


# Event-code names used by tests' _inject_for_tests helper.
_TEST_CODE_TO_TYPE_CODE = {
    "EV_REL_X": ("REL", "REL_X"),
    "EV_REL_Y": ("REL", "REL_Y"),
    "EV_ABS_X": ("ABS", "ABS_X"),
    "EV_ABS_Y": ("ABS", "ABS_Y"),
    "EV_KEY_BTN_LEFT": ("KEY", "BTN_LEFT"),
    "EV_KEY_BTN_TOUCH": ("KEY", "BTN_TOUCH"),
    "EV_SYN": ("SYN", "SYN_REPORT"),
}


class PointerInput:
    AUTO_HIDE_S = 3.0
    REDISCOVERY_INTERVAL_S = 30.0

    def __init__(self, fb_size: tuple[int, int]):
        self.fb_w, self.fb_h = fb_size
        self._x = fb_size[0] // 2
        self._y = fb_size[1] // 2
        # Epoch-relative — cursor stays hidden until first motion.
        self._last_motion = 0.0
        self._last_rediscovery = 0.0
        self._test_queue: list[tuple] = []
        self._device_gone = False
        self._devices = []
        if HAS_EVDEV:
            self._devices = self._discover_devices()

    @property
    def cursor_xy(self) -> tuple[int, int]:
        return (self._x, self._y)

    @property
    def cursor_visible(self) -> bool:
        return (time.time() - self._last_motion) < self.AUTO_HIDE_S

    def poll(self) -> list[InputEvent]:
        out: list[InputEvent] = []
        # Drain test queue first.
        out.extend(self._drain_test_queue())
        # Real devices.
        for dev in list(self._devices):
            try:
                for ev in dev.read():
                    e = self._handle_evdev_event(ev)
                    if e is not None:
                        out.append(e)
            except BlockingIOError:
                continue  # nothing queued, normal
            except OSError as ose:
                log.warning("pointer device %s gone: %s", dev.path, ose)
                self._devices.remove(dev)
                self._device_gone = True
        # Periodic re-discovery if any device was lost.
        if self._device_gone and HAS_EVDEV:
            now = time.time()
            if now - self._last_rediscovery > self.REDISCOVERY_INTERVAL_S:
                self._devices = self._discover_devices()
                self._last_rediscovery = now
                if self._devices:
                    self._device_gone = False
        return out

    # ---- internals ----

    def _discover_devices(self) -> list:
        if not HAS_EVDEV:
            return []
        devices = []
        for path in list_devices():
            try:
                dev = InputDevice(path)
                caps = dev.capabilities()
                key_caps = caps.get(ecodes.EV_KEY, [])
                if ecodes.BTN_LEFT in key_caps or ecodes.BTN_TOUCH in key_caps:
                    # Make it non-blocking so poll() can drain without hanging.
                    flags = fcntl.fcntl(dev.fd, fcntl.F_GETFL)
                    fcntl.fcntl(dev.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                    devices.append(dev)
            except OSError:
                continue
        if devices:
            log.info("pointer devices found: %s", [d.path for d in devices])
        else:
            log.warning("no pointer devices found (mouse/touchpad/touchscreen)")
        return devices

    def _handle_evdev_event(self, ev) -> "InputEvent | None":
        if not HAS_EVDEV:
            return None
        if ev.type == ecodes.EV_REL:
            if ev.code == ecodes.REL_X:
                self._x = self._clamp_x(self._x + ev.value)
                self._touch_motion()
                return InputEvent("motion", self._x, self._y)
            elif ev.code == ecodes.REL_Y:
                self._y = self._clamp_y(self._y + ev.value)
                self._touch_motion()
                return InputEvent("motion", self._x, self._y)
        elif ev.type == ecodes.EV_ABS:
            if ev.code == ecodes.ABS_X:
                self._x = self._clamp_x(ev.value)
                self._touch_motion()
                return InputEvent("motion", self._x, self._y)
            elif ev.code == ecodes.ABS_Y:
                self._y = self._clamp_y(ev.value)
                self._touch_motion()
                return InputEvent("motion", self._x, self._y)
        elif ev.type == ecodes.EV_KEY:
            if ev.code in (ecodes.BTN_LEFT, ecodes.BTN_TOUCH) and ev.value == 1:
                return InputEvent("tap", self._x, self._y)
        return None

    def _drain_test_queue(self) -> list[InputEvent]:
        out: list[InputEvent] = []
        had_motion = False
        for name, value in self._test_queue:
            kind, code = _TEST_CODE_TO_TYPE_CODE.get(name, (None, None))
            if kind is None:
                continue
            if kind == "REL":
                if code == "REL_X":
                    self._x = self._clamp_x(self._x + value); had_motion = True
                elif code == "REL_Y":
                    self._y = self._clamp_y(self._y + value); had_motion = True
            elif kind == "ABS":
                if code == "ABS_X":
                    self._x = self._clamp_x(value); had_motion = True
                elif code == "ABS_Y":
                    self._y = self._clamp_y(value); had_motion = True
            elif kind == "KEY":
                if value == 1 and code in ("BTN_LEFT", "BTN_TOUCH"):
                    out.append(InputEvent("tap", self._x, self._y))
        if had_motion:
            self._touch_motion()
            out.append(InputEvent("motion", self._x, self._y))
        self._test_queue.clear()
        return out

    def _touch_motion(self) -> None:
        self._last_motion = time.time()

    def _clamp_x(self, x: int) -> int:
        return max(0, min(self.fb_w - 1, int(x)))

    def _clamp_y(self, y: int) -> int:
        return max(0, min(self.fb_h - 1, int(y)))

    # ---- test hooks ----

    def _inject_for_tests(self, events: list[tuple]) -> None:
        self._test_queue.extend(events)

    def _mark_device_gone_for_tests(self) -> None:
        self._device_gone = True
        self._devices = []
