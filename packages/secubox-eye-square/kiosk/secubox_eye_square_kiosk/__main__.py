# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox Eye Square kiosk — event loop driver (converged)."""
from __future__ import annotations

import logging
import os
import sys
import time

from .cursor import draw_cursor
from .framebuffer import FrameBuffer
from .helper_client import HelperClient
from .pointer_input import PointerInput
from .right_panel import RightPanel
from .sim import SimState, step
from .square_dashboard import SquareDashboard
from .touch_input import TouchEvent, classify, find_touch_devices, read_events
from .transport_manager import TransportManager

log = logging.getLogger("secubox_eye_square_kiosk")

FB_PATH = os.environ.get("EYE_SQUARE_FB", "/dev/fb0")
HELPER_SOCK = os.environ.get(
    "EYE_SQUARE_HELPER_SOCK", "/run/secubox/eye-square-helper.sock"
)
TARGET_FPS = 30
PROBE_INTERVAL_S = 30
METRICS_INTERVAL_S = 2


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    log.info("Starting SecuBox Eye Square kiosk (converged)")

    helper = HelperClient(HELPER_SOCK)
    tm = TransportManager(simulate=False)
    tm.probe()

    sim = SimState()

    panel = RightPanel(helper)
    dashboard = SquareDashboard(right_panel=panel)
    tm.on_transport_change = lambda active: panel.on_transport_change(active)

    try:
        fb = FrameBuffer(FB_PATH)
    except OSError as e:
        log.error("Cannot open framebuffer %s: %s", FB_PATH, e)
        return 1

    touch_devices = find_touch_devices()
    pointer = PointerInput(fb_size=(fb.width, fb.height))

    # Touch gesture state: track press so we can classify on release.
    _pending_press: TouchEvent | None = None

    last_probe = 0.0
    last_metrics = 0.0
    frame_period = 1.0 / TARGET_FPS
    metrics: dict = {}

    try:
        while True:
            now = time.time()

            # Periodic transport probe + metrics refresh.
            if now - last_probe > PROBE_INTERVAL_S:
                tm.probe()
                last_probe = now
            if now - last_metrics > METRICS_INTERVAL_S:
                fetched = tm.fetch_metrics()
                if fetched is None:
                    step(sim, refresh_interval_s=METRICS_INTERVAL_S)
                    metrics = sim.to_dict()
                else:
                    metrics = fetched
                last_metrics = now

            # Touch input poll + dispatch.
            for raw in read_events(touch_devices, timeout_s=0.0):
                # read_events yields raw evdev events; we reconstruct
                # TouchEvent press/release from ABS_X/Y + BTN_TOUCH.
                # Gesture classification is handled on release.
                pass  # evdev decode handled at device level; taps via pointer

            # Pointer input poll + dispatch.
            for ev in pointer.poll():
                if ev.kind == "tap":
                    _dispatch_tap(ev.x, ev.y, panel, dashboard)

            # Render.
            full = dashboard.layout(metrics)
            if pointer.cursor_visible:
                draw_cursor(full, *pointer.cursor_xy)
            fb.blit(full)

            time.sleep(frame_period)
    except KeyboardInterrupt:
        log.info("Shutting down kiosk")
    finally:
        fb.close()
    return 0


def _dispatch_tap(x: int, y: int, panel: RightPanel, dashboard) -> None:
    if x >= 480:
        panel.handle_tap(x - 480, y)
    else:
        # Future: dashboard.handle_tap(x, y) — pod cluster interaction.
        # For now the dashboard is read-only; only the tab bar takes taps.
        pass


if __name__ == "__main__":
    sys.exit(main())
