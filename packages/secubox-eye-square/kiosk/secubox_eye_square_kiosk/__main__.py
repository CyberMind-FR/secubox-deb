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
from .transport_manager import TransportManager

log = logging.getLogger("secubox_eye_square_kiosk")

FB_PATH = os.environ.get("EYE_SQUARE_FB", "/dev/fb0")
HELPER_SOCK = os.environ.get(
    "EYE_SQUARE_HELPER_SOCK", "/run/secubox/eye-square-helper.sock"
)
TARGET_FPS = 30
PROBE_INTERVAL_S = 30
METRICS_INTERVAL_S = 2
# Radar sweep rotation speed (matches the deployed round fallback radar).
RADAR_RPM = 12.0


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

    # PointerInput's _discover_devices picks up every /dev/input/event*
    # that exposes BTN_LEFT or BTN_TOUCH — that covers USB mouse, USB
    # touchpad, and the 7" DSI touchscreen in one place. The legacy
    # touch_input.py free functions are kept on disk for now but not
    # called from the loop to avoid duplicate reads on the same fds.
    pointer = PointerInput(fb_size=(fb.width, fb.height))

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

            # Input poll + dispatch — mouse/touchpad/touchscreen all go
            # through PointerInput (T12) which discovers BTN_LEFT and
            # BTN_TOUCH devices.
            for ev in pointer.poll():
                if ev.kind == "tap":
                    _dispatch_tap(ev.x, ev.y, panel, dashboard)

            # Render. phase advances the radar sweep angle — monotonic
            # so frame-to-frame motion is smooth across system clock jumps.
            phase = (time.monotonic() * RADAR_RPM / 60.0) % 1.0
            full = dashboard.layout(metrics, phase=phase)
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
