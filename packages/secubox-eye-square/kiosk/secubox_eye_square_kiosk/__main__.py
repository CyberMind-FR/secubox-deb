# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/__main__.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox Eye Square kiosk — event loop driver."""
from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

from PIL import Image

from .framebuffer import FrameBuffer
from .helper_client import HelperClient
from .right_panel import RightPanel
from .ring_dashboard import RingDashboard
from .sim import SimState, step
from .transport_manager import TransportManager

log = logging.getLogger("secubox_eye_square_kiosk")

FB_PATH = os.environ.get("EYE_SQUARE_FB", "/dev/fb0")
HELPER_SOCK = os.environ.get("EYE_SQUARE_HELPER_SOCK",
                              "/run/secubox/eye-square-helper.sock")
TARGET_FPS = 30
PROBE_INTERVAL_S = 30
METRICS_INTERVAL_S = 2


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    log.info("Starting SecuBox Eye Square kiosk")

    # Helper + TransportManager
    helper = HelperClient(HELPER_SOCK)
    tm = TransportManager(simulate=False)
    tm.probe()

    # SIM state for fallback
    sim = SimState()

    # Dashboard + right panel
    rd = RingDashboard()
    panel = RightPanel(helper)
    rd.on_module_tap = panel.on_module_tap
    tm.on_transport_change = lambda active: (
        panel.on_transport_change(active),
        rd.set_transport(active),
    )

    # Framebuffer
    try:
        fb = FrameBuffer(FB_PATH)
    except OSError as e:
        log.error("Cannot open framebuffer %s: %s", FB_PATH, e)
        return 1

    last_probe = 0.0
    last_metrics = 0.0
    frame_period = 1.0 / TARGET_FPS

    try:
        while True:
            now = time.time()

            # Periodic transport probe
            if now - last_probe > PROBE_INTERVAL_S:
                tm.probe()
                last_probe = now

            # Periodic metrics fetch (or SIM drift)
            if now - last_metrics > METRICS_INTERVAL_S:
                metrics = tm.fetch_metrics()
                if metrics is None:
                    step(sim, refresh_interval_s=METRICS_INTERVAL_S)
                    metrics = sim.to_dict()
                rd.update_metrics(metrics)
                last_metrics = now

            # Animation tick
            rd.advance()

            # Compose frame
            full = Image.new("RGBA", (800, 480), (0, 0, 0, 255))
            full.paste(rd.draw(), (0, 0))
            panel_img = Image.new("RGBA", (320, 480), (0, 0, 0, 255))
            panel.draw(panel_img)
            full.paste(panel_img, (480, 0))

            fb.blit(full)

            time.sleep(frame_period)
    except KeyboardInterrupt:
        log.info("Shutting down kiosk")
    finally:
        fb.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
