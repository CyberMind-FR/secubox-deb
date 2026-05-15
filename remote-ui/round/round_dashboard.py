# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""RoundDashboard — 480×480 Pi Zero W kiosk using secubox_common primitives."""
from __future__ import annotations

from PIL import Image

from secubox_common import theme
from secubox_common.canvas import DashboardCanvas
from secubox_common.modules import MODULES


class RoundDashboard(DashboardCanvas):
    SIZE = (480, 480)
    CENTER = (240, 240)
    # Match the deployed fallback_manager.py radar geometry so the round
    # rendering stays visually identical after migration.
    RING_RADII = [214, 188, 162, 136, 110, 84]

    def layout(self, metrics: dict, phase: float = 0.0) -> Image.Image:
        """Render one frame at the given animation `phase` (0..1).

        Phase advances the rotating sweep; callers pass `phase=0.0` for
        a static still frame, or `(time.monotonic() * rpm / 60) % 1` for
        an animated loop.
        """
        img = Image.new("RGBA", self.SIZE, theme.COSMOS_BLACK + (255,))
        self.paint_radar_concentric(
            img, self.CENTER, MODULES, metrics,
            radii=self.RING_RADII, phase=phase, draw_hub=True,
        )
        # Pods sit on top of the hub; pod_size=48 matches deployed icon
        # sizes (22/48/96/128). radius=78 keeps the pod inner edge (54)
        # clear of the central button (44).
        self.paint_pod_cluster(img, MODULES, self.CENTER, radius=78, pod_size=48)
        self.paint_central_button(img, self.CENTER, size=44)
        return img

    # Round-only additional view modes (called by fb_dashboard.py's main
    # loop when the user long-presses center → radial menu → terminal/flash/auth).
    def layout_terminal(self, term_state) -> Image.Image:
        from fb_dashboard import draw_terminal
        return draw_terminal(term_state)

    def layout_flash(self, flash_state) -> Image.Image:
        from fb_dashboard import draw_flash_progress
        return draw_flash_progress(flash_state)

    def layout_auth(self, auth_state) -> Image.Image:
        from fb_dashboard import draw_auth_mode
        return draw_auth_mode(auth_state)
