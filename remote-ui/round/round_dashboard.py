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
    RING_RADII = [200, 185, 170, 155, 140, 125]

    def layout(self, metrics: dict) -> Image.Image:
        img = Image.new("RGBA", self.SIZE, theme.COSMOS_BLACK + (255,))
        self.paint_rainbow_ring(img, self.CENTER, 235, 220)
        self.paint_concentric_arcs(img, self.CENTER, MODULES, metrics,
                                    self.RING_RADII)
        # pod_size=48 matches the deployed icon sizes (22/48/96/128); 40 would
        # miss and fall back to the first-letter placeholder. radius bumped
        # to 78 so pod inner edge (54) stays clear of the central button (44).
        self.paint_pod_cluster(img, MODULES, self.CENTER, radius=78, pod_size=48)
        self.paint_central_button(img, self.CENTER, size=44)
        return img

    # Round-only additional view modes (called by fb_dashboard.py's main
    # loop when the user long-presses center → radial menu → terminal/flash/auth).
    def layout_terminal(self, term_state) -> Image.Image:
        # Delegates to the existing draw_terminal() helper for now;
        # extracted into a method to give the main loop a class-based API.
        from fb_dashboard import draw_terminal
        return draw_terminal(term_state)

    def layout_flash(self, flash_state) -> Image.Image:
        from fb_dashboard import draw_flash_progress
        return draw_flash_progress(flash_state)

    def layout_auth(self, auth_state) -> Image.Image:
        from fb_dashboard import draw_auth_mode
        return draw_auth_mode(auth_state)
