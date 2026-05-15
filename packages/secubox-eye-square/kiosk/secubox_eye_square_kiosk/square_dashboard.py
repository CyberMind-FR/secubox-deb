# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SquareDashboard — 800×480 landscape kiosk for Pi 4B/400.

Composes a 480×480 round-style dashboard (using secubox_common
primitives) into the left half, then pastes the right_panel's tab bar
+ active tab content (320×480) into the right half.
"""
from __future__ import annotations

from PIL import Image

from secubox_common import theme
from secubox_common.canvas import DashboardCanvas
from secubox_common.modules import MODULES


class SquareDashboard(DashboardCanvas):
    SIZE = (800, 480)
    DASHBOARD_REGION_SIZE = (480, 480)
    PANEL_REGION_SIZE = (320, 480)
    CENTER = (240, 240)
    # Same radii as RoundDashboard so the left half is visually identical
    # to the deployed Pi Zero W radar.
    RING_RADII = [214, 188, 162, 136, 110, 84]

    def __init__(self, right_panel):
        self.right_panel = right_panel

    def layout(self, metrics: dict, phase: float = 0.0) -> Image.Image:
        """Render one frame at animation `phase` (0..1).

        Phase rotates the radar sweep on the left half; the right panel
        is static. Pass `phase=0.0` for a still frame.
        """
        img = Image.new("RGBA", self.SIZE, theme.COSMOS_BLACK + (255,))

        # Left dashboard region — phase-aware radar.
        dash = Image.new("RGBA", self.DASHBOARD_REGION_SIZE,
                         theme.COSMOS_BLACK + (255,))
        self.paint_radar_concentric(
            dash, self.CENTER, MODULES, metrics,
            radii=self.RING_RADII, phase=phase, draw_hub=True,
        )
        # pod_size=48 matches deployed icon sizes (22/48/96/128).
        self.paint_pod_cluster(dash, MODULES, self.CENTER, radius=78, pod_size=48)
        self.paint_central_button(dash, self.CENTER, size=44)
        img.paste(dash, (0, 0))

        # Right panel (static).
        panel = Image.new("RGBA", self.PANEL_REGION_SIZE,
                          theme.COSMOS_BLACK + (255,))
        self.right_panel.draw(panel)
        img.paste(panel, (480, 0))

        return img
