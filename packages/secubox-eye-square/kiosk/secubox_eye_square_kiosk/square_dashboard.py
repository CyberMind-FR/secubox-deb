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
    RING_RADII = [200, 185, 170, 155, 140, 125]

    def __init__(self, right_panel):
        self.right_panel = right_panel

    def layout(self, metrics: dict) -> Image.Image:
        # Image.new() with COSMOS_BLACK+(255,) is equivalent to calling
        # paint_background on a fresh canvas; skip the redundant fill.
        img = Image.new("RGBA", self.SIZE, theme.COSMOS_BLACK + (255,))

        # Left dashboard region.
        dash = Image.new("RGBA", self.DASHBOARD_REGION_SIZE,
                         theme.COSMOS_BLACK + (255,))
        self.paint_rainbow_ring(dash, self.CENTER, 235, 220)
        self.paint_concentric_arcs(dash, self.CENTER, MODULES, metrics,
                                    self.RING_RADII)
        self.paint_pod_cluster(dash, MODULES, self.CENTER, radius=70, pod_size=40)
        self.paint_central_button(dash, self.CENTER, size=44)
        img.paste(dash, (0, 0))

        # Right panel.
        panel = Image.new("RGBA", self.PANEL_REGION_SIZE,
                          theme.COSMOS_BLACK + (255,))
        self.right_panel.draw(panel)
        img.paste(panel, (480, 0))

        return img
