# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/right_panel.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Right panel — tab bar at top, content area below. Owns 4 tab widgets."""
from __future__ import annotations

from PIL import Image, ImageDraw

from . import theme
from .tabs.alerts import AlertsTab
from .tabs.console import ConsoleTab
from .tabs.mode_controls import ModeControlsTab
from .tabs.module_detail import ModuleDetailTab

TAB_BAR_HEIGHT = 56
TAB_WIDTH = 80
TAB_LABELS = [
    ("alerts", "ALERTS"),
    ("module_detail", "DETAIL"),
    ("console", "CON"),
    ("mode_controls", "CTL"),
]


class RightPanel:
    """Manages the 4 tabs and the tab bar."""

    def __init__(self, helper_client):
        self.tabs = {
            "alerts": AlertsTab(),
            "module_detail": ModuleDetailTab(),
            "console": ConsoleTab(),
            "mode_controls": ModeControlsTab(helper_client),
        }
        # Wire alert tap → switch to module detail
        self.tabs["alerts"].on_row_tap = self._on_alert_tapped
        self.active_tab = "alerts"

    def set_active_tab(self, name: str) -> None:
        if name in self.tabs:
            self.active_tab = name

    def on_module_tap(self, module_name: str) -> None:
        """Called by ring_dashboard when the user taps a pod."""
        self.active_tab = "module_detail"
        # value/history can be empty for the initial switch; ring_dashboard will refresh
        self.tabs["module_detail"].load_module(module_name, "", value=0.0, history=[])

    def on_transport_change(self, active: str) -> None:
        self.tabs["mode_controls"].update_transport(active)

    def append_console_line(self, line: str) -> None:
        self.tabs["console"].append_line(line)

    def set_alerts(self, items) -> None:
        self.tabs["alerts"].set_alerts(items)

    def _on_alert_tapped(self, item) -> None:
        self.active_tab = "module_detail"
        self.tabs["module_detail"].load_module(item.module, "", value=0.0, history=[])

    def handle_tap(self, x: int, y: int) -> None:
        # Tab bar?
        if y < TAB_BAR_HEIGHT:
            tab_idx = x // TAB_WIDTH
            if 0 <= tab_idx < len(TAB_LABELS):
                self.active_tab = TAB_LABELS[tab_idx][0]
            return
        # Route to active tab (subtract tab bar offset)
        self.tabs[self.active_tab].handle_tap(x, y - TAB_BAR_HEIGHT)

    def draw(self, region: Image.Image) -> None:
        """Render tab bar + active tab into the 320x480 region."""
        draw = ImageDraw.Draw(region)
        w, h = region.size
        # Tab bar background
        draw.rectangle((0, 0, w, TAB_BAR_HEIGHT), fill=theme.COSMOS_BLACK)
        for i, (key, label) in enumerate(TAB_LABELS):
            x = i * TAB_WIDTH
            colour = theme.GOLD_HERMETIC if key == self.active_tab else theme.TEXT_MUTED
            draw.rectangle((x, 0, x + TAB_WIDTH, TAB_BAR_HEIGHT - 1),
                           outline=colour, width=1 if key != self.active_tab else 2)
            draw.text((x + 8, 20), label, fill=colour, font=theme.DEFAULT_FONT)
        # Content area
        content_h = h - TAB_BAR_HEIGHT
        content = Image.new("RGBA", (w, content_h), (0, 0, 0, 255))
        self.tabs[self.active_tab].draw(content)
        region.paste(content, (0, TAB_BAR_HEIGHT))
