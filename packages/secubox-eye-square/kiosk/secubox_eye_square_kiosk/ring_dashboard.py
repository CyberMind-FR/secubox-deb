# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/ring_dashboard.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Ring dashboard — left 480x480 Pillow renderer.

Pixel-faithful intent vs Phase 1 round/index.html: 6 concentric arcs
(radii 214/201/188/175/162/149), each module colour-mapped, smooth fill
animation toward target value, central clock + hostname + uptime,
transport badge, status row, temperature bar. Alerts ribbon overlays
bottom 24px when severity ≥ warn.
"""
from __future__ import annotations

import math
import socket
import time
from datetime import datetime
from typing import Callable, Optional

from PIL import Image, ImageDraw

from . import theme
from .modules_table import MODULES, Module

CX, CY = 240, 240
RING_WIDTH = 5
EASE_STEPS = 8  # animation frames between metric updates
POD_DISTANCE = 235
ALERT_RIBBON_HEIGHT = 24
TRANSPORT_BADGE_Y = 14


class RingDashboard:
    """480x480 left half. update_metrics() sets target values; advance() eases
    current values toward target each tick; draw() renders the frame."""

    def __init__(self):
        self.size = (480, 480)
        self.transport = "SIM"
        self.hostname = socket.gethostname()
        self._current: dict[str, float] = {m.metric: 0.0 for m in MODULES}
        self._target: dict[str, float] = {m.metric: 0.0 for m in MODULES}
        self._alert_text = ""
        self._alert_severity = "info"
        self.on_module_tap: Callable[[str], None] = lambda _: None

    def update_metrics(self, metrics: dict) -> None:
        """Set new target values. _current eases toward _target over EASE_STEPS frames.

        Stores raw metric values (e.g. cpu_percent=80.0). The modules_table
        extract() function converts to 0..1 fill ratio at draw time.
        """
        for m in MODULES:
            if m.metric in metrics:
                self._target[m.metric] = float(metrics[m.metric])

    def advance(self) -> None:
        """One easing frame — move _current toward _target by 1/EASE_STEPS."""
        for m in MODULES:
            cur = self._current[m.metric]
            tgt = self._target[m.metric]
            self._current[m.metric] = cur + (tgt - cur) / EASE_STEPS

    def set_transport(self, active: str) -> None:
        self.transport = active

    def set_alert_ribbon(self, text: str, severity: str = "info") -> None:
        self._alert_text = text
        self._alert_severity = severity

    def clear_alert_ribbon(self) -> None:
        self._alert_text = ""

    def handle_tap(self, x: int, y: int) -> None:
        """Detect pod taps. Pods sit at angles -π/2, -π/2+π/3, ... around the ring."""
        dx, dy = x - CX, y - CY
        dist = math.hypot(dx, dy)
        if abs(dist - POD_DISTANCE) > 30:
            return
        # angle in radians, 0 = right, -π/2 = top
        angle = math.atan2(dy, dx)
        # Normalise so AUTH is at -π/2 (top), increment by π/3 clockwise
        normalised = (angle + math.pi / 2) % (2 * math.pi)
        idx = int(normalised / (math.pi / 3))
        if 0 <= idx < len(MODULES):
            self.on_module_tap(MODULES[idx].name)

    def _pod_position(self, idx: int) -> tuple[int, int]:
        """Where to draw the idx-th pod's icon/label."""
        angle = -math.pi / 2 + idx * (math.pi / 3)
        x = CX + int(POD_DISTANCE * math.cos(angle))
        y = CY + int(POD_DISTANCE * math.sin(angle))
        return x, y

    def draw(self) -> Image.Image:
        img = Image.new("RGBA", self.size, theme.COSMOS_BLACK + (255,))
        draw = ImageDraw.Draw(img)

        # 6 rings — draw track then fill arc for each module
        for m in MODULES:
            pct = m.extract(self._current)
            # ring track (full circle, very dark)
            draw.arc(
                (CX - m.radius, CY - m.radius, CX + m.radius, CY + m.radius),
                start=-90, end=270,
                fill=(0x14, 0x14, 0x14, 255), width=RING_WIDTH + 2,
            )
            # ring fill (proportional arc from top, clockwise)
            if pct > 0.005:
                end_angle = -90 + 360 * pct
                draw.arc(
                    (CX - m.radius, CY - m.radius, CX + m.radius, CY + m.radius),
                    start=-90, end=end_angle,
                    fill=m.colour + (255,), width=RING_WIDTH,
                )

        # Pods — coloured dot at ring perimeter + module name label
        for i, m in enumerate(MODULES):
            px, py = self._pod_position(i)
            # Coloured dot
            draw.ellipse((px - 5, py - 5, px + 5, py + 5), fill=m.colour + (255,))
            # Module name label below dot
            draw.text((px - 16, py + 8), m.name, fill=theme.TEXT_PRIMARY,
                      font=theme.DEFAULT_FONT)

        # Central clock + hostname
        now = datetime.now().strftime("%H:%M:%S")
        date = datetime.now().strftime("%a %d %b")
        draw.text((CX - 50, CY - 18), now, fill=theme.TEXT_PRIMARY,
                  font=theme.DEFAULT_FONT)
        draw.text((CX - 30, CY + 4), date, fill=theme.TEXT_MUTED,
                  font=theme.DEFAULT_FONT)
        draw.text((CX - 70, CY + 22), self.hostname[:18], fill=theme.TEXT_MUTED,
                  font=theme.DEFAULT_FONT)

        # Transport badge top-right
        dot = "●" if self.transport in ("OTG", "WiFi") else "○"
        dot_colour = theme.MATRIX_GREEN if dot == "●" else theme.TEXT_MUTED
        draw.text((CX + 110, TRANSPORT_BADGE_Y), f"{dot} {self.transport}",
                  fill=dot_colour, font=theme.DEFAULT_FONT)

        # Alerts ribbon — overlay bottom 24px when alert is active
        if self._alert_text:
            ribbon_colour = theme.SEVERITY.get(self._alert_severity, theme.TEXT_MUTED)
            draw.rectangle((0, 480 - ALERT_RIBBON_HEIGHT, 480, 480),
                           fill=theme.COSMOS_BLACK + (200,))
            draw.text((10, 480 - ALERT_RIBBON_HEIGHT + 4),
                      f"▲ {self._alert_text}"[:50], fill=ribbon_colour,
                      font=theme.DEFAULT_FONT)

        return img
