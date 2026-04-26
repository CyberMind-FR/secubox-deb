"""
SecuBox Eye Remote — Dashboard Mode Display
Renders 6 metric rings with real-time SecuBox data.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import math
import time
from typing import Tuple

from PIL import Image, ImageDraw

from .renderer import (
    DisplayRenderer,
    RenderContext,
    MODULE_COLORS,
    TEXT_COLOR,
    TEXT_MUTED,
    STATUS_OK,
    STATUS_WARN,
    STATUS_OFFLINE,
)

# Ring configuration — 6 concentric rings (outer to inner)
RINGS = [
    {"name": "AUTH", "metric": "cpu", "unit": "%", "radius": 214, "width": 10},
    {"name": "WALL", "metric": "mem", "unit": "%", "radius": 201, "width": 10},
    {"name": "BOOT", "metric": "disk", "unit": "%", "radius": 188, "width": 10},
    {"name": "MIND", "metric": "load", "unit": "x", "radius": 175, "width": 10},
    {"name": "ROOT", "metric": "temp", "unit": "°", "radius": 162, "width": 10},
    {"name": "MESH", "metric": "wifi", "unit": "dB", "radius": 149, "width": 10},
]


class DashboardRenderer(DisplayRenderer):
    """Renders Dashboard mode with 6 metric rings."""

    def __init__(self):
        super().__init__()
        self._animation_offset = 0.0

    def render(self, ctx: RenderContext) -> Image.Image:
        """Render Dashboard mode frame with metric rings and status."""
        self.create_frame()
        draw = self.get_draw()

        self._draw_rings(draw, ctx)
        self._draw_connection_badge(draw, ctx)
        self._draw_center(draw, ctx)
        self._draw_status(draw, ctx)
        self.draw_circle_mask(draw)

        self._animation_offset += 0.02
        return self._frame

    def _draw_rings(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw the 6 metric rings (AUTH, WALL, BOOT, MIND, ROOT, MESH)."""
        cx, cy = self.center
        metrics = ctx.metrics

        for ring in RINGS:
            name = ring["name"]
            radius = ring["radius"]
            width = ring["width"]
            color = MODULE_COLORS.get(name, (128, 128, 128))

            # Get metric value and normalize to 0.0-1.0 range
            value = metrics.get(ring["metric"], 0)
            normalized = self._normalize_metric(ring["metric"], value)

            # Apply connection state visual feedback
            if ctx.connection_state == "degraded":
                color = tuple(c // 2 for c in color)
            elif ctx.connection_state == "stale":
                # Pulsing effect when stale
                pulse = (math.sin(self._animation_offset * 4) + 1) / 2
                color = tuple(int(c * (0.5 + 0.5 * pulse)) for c in color)

            # Draw background arc (very dim)
            bg_color = tuple(c // 8 for c in color)
            self._draw_arc(draw, cx, cy, radius, width, 0, 360, bg_color)

            # Draw value arc
            end_angle = int(normalized * 360)
            if end_angle > 0:
                self._draw_arc(draw, cx, cy, radius, width, -90, -90 + end_angle, color)

    def _normalize_metric(self, metric: str, value: float) -> float:
        """Normalize metric value to 0.0-1.0 range based on metric type."""
        if metric == "load":
            # Load average: normalize to 4.0 as 100%
            return min(1.0, value / 4.0)
        elif metric == "wifi":
            # WiFi RSSI: normalize -80 to -20 dBm as 0% to 100%
            return min(1.0, max(0.0, (value + 80) / 60))
        elif metric == "temp":
            # Temperature: normalize 30°C to 80°C as 0% to 100%
            return min(1.0, max(0.0, (value - 30) / 50))
        else:
            # CPU, MEM, DISK: direct percentage
            return min(1.0, value / 100.0)

    def _draw_arc(
        self,
        draw: ImageDraw.ImageDraw,
        cx: int,
        cy: int,
        radius: int,
        width: int,
        start: int,
        end: int,
        color: Tuple[int, int, int],
    ) -> None:
        """Draw an arc using PIL."""
        bbox = [cx - radius, cy - radius, cx + radius, cy + radius]
        draw.arc(bbox, start, end, fill=color, width=width)

    def _draw_connection_badge(
        self, draw: ImageDraw.ImageDraw, ctx: RenderContext
    ) -> None:
        """Draw connection status badge at top (OTG/WiFi/SIM)."""
        y_pos = 30
        if ctx.connection_state == "connected":
            text, color = "● OTG", STATUS_OK
        elif ctx.connection_state in ("stale", "degraded"):
            text, color = "● OFFLINE", STATUS_WARN
        else:
            text, color = "○ DISCONNECTED", STATUS_OFFLINE
        self.draw_text_centered(draw, text, y_pos, "small", color)

    def _draw_center(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw central information: time, date, hostname, uptime."""
        cy = self.height // 2

        # Time in HH:MM:SS format (updated every second)
        time_str = time.strftime("%H:%M:%S")
        self.draw_text_centered(draw, time_str, cy - 40, "time", TEXT_COLOR)

        # Hostname or fallback
        hostname = ctx.hostname or "secubox"
        self.draw_text_centered(draw, hostname, cy + 20, "medium", TEXT_MUTED)

        # Uptime in human-readable format
        uptime_str = f"up {self._format_uptime(ctx.uptime_seconds)}"
        self.draw_text_centered(draw, uptime_str, cy + 45, "small", TEXT_MUTED)

    def _draw_status(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw overall system status indicator."""
        metrics = ctx.metrics
        cpu = metrics.get("cpu", 0)
        mem = metrics.get("mem", 0)

        # Determine status level
        if cpu > 85 or mem > 90:
            text, color = "▲ CRITICAL", (255, 0, 80)
        elif cpu > 70 or mem > 75:
            text, color = "▲ WARNING", STATUS_WARN
        else:
            text, color = "● NOMINAL", STATUS_OK

        self.draw_text_centered(draw, text, self.height - 50, "medium", color)

    def _format_uptime(self, seconds: int) -> str:
        """Format uptime in human-readable format (s, m, h, d)."""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m"
        elif seconds < 86400:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h{minutes:02d}m"
        else:
            days = seconds // 86400
            hours = (seconds % 86400) // 3600
            return f"{days}d{hours}h"
