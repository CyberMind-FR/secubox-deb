"""
SecuBox Eye Remote — Local Mode Display
Renders Pi Zero self-monitoring with icon grid.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

from PIL import Image, ImageDraw

from .renderer import (
    DisplayRenderer,
    RenderContext,
    TEXT_COLOR,
    TEXT_MUTED,
    STATUS_OK,
)

ICONS = [
    {"name": "Network", "symbol": "📡", "metric": "network"},
    {"name": "Power", "symbol": "🔋", "metric": "power"},
    {"name": "Storage", "symbol": "💾", "metric": "disk"},
    {"name": "WiFi", "symbol": "📶", "metric": "wifi"},
    {"name": "Settings", "symbol": "⚙️", "metric": None},
    {"name": "Refresh", "symbol": "🔄", "metric": None},
]


class LocalRenderer(DisplayRenderer):
    """Renders Local mode with Pi Zero self-monitoring."""

    def render(self, ctx: RenderContext) -> Image.Image:
        """
        Render Local mode display with icon grid.

        Args:
            ctx: RenderContext with metrics and display state

        Returns:
            PIL Image of the rendered display
        """
        self.create_frame()
        draw = self.get_draw()

        self._draw_mode_badge(draw)
        self._draw_icon_grid(draw, ctx)
        self._draw_device_info(draw, ctx)
        self._draw_web_hint(draw)
        self.draw_circle_mask(draw)

        return self._frame

    def _draw_mode_badge(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw the LOCAL MODE badge at top."""
        self.draw_text_centered(
            draw, "● LOCAL MODE", 35, "medium", (0, 170, 255)
        )

    def _draw_icon_grid(
        self, draw: ImageDraw.ImageDraw, ctx: RenderContext
    ) -> None:
        """
        Draw a 3×2 icon grid in the middle of the display.

        Args:
            draw: ImageDraw object
            ctx: RenderContext with metrics
        """
        cx, cy = self.center
        cols, rows = 3, 2
        spacing_x, spacing_y = 90, 80
        start_x = cx - spacing_x
        start_y = cy - 60

        for i, icon_data in enumerate(ICONS):
            col = i % cols
            row = i // cols
            x = start_x + col * spacing_x
            y = start_y + row * spacing_y

            font = self.get_font("xlarge")
            draw.text((x - 15, y - 20), icon_data["symbol"], font=font, fill=TEXT_COLOR)

    def _draw_device_info(
        self, draw: ImageDraw.ImageDraw, ctx: RenderContext
    ) -> None:
        """
        Draw device information (hostname and uptime).

        Args:
            draw: ImageDraw object
            ctx: RenderContext with uptime and hostname
        """
        cy = self.center[1]
        uptime = self._format_uptime(ctx.uptime_seconds)
        info_text = f"Pi Zero W • up {uptime}"
        self.draw_text_centered(draw, info_text, cy + 100, "medium", TEXT_MUTED)

    def _draw_web_hint(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw web access hint at the bottom."""
        hint_text = "Web: eye-remote.local:8080"
        self.draw_text_centered(
            draw, hint_text, self.height - 50, "small", (100, 150, 200)
        )

    @staticmethod
    def _format_uptime(seconds: int) -> str:
        """
        Format uptime seconds into human-readable string.

        Args:
            seconds: Uptime in seconds

        Returns:
            Formatted uptime string (e.g., "1h23m", "2d5h")
        """
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
