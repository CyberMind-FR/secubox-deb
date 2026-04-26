"""
SecuBox Eye Remote — Gateway Mode Display
Renders multi-SecuBox fleet management view.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

from PIL import Image, ImageDraw

from .renderer import (
    DisplayRenderer, RenderContext,
    TEXT_COLOR, TEXT_MUTED, STATUS_OK, STATUS_WARN,
)


class GatewayRenderer(DisplayRenderer):
    """Renders Gateway mode for multi-SecuBox fleet."""

    def render(self, ctx: RenderContext) -> Image.Image:
        """Render gateway mode display with fleet view."""
        self.create_frame()
        draw = self.get_draw()

        self._draw_mode_badge(draw)
        self._draw_fleet_icon(draw)
        self._draw_device_list(draw, ctx)
        self._draw_fleet_summary(draw, ctx)
        self._draw_alerts(draw, ctx)
        self.draw_circle_mask(draw)

        return self._frame

    def _draw_mode_badge(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw 'GATEWAY MODE' header badge."""
        self.draw_text_centered(draw, "🌐 GATEWAY MODE", 35, 'medium', (160, 0, 255))

    def _draw_fleet_icon(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw fleet icon (network/server cluster)."""
        cx, cy = self.center
        font = self.get_font('xlarge')
        draw.text((cx - 20, cy - 100), "🖥️", font=font, fill=TEXT_COLOR)

    def _draw_device_list(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw list of devices in fleet."""
        cx, cy = self.center
        devices = ctx.devices or []
        y_start, y_spacing = cy - 40, 28

        for i, device in enumerate(devices[:5]):
            y = y_start + i * y_spacing
            name = device.get('name', f'device-{i}')
            online = device.get('online', False)

            # Status indicator and device name
            dot = "●" if online else "○"
            dot_color = STATUS_OK if online else (100, 100, 120)
            text = f"{dot} {name}" + ("" if online else " (down)")

            font = self.get_font('medium')
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            x = cx - text_width // 2
            draw.text((x, y), text, font=font, fill=dot_color if not online else TEXT_COLOR)

    def _draw_fleet_summary(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw fleet summary (online count)."""
        devices = ctx.devices or []
        online = sum(1 for d in devices if d.get('online', False))
        summary_text = f"Fleet: {online}/{len(devices)} online"
        self.draw_text_centered(draw, summary_text, self.height - 80, 'medium', TEXT_MUTED)

    def _draw_alerts(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw alert status."""
        if ctx.alert_count > 0:
            text = f"▲ {ctx.alert_count} alert{'s' if ctx.alert_count > 1 else ''}"
            color = STATUS_WARN
        else:
            text, color = "● No alerts", STATUS_OK
        self.draw_text_centered(draw, text, self.height - 50, 'medium', color)
