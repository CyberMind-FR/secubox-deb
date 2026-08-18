# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote - Display Renderers
Mode-specific renderers for different display states.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import logging
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# Display constants
DISPLAY_WIDTH = 480
DISPLAY_HEIGHT = 480
CENTER_X = 240
CENTER_Y = 240

# Color palette (SecuBox cyberpunk theme)
COLORS = {
    'background': (5, 5, 12, 255),      # Near black
    'gold': (201, 168, 76, 255),         # Gold hermetic
    'cyan': (0, 212, 255, 255),          # Cyber cyan
    'green': (0, 255, 65, 255),          # Matrix green
    'red': (230, 57, 70, 255),           # Cinnabar
    'purple': (110, 64, 201, 255),       # Void purple
    'text': (232, 230, 217, 255),        # Primary text
    'muted': (107, 107, 122, 255),       # Muted text
}


@dataclass
class RenderContext:
    """Context passed to renderers with current state."""
    mode: str = "dashboard"
    connection_state: str = "disconnected"
    metrics: Dict[str, Any] = field(default_factory=dict)
    hostname: str = "eye-remote"
    uptime_seconds: int = 0
    secubox_name: str = ""
    devices: List[Dict[str, Any]] = field(default_factory=list)
    alert_level: str = "nominal"
    flash_message: str = ""


class BaseRenderer:
    """
    Base class for all display renderers.
    Uses PIL for framebuffer rendering.
    """

    def __init__(self):
        self._image = None
        self._draw = None
        self._fonts = {}
        self._init_display()

    def _init_display(self) -> None:
        """Initialize PIL image and drawing context."""
        try:
            from PIL import Image, ImageDraw, ImageFont
            self._image = Image.new('RGBA', (DISPLAY_WIDTH, DISPLAY_HEIGHT), COLORS['background'])
            self._draw = ImageDraw.Draw(self._image)
            self._load_fonts()
        except ImportError:
            log.warning("PIL not available - display rendering disabled")

    def _load_fonts(self) -> None:
        """Load fonts for rendering."""
        try:
            from PIL import ImageFont
            # Try to load system fonts
            font_paths = [
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
                "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            ]
            for path in font_paths:
                if Path(path).exists():
                    self._fonts['small'] = ImageFont.truetype(path, 16)
                    self._fonts['medium'] = ImageFont.truetype(path, 24)
                    self._fonts['large'] = ImageFont.truetype(path, 36)
                    self._fonts['xlarge'] = ImageFont.truetype(path, 48)
                    return
            # Fallback to default
            self._fonts['small'] = ImageFont.load_default()
            self._fonts['medium'] = self._fonts['small']
            self._fonts['large'] = self._fonts['small']
            self._fonts['xlarge'] = self._fonts['small']
        except Exception as e:
            log.debug(f"Font loading error: {e}")

    def clear(self) -> None:
        """Clear the display to background color."""
        if self._draw:
            self._draw.rectangle([0, 0, DISPLAY_WIDTH, DISPLAY_HEIGHT], fill=COLORS['background'])

    def render(self, ctx: RenderContext) -> None:
        """Render the display. Override in subclasses."""
        self.clear()

    def write_to_framebuffer(self, path: str = "/dev/fb0") -> bool:
        """Write image to framebuffer."""
        if not self._image:
            return False
        try:
            with open(path, 'wb') as fb:
                fb.write(self._image.tobytes('raw', 'BGRA'))
            return True
        except Exception as e:
            log.error(f"Framebuffer write error: {e}")
            return False


class DashboardRenderer(BaseRenderer):
    """
    Main dashboard renderer showing SecuBox metrics.
    Displays 3D cube with rainbow metric rings.
    """

    def __init__(self):
        super().__init__()
        self._cube_angle = 0.0
        self._last_render = 0.0

    def render(self, ctx: RenderContext) -> None:
        """Render dashboard with metrics."""
        self.clear()
        if not self._draw:
            return

        now = time.time()
        dt = now - self._last_render if self._last_render > 0 else 0.016
        self._last_render = now
        self._cube_angle += dt * 30  # 30 degrees per second

        # Draw metric rings
        self._draw_metric_rings(ctx.metrics)

        # Draw center 3D cube
        self._draw_cube()

        # Draw hostname and connection status
        self._draw_info(ctx)

    def _draw_metric_rings(self, metrics: dict) -> None:
        """Draw rainbow metric rings around the display."""
        if not self._draw:
            return

        ring_data = [
            ('cpu_percent', COLORS['red'], 220),
            ('mem_percent', COLORS['gold'], 205),
            ('disk_percent', COLORS['purple'], 190),
            ('load_avg_1', COLORS['cyan'], 175),
            ('cpu_temp', COLORS['green'], 160),
        ]

        for metric_key, color, radius in ring_data:
            value = metrics.get(metric_key, 0)
            if metric_key == 'load_avg_1':
                value = min(100, value * 25)  # Scale load average
            elif metric_key == 'cpu_temp':
                value = min(100, max(0, (value - 30) * 2))  # Scale temp 30-80

            # Draw ring arc based on value
            arc_angle = int(value * 3.6)  # 0-100 -> 0-360
            if arc_angle > 0:
                bbox = [
                    CENTER_X - radius, CENTER_Y - radius,
                    CENTER_X + radius, CENTER_Y + radius
                ]
                self._draw.arc(bbox, -90, -90 + arc_angle, fill=color, width=8)

    def _draw_cube(self) -> None:
        """Draw rotating 3D cube in center."""
        if not self._draw:
            return

        # Simple cube projection
        angle_rad = math.radians(self._cube_angle)
        size = 40
        cos_a = math.cos(angle_rad)
        sin_a = math.sin(angle_rad)

        # Cube vertices
        vertices = [
            (-1, -1, -1), (1, -1, -1), (1, 1, -1), (-1, 1, -1),
            (-1, -1, 1), (1, -1, 1), (1, 1, 1), (-1, 1, 1)
        ]

        # Project and rotate
        projected = []
        for x, y, z in vertices:
            # Rotate around Y axis
            rx = x * cos_a - z * sin_a
            rz = x * sin_a + z * cos_a
            # Simple perspective
            scale = 1 / (3 - rz)
            px = CENTER_X + rx * size * scale
            py = CENTER_Y + y * size * scale
            projected.append((px, py))

        # Draw edges
        edges = [
            (0, 1), (1, 2), (2, 3), (3, 0),  # Back face
            (4, 5), (5, 6), (6, 7), (7, 4),  # Front face
            (0, 4), (1, 5), (2, 6), (3, 7)   # Connecting edges
        ]
        for i, j in edges:
            self._draw.line([projected[i], projected[j]], fill=COLORS['cyan'], width=2)

    def _draw_info(self, ctx: RenderContext) -> None:
        """Draw hostname and status info."""
        if not self._draw:
            return

        # Hostname at top
        font = self._fonts.get('medium')
        self._draw.text((CENTER_X, 30), ctx.hostname, fill=COLORS['text'], font=font, anchor='mm')

        # Connection status at bottom
        status_color = COLORS['green'] if ctx.connection_state == 'connected' else COLORS['red']
        self._draw.text((CENTER_X, 450), ctx.connection_state.upper(), fill=status_color, font=font, anchor='mm')

        # SecuBox name
        if ctx.secubox_name:
            self._draw.text((CENTER_X, 60), ctx.secubox_name, fill=COLORS['muted'], font=self._fonts.get('small'), anchor='mm')


class LocalRenderer(BaseRenderer):
    """
    Local mode renderer showing Pi Zero W system info.
    Used when disconnected from SecuBox.
    """

    def render(self, ctx: RenderContext) -> None:
        """Render local system info."""
        self.clear()
        if not self._draw:
            return

        # Title
        self._draw.text((CENTER_X, 50), "LOCAL MODE", fill=COLORS['gold'],
                       font=self._fonts.get('large'), anchor='mm')

        # Local metrics
        y = 150
        local_info = [
            ("Hostname", ctx.hostname),
            ("Uptime", self._format_uptime(ctx.uptime_seconds)),
            ("Status", ctx.connection_state),
        ]

        for label, value in local_info:
            self._draw.text((100, y), f"{label}:", fill=COLORS['muted'],
                           font=self._fonts.get('medium'), anchor='lm')
            self._draw.text((380, y), str(value), fill=COLORS['text'],
                           font=self._fonts.get('medium'), anchor='rm')
            y += 40

        # Waiting message
        self._draw.text((CENTER_X, 400), "Waiting for SecuBox...",
                       fill=COLORS['cyan'], font=self._fonts.get('medium'), anchor='mm')

    def _format_uptime(self, seconds: int) -> str:
        """Format uptime in human-readable form."""
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"


class FlashRenderer(BaseRenderer):
    """
    Flash mode renderer for temporary messages.
    Used for alerts, notifications, and splash screens.
    """

    def render(self, ctx: RenderContext) -> None:
        """Render flash message."""
        self.clear()
        if not self._draw:
            return

        message = ctx.flash_message or "SECUBOX"

        # Large centered text
        self._draw.text((CENTER_X, CENTER_Y), message, fill=COLORS['gold'],
                       font=self._fonts.get('xlarge'), anchor='mm')

        # Pulsing circle around text
        pulse = (math.sin(time.time() * 2) + 1) / 2
        radius = 100 + int(pulse * 20)
        self._draw.ellipse(
            [CENTER_X - radius, CENTER_Y - radius, CENTER_X + radius, CENTER_Y + radius],
            outline=COLORS['cyan'],
            width=3
        )


class GatewayRenderer(BaseRenderer):
    """
    Gateway mode renderer for fleet overview.
    Shows status of multiple SecuBox devices.
    """

    def render(self, ctx: RenderContext) -> None:
        """Render fleet overview."""
        self.clear()
        if not self._draw:
            return

        # Title
        self._draw.text((CENTER_X, 40), "GATEWAY MODE", fill=COLORS['gold'],
                       font=self._fonts.get('large'), anchor='mm')

        # Device count
        device_count = len(ctx.devices)
        online_count = sum(1 for d in ctx.devices if d.get('online', False))
        self._draw.text((CENTER_X, 80), f"{online_count}/{device_count} Online",
                       fill=COLORS['green'] if online_count == device_count else COLORS['gold'],
                       font=self._fonts.get('medium'), anchor='mm')

        # Device list
        y = 140
        max_visible = 6
        for i, device in enumerate(ctx.devices[:max_visible]):
            color = COLORS['green'] if device.get('online') else COLORS['red']
            status = "●" if device.get('online') else "○"
            name = device.get('name', f'Device {i+1}')
            self._draw.text((80, y), status, fill=color, font=self._fonts.get('medium'), anchor='lm')
            self._draw.text((110, y), name, fill=COLORS['text'], font=self._fonts.get('medium'), anchor='lm')
            y += 45

        if device_count > max_visible:
            self._draw.text((CENTER_X, 420), f"+{device_count - max_visible} more",
                           fill=COLORS['muted'], font=self._fonts.get('small'), anchor='mm')
