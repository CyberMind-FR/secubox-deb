#!/usr/bin/env python3
"""
SecuBox Eye Remote - Gadget Status Display

Renders USB gadget status overlay on the dashboard.
Shows mode, connection state, and transfer activity.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

from __future__ import annotations

import math
import time
from typing import Optional, Any
from PIL import ImageDraw

# Import gadget API
HAS_GADGET_API = False
GadgetController: Any = None
GadgetStatus: Any = None

def _dummy_get_controller() -> None:
    return None

def _dummy_get_gadget_mode_info() -> dict:
    return {}

get_controller = _dummy_get_controller
get_gadget_mode_info = _dummy_get_gadget_mode_info

try:
    from ..api.gadget import (
        GadgetController, GadgetStatus, get_controller, get_gadget_mode_info
    )
    HAS_GADGET_API = True
except ImportError:
    pass


WIDTH = HEIGHT = 480
CENTER = 240

# Mode colors matching the gadget API
MODE_COLORS = {
    'none': (80, 80, 80),
    'ecm': (0, 180, 255),
    'acm': (255, 200, 0),
    'mass_storage': (0, 255, 120),
    'composite': (200, 100, 255),
}

# Connection state colors
STATE_COLORS = {
    'disconnected': (255, 80, 80),
    'connected': (0, 255, 100),
    'transferring': (0, 200, 255),
}

# Mode icons (fallback text if no font)
MODE_ICONS = {
    'none': '○',
    'ecm': '◉',
    'acm': '▣',
    'mass_storage': '▤',
    'composite': '◈',
}


class GadgetStatusRenderer:
    """Renders gadget status on display."""

    def __init__(self):
        self._controller: Optional[Any] = None
        self._status: Optional[Any] = None
        self._last_update = 0
        self._update_interval = 0.5  # Update every 500ms
        self._pulse_phase = 0
        self._transfer_anim = 0

        if HAS_GADGET_API and callable(get_controller):
            self._controller = get_controller()  # type: ignore

    def update(self):
        """Update gadget status."""
        now = time.time()
        if now - self._last_update < self._update_interval:
            return

        self._last_update = now
        self._pulse_phase += 0.15
        self._transfer_anim += 0.2

        if self._controller:
            self._status = self._controller.get_status()

    def render_status_bar(self, draw: ImageDraw.ImageDraw, y: int = 455):
        """Render gadget status bar at bottom of screen."""
        self.update()

        if not self._status:
            return

        mode = self._status.mode.value
        conn = self._status.connection.value
        mode_color = MODE_COLORS.get(mode, (80, 80, 80))
        state_color = STATE_COLORS.get(conn, (80, 80, 80))

        # Background bar
        draw.rectangle([10, y - 5, WIDTH - 10, y + 20], fill=(15, 15, 20))

        # Mode indicator (left side)
        mode_info = get_gadget_mode_info() if HAS_GADGET_API and callable(get_gadget_mode_info) else {}  # type: ignore[misc]
        mode_name = mode_info.get('name', mode.upper())

        # Pulsing mode dot
        pulse = (math.sin(self._pulse_phase) + 1) / 2
        dot_size = int(4 + pulse * 2)
        draw.ellipse([20 - dot_size, y + 5 - dot_size,
                     20 + dot_size, y + 5 + dot_size],
                    fill=mode_color)

        # Mode name
        draw.text((30, y - 2), mode_name[:8], fill=mode_color)

        # Connection state (center)
        state_x = CENTER - 30
        state_text = conn.upper()[:6]
        draw.text((state_x, y - 2), state_text, fill=state_color)

        # Transfer rates (right side) - only when connected
        if conn in ('connected', 'transferring'):
            rx_rate = self._status.rx_rate_kbps
            tx_rate = self._status.tx_rate_kbps

            # RX arrow and rate
            rx_x = WIDTH - 120
            rx_color = (0, 255, 120) if rx_rate > 0 else (60, 60, 60)
            draw.text((rx_x, y - 2), f"↓{rx_rate:.0f}", fill=rx_color)

            # TX arrow and rate
            tx_x = WIDTH - 60
            tx_color = (255, 120, 0) if tx_rate > 0 else (60, 60, 60)
            draw.text((tx_x, y - 2), f"↑{tx_rate:.0f}", fill=tx_color)

            # Transfer animation
            if conn == 'transferring':
                anim_x = int(WIDTH - 140 + (self._transfer_anim % 1) * 20)
                draw.ellipse([anim_x - 2, y + 3, anim_x + 2, y + 7],
                            fill=(0, 255, 255))

    def render_full_status(self, draw: ImageDraw.ImageDraw):
        """Render detailed gadget status overlay."""
        self.update()

        if not self._status:
            return

        # Semi-transparent background
        # (PIL doesn't support alpha, so use dark color)
        draw.rectangle([40, 80, WIDTH - 40, HEIGHT - 80],
                      fill=(10, 10, 15), outline=(40, 40, 50))

        mode = self._status.mode.value
        conn = self._status.connection.value
        mode_color = MODE_COLORS.get(mode, (80, 80, 80))
        state_color = STATE_COLORS.get(conn, (80, 80, 80))

        y = 100

        # Title
        draw.text((CENTER - 60, y), "USB GADGET", fill=(200, 200, 210))
        y += 30

        # Mode section
        mode_info = get_gadget_mode_info() if HAS_GADGET_API and callable(get_gadget_mode_info) else {}  # type: ignore[misc]
        mode_name = mode_info.get('name', mode.upper())
        mode_desc = mode_info.get('description', '')

        draw.rectangle([60, y, WIDTH - 60, y + 50], outline=mode_color, width=2)
        draw.text((70, y + 5), f"Mode: {mode_name}", fill=mode_color)
        draw.text((70, y + 25), mode_desc[:30], fill=(120, 120, 130))
        y += 70

        # Connection section
        draw.text((70, y), "Connection:", fill=(150, 150, 160))
        draw.text((180, y), conn.upper(), fill=state_color)
        y += 25

        if self._status.host_ip:
            draw.text((70, y), f"Host IP: {self._status.host_ip}", fill=(150, 150, 160))
            y += 20

        draw.text((70, y), f"Device IP: {self._status.device_ip}", fill=(150, 150, 160))
        y += 30

        # ECM stats
        if mode in ('ecm', 'composite'):
            draw.text((70, y), "Network Stats:", fill=(0, 180, 255))
            y += 20

            rx_mb = self._status.ecm_rx_bytes / (1024 * 1024)
            tx_mb = self._status.ecm_tx_bytes / (1024 * 1024)
            draw.text((80, y), f"RX: {rx_mb:.2f} MB ({self._status.ecm_rx_packets} pkts)",
                     fill=(150, 150, 160))
            y += 18
            draw.text((80, y), f"TX: {tx_mb:.2f} MB ({self._status.ecm_tx_packets} pkts)",
                     fill=(150, 150, 160))
            y += 25

        # ACM stats
        if mode in ('acm', 'composite'):
            acm_status = "Active" if self._status.acm_active else "Idle"
            acm_color = (0, 255, 100) if self._status.acm_active else (100, 100, 100)
            draw.text((70, y), f"Serial: {acm_status}", fill=acm_color)
            draw.text((200, y), self._status.acm_device, fill=(100, 100, 110))
            y += 25

        # Mass storage stats
        if mode in ('mass_storage', 'composite'):
            if self._status.storage_mounted:
                draw.text((70, y), f"Storage: {self._status.storage_size_mb} MB",
                         fill=(0, 255, 120))
            else:
                draw.text((70, y), "Storage: Not mounted", fill=(100, 100, 100))
            y += 25

        # Transfer rates (live)
        if conn in ('connected', 'transferring'):
            y += 10
            draw.text((70, y), "Transfer Rate:", fill=(150, 150, 160))
            y += 20

            # RX rate bar
            rx_pct = min(100, self._status.rx_rate_kbps / 10)  # Scale to 1000 KB/s
            bar_width = int((WIDTH - 160) * rx_pct / 100)
            draw.rectangle([80, y, 80 + bar_width, y + 12], fill=(0, 255, 120))
            draw.rectangle([80, y, WIDTH - 80, y + 12], outline=(60, 60, 70))
            draw.text((WIDTH - 75, y - 2), f"{self._status.rx_rate_kbps:.1f}", fill=(0, 255, 120))
            y += 18

            # TX rate bar
            tx_pct = min(100, self._status.tx_rate_kbps / 10)
            bar_width = int((WIDTH - 160) * tx_pct / 100)
            draw.rectangle([80, y, 80 + bar_width, y + 12], fill=(255, 120, 0))
            draw.rectangle([80, y, WIDTH - 80, y + 12], outline=(60, 60, 70))
            draw.text((WIDTH - 75, y - 2), f"{self._status.tx_rate_kbps:.1f}", fill=(255, 120, 0))

    def render_compact_indicator(self, draw: ImageDraw.ImageDraw,
                                  x: int = 20, y: int = HEIGHT - 25):
        """Render compact gadget indicator (corner badge)."""
        self.update()

        if not self._status:
            return

        mode = self._status.mode.value
        conn = self._status.connection.value
        mode_color = MODE_COLORS.get(mode, (80, 80, 80))

        # Skip if no gadget active
        if mode == 'none':
            return

        # Small colored dot
        pulse = (math.sin(self._pulse_phase * 2) + 1) / 2
        size = int(4 + pulse * 2) if conn != 'disconnected' else 4

        # Different dot style based on connection
        if conn == 'transferring':
            # Animated ring for transfer
            draw.ellipse([x - size - 2, y - size - 2, x + size + 2, y + size + 2],
                        outline=(0, 255, 255), width=2)
        elif conn == 'connected':
            # Filled dot for connected
            draw.ellipse([x - size, y - size, x + size, y + size],
                        fill=mode_color)
        else:
            # Hollow dot for disconnected
            draw.ellipse([x - size, y - size, x + size, y + size],
                        outline=mode_color, width=1)

        # Mode letter
        mode_letter = mode[0].upper()
        draw.text((x + size + 4, y - 6), mode_letter, fill=mode_color)


# Singleton instance
_renderer: Optional[GadgetStatusRenderer] = None


def get_renderer() -> GadgetStatusRenderer:
    """Get singleton renderer instance."""
    global _renderer
    if _renderer is None:
        _renderer = GadgetStatusRenderer()
    return _renderer


def render_gadget_status_bar(draw: ImageDraw.ImageDraw, y: int = 455):
    """Convenience function to render status bar."""
    get_renderer().render_status_bar(draw, y)


def render_gadget_full_status(draw: ImageDraw.ImageDraw):
    """Convenience function to render full status."""
    get_renderer().render_full_status(draw)


def render_gadget_indicator(draw: ImageDraw.ImageDraw, x: int = 20, y: int = HEIGHT - 25):
    """Convenience function to render compact indicator."""
    get_renderer().render_compact_indicator(draw, x, y)
