"""
SecuBox Eye Remote — Flash Mode Display
Renders USB storage status and flash progress for ESPRESSObin recovery.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

from .renderer import (
    DisplayRenderer, RenderContext,
    TEXT_COLOR, TEXT_MUTED, STATUS_OK, STATUS_WARN,
)

STORAGE_PATH = Path("/var/lib/secubox/eye-remote/storage.img")


class FlashRenderer(DisplayRenderer):
    """Renders Flash mode for ESPRESSObin recovery."""

    def render(self, ctx: RenderContext) -> Image.Image:
        """
        Render Flash mode display.

        Args:
            ctx: Render context with flash_progress and other state

        Returns:
            PIL Image with rendered Flash mode display
        """
        self.create_frame()
        draw = self.get_draw()

        self._draw_mode_badge(draw)
        self._draw_storage_icon(draw)
        self._draw_storage_info(draw)
        if ctx.flash_progress > 0:
            self._draw_progress_bar(draw, ctx.flash_progress)
        self._draw_uboot_status(draw)
        self.draw_circle_mask(draw)

        return self._frame

    def _draw_mode_badge(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw Flash Mode badge at top."""
        self.draw_text_centered(draw, "⚡ FLASH MODE", 35, 'medium', (255, 136, 0))

    def _draw_storage_icon(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw USB storage icon."""
        cx, cy = self.center
        font = self.get_font('xlarge')
        draw.text((cx - 20, cy - 80), "💾", font=font, fill=TEXT_COLOR)

    def _draw_storage_info(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw USB storage information and size."""
        cy = self.center[1]
        self.draw_text_centered(draw, "USB STORAGE", cy - 20, 'large', TEXT_COLOR)

        if STORAGE_PATH.exists():
            size_gb = STORAGE_PATH.stat().st_size / (1024 ** 3)
            size_text = f"{size_gb:.1f} GB • FAT32"
        else:
            size_text = "Not mounted"
        self.draw_text_centered(draw, size_text, cy + 15, 'medium', TEXT_MUTED)

    def _draw_progress_bar(self, draw: ImageDraw.ImageDraw, progress: float) -> None:
        """
        Draw progress bar for flash operation.

        Args:
            draw: ImageDraw object
            progress: Progress as float 0.0-1.0
        """
        cx, cy = self.center
        bar_width, bar_height = 200, 16
        bar_x = cx - bar_width // 2
        bar_y = cy + 50

        # Draw background
        draw.rectangle(
            [bar_x, bar_y, bar_x + bar_width, bar_y + bar_height],
            fill=(40, 40, 50),
            outline=(80, 80, 90),
        )

        # Draw filled portion
        fill_width = int(bar_width * progress)
        if fill_width > 0:
            draw.rectangle(
                [bar_x + 1, bar_y + 1, bar_x + fill_width - 1, bar_y + bar_height - 1],
                fill=(255, 136, 0),
            )

        # Draw percentage
        self.draw_text_centered(
            draw,
            f"{int(progress * 100)}%",
            bar_y + bar_height + 10,
            'medium',
            TEXT_MUTED,
        )

        # Draw status message
        status = "Flash complete!" if progress >= 1.0 else "Flashing image..."
        self.draw_text_centered(draw, status, bar_y + bar_height + 35, 'small', TEXT_MUTED)

    def _draw_uboot_status(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw U-Boot ready status at bottom."""
        self.draw_text_centered(
            draw, "U-Boot ready", self.height - 50, 'medium', STATUS_OK
        )
