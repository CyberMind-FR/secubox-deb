"""
SecuBox Eye Remote — Display Renderer Base
Base class for framebuffer rendering on HyperPixel 2.1 Round (480x480).

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple

from PIL import Image, ImageDraw, ImageFont

log = logging.getLogger(__name__)

# Display constants
WIDTH = 480
HEIGHT = 480
FB_DEV = '/dev/fb0'

# Colors (RGB)
BG_COLOR = (8, 8, 12)           # Deep space black
TEXT_COLOR = (240, 240, 250)    # Bright white
TEXT_MUTED = (130, 130, 150)    # Soft gray-blue
STATUS_OK = (0, 255, 65)        # Neon green
STATUS_WARN = (255, 100, 0)     # Neon orange
STATUS_ERROR = (255, 0, 80)     # Neon red
STATUS_OFFLINE = (100, 100, 120)  # Dim gray

# Module colors (Neon Rainbow)
MODULE_COLORS = {
    'AUTH': (255, 0, 100),    # Neon Magenta
    'WALL': (255, 100, 0),    # Neon Orange
    'BOOT': (220, 255, 0),    # Neon Yellow
    'MIND': (0, 255, 65),     # Matrix Green
    'ROOT': (0, 255, 255),    # Cyber Cyan
    'MESH': (185, 0, 255),    # Laser Purple
}


@dataclass
class RenderContext:
    """Context passed to render methods."""
    width: int = WIDTH
    height: int = HEIGHT
    mode: str = "local"
    connection_state: str = "disconnected"
    metrics: dict = field(default_factory=dict)
    hostname: str = "eye-remote"
    uptime_seconds: int = 0
    secubox_name: str = ""
    alert_count: int = 0
    flash_progress: float = 0.0
    devices: list = field(default_factory=list)


class DisplayRenderer:
    """Base display renderer for Eye Remote."""

    def __init__(self, width: int = WIDTH, height: int = HEIGHT):
        self.width = width
        self.height = height
        self.center = (width // 2, height // 2)
        self._fonts: dict[str, Any] = {}  # FreeTypeFont or ImageFont
        self._load_fonts()
        self._frame: Optional[Image.Image] = None
        self._fb_info: Optional[dict] = None

    def _load_fonts(self) -> None:
        font_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
            "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
        ]
        sizes = {'small': 12, 'medium': 16, 'large': 24, 'xlarge': 32, 'time': 48}
        for name, size in sizes.items():
            for path in font_paths:
                if os.path.exists(path):
                    try:
                        self._fonts[name] = ImageFont.truetype(path, size)
                        break
                    except Exception:
                        pass
            if name not in self._fonts:
                self._fonts[name] = ImageFont.load_default()

    def get_font(self, name: str = 'medium') -> Any:
        """Get a named font, returns FreeTypeFont or default ImageFont."""
        return self._fonts.get(name) or self._fonts.get('medium')

    def create_frame(self) -> Image.Image:
        self._frame = Image.new('RGB', (self.width, self.height), BG_COLOR)
        return self._frame

    def get_draw(self) -> ImageDraw.ImageDraw:
        """Get ImageDraw for current frame, creating frame if needed."""
        if self._frame is None:
            self.create_frame()
        assert self._frame is not None  # For type checker
        return ImageDraw.Draw(self._frame)

    def draw_text_centered(
        self,
        draw: ImageDraw.ImageDraw,
        text: str,
        y: int,
        font_name: str = 'medium',
        color: Tuple[int, int, int] = TEXT_COLOR,
    ) -> None:
        font = self.get_font(font_name)
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        x = (self.width - text_width) // 2
        draw.text((x, y), text, font=font, fill=color)

    def draw_circle_mask(self, _draw: ImageDraw.ImageDraw) -> None:
        mask = Image.new('L', (self.width, self.height), 0)
        mask_draw = ImageDraw.Draw(mask)
        mask_draw.ellipse([0, 0, self.width - 1, self.height - 1], fill=255)
        if self._frame:
            bg = Image.new('RGB', (self.width, self.height), (0, 0, 0))
            self._frame = Image.composite(self._frame, bg, mask)

    def write_to_framebuffer(self) -> bool:
        """Write frame to framebuffer with auto-format detection."""
        if self._frame is None:
            return False
        try:
            if self._fb_info is None:
                self._fb_info = self._get_fb_info()

            bpp = self._fb_info.get('bpp', 32)

            if bpp == 32:
                # 32-bit BGRA (HyperPixel DPI displays)
                raw = self._convert_to_bgra32(self._frame)
            elif bpp == 24:
                # 24-bit BGR
                raw = self._frame.convert('RGB').tobytes('raw', 'BGR')
            elif bpp == 16:
                # 16-bit RGB565
                raw = self._convert_to_rgb565(self._frame)
            else:
                log.warning(f"Unknown bpp {bpp}, trying BGRA32")
                raw = self._convert_to_bgra32(self._frame)

            with open(FB_DEV, 'wb') as fb:
                fb.write(raw)
            return True
        except Exception as e:
            log.error(f"Failed to write framebuffer: {e}")
            return False

    def _get_fb_info(self) -> dict:
        """Get framebuffer info (resolution, bits per pixel)."""
        import fcntl
        FBIOGET_VSCREENINFO = 0x4600
        try:
            with open(FB_DEV, 'rb') as fb:
                info = fcntl.ioctl(fb.fileno(), FBIOGET_VSCREENINFO, b'\x00' * 160)
                xres, yres = struct.unpack('II', info[:8])
                bits_per_pixel = struct.unpack('I', info[24:28])[0]
                log.info(f"Framebuffer: {xres}x{yres} @ {bits_per_pixel}bpp")
                return {'xres': xres, 'yres': yres, 'bpp': bits_per_pixel}
        except Exception:
            # Default to 32bpp for HyperPixel Round
            return {'xres': self.width, 'yres': self.height, 'bpp': 32}

    def _convert_to_bgra32(self, img: Image.Image) -> bytes:
        """Convert PIL Image to BGRA32 bytes for 32-bit framebuffer."""
        rgba = img.convert('RGBA')
        return rgba.tobytes('raw', 'BGRA')

    def _convert_to_rgb565(self, img: Image.Image) -> bytes:
        """Convert PIL Image to RGB565 bytes for 16-bit framebuffer."""
        rgb = img.convert('RGB')
        pixels = list(rgb.getdata())  # type: ignore[arg-type]
        result = bytearray(len(pixels) * 2)
        for i, (r, g, b) in enumerate(pixels):
            rgb565 = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            result[i * 2] = rgb565 & 0xFF
            result[i * 2 + 1] = (rgb565 >> 8) & 0xFF
        return bytes(result)
