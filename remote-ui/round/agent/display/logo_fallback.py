#!/usr/bin/env python3
"""
SecuBox Eye Remote - Logo Fallback Display

Endless animated logo display - the ultimate fallback when all dashboards stop.
Shows phoenix logo with subtle breathing animation.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import time
import math
from pathlib import Path
from typing import Optional
from PIL import Image, ImageDraw, ImageFilter

WIDTH = HEIGHT = 480
CENTER = 240

# Logo paths to try
LOGO_PATHS = [
    Path("/tmp/assets/splash/phoenix_logo.png"),
    Path("/etc/secubox/eye-remote/assets/phoenix_logo.png"),
    Path(__file__).parent.parent.parent / "assets" / "splash" / "phoenix_logo.png",
]


class LogoFallback:
    """Endless animated logo display."""

    def __init__(self):
        self._start_time = time.time()
        self._logo: Optional[Image.Image] = None
        self._load_logo()

    def _load_logo(self):
        """Load logo from available paths."""
        for path in LOGO_PATHS:
            try:
                if path.exists():
                    self._logo = Image.open(path).convert('RGBA')
                    # Resize to fit nicely
                    self._logo = self._logo.resize((280, 280), Image.Resampling.LANCZOS)
                    print(f"Logo loaded from {path}")
                    return
            except Exception as e:
                print(f"Failed to load {path}: {e}")
        print("No logo found, using fallback symbol")

    def render(self) -> Image.Image:
        """Render logo with breathing animation."""
        elapsed = time.time() - self._start_time

        # Slow breathing pulse (4 second cycle)
        breath = (math.sin(elapsed * 0.5) + 1) / 2  # 0-1

        img = Image.new('RGBA', (WIDTH, HEIGHT), (5, 5, 12, 255))
        draw = ImageDraw.Draw(img)

        # Subtle background glow rings
        self._draw_ambient_glow(draw, elapsed, breath)

        if self._logo:
            self._draw_logo_animated(img, elapsed, breath)
        else:
            self._draw_fallback_symbol(draw, elapsed, breath)

        # Branding at bottom
        self._draw_branding(draw, breath)

        return img

    def _draw_ambient_glow(self, draw, elapsed, breath):
        """Draw subtle ambient glow rings."""
        # Very subtle rotating rings
        for i in range(3):
            r = 180 + i * 25
            alpha = int(15 + breath * 10)
            # Warm colors
            colors = [(255, 80, 30), (255, 120, 40), (255, 60, 20)]
            color = (*colors[i], alpha)

            # Slow rotation
            for seg in range(6):
                angle = elapsed * 0.1 + seg * (math.pi / 3) + i * 0.2
                x1 = CENTER + (r - 5) * math.cos(angle)
                y1 = CENTER + (r - 5) * math.sin(angle)
                x2 = CENTER + (r + 5) * math.cos(angle)
                y2 = CENTER + (r + 5) * math.sin(angle)
                draw.line([(x1, y1), (x2, y2)], fill=color, width=2)

    def _draw_logo_animated(self, img: Image.Image, elapsed: float, breath: float):
        """Draw logo with subtle animation."""
        if self._logo is None:
            return

        # Subtle scale breathing
        scale = 1.0 + breath * 0.03
        new_size = int(280 * scale)

        # Very subtle rotation
        rotation = math.sin(elapsed * 0.2) * 2  # ±2 degrees

        logo = self._logo.copy()
        if abs(rotation) > 0.1:
            logo = logo.rotate(rotation, Image.Resampling.BILINEAR, expand=False)

        logo = logo.resize((new_size, new_size), Image.Resampling.LANCZOS)

        # Subtle glow behind logo
        glow_intensity = int(breath * 20)
        if glow_intensity > 5:
            glow = logo.filter(ImageFilter.GaussianBlur(radius=15))
            glow_layer = Image.new('RGBA', (WIDTH, HEIGHT), (0, 0, 0, 0))
            glow_pos = (CENTER - new_size // 2, CENTER - new_size // 2 - 15)
            glow_layer.paste(glow, glow_pos, glow)
            img.alpha_composite(glow_layer)

        # Paste logo
        pos = (CENTER - new_size // 2, CENTER - new_size // 2 - 15)
        img.paste(logo, pos, logo)

    def _draw_fallback_symbol(self, draw, elapsed, breath):
        """Draw fallback phoenix-like symbol if no logo."""
        # Central fire orb
        r = 60 + breath * 8

        colors = [
            (255, 100, 30, int(200 + breath * 55)),
            (255, 60, 10, int(170 + breath * 55)),
            (255, 30, 0, int(140 + breath * 55)),
        ]

        for i, color in enumerate(colors):
            size = r - i * 18
            draw.ellipse([
                CENTER - size, CENTER - size - 15,
                CENTER + size, CENTER + size - 15
            ], fill=color)

        # Flame tips
        for i in range(5):
            angle = -math.pi/2 + (i - 2) * 0.3 + math.sin(elapsed * 2 + i) * 0.1
            length = 80 + math.sin(elapsed * 3 + i * 0.7) * 15
            x = CENTER + length * math.cos(angle)
            y = CENTER - 15 + length * math.sin(angle)
            alpha = int(150 + breath * 100)
            draw.line([(CENTER, CENTER - 15), (x, y)],
                     fill=(255, 150, 50, alpha), width=4)

        # Inner dark core
        draw.ellipse([CENTER - 20, CENTER - 35, CENTER + 20, CENTER + 5],
                    fill=(10, 10, 20))

    def _draw_branding(self, draw, breath):
        """Draw SecuBox branding."""
        alpha = int(120 + breath * 40)

        # SecuBox text
        draw.text((CENTER - 35, 420), "SECUBOX", fill=(150, 140, 120, alpha))
        draw.text((CENTER - 40, 442), "EYE REMOTE", fill=(100, 95, 85, alpha))

        # Subtle version
        draw.text((CENTER - 20, 462), "v2.3.0", fill=(60, 60, 70))


def run_logo_fallback():
    """Run endless logo fallback display."""
    print("SecuBox Eye Remote - Logo Fallback Display")
    print("Press Ctrl+C to stop")

    display = LogoFallback()

    try:
        while True:
            img = display.render()
            rgba = img.convert('RGBA')
            with open('/dev/fb0', 'wb') as fb:
                fb.write(rgba.tobytes('raw', 'BGRA'))
            time.sleep(0.05)  # 20 FPS (light on CPU)
    except KeyboardInterrupt:
        print("\nStopped")


if __name__ == "__main__":
    run_logo_fallback()
