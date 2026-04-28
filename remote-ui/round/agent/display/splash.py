#!/usr/bin/env python3
"""
SecuBox Eye Remote - Splash Screen Display

Shows logo during:
- BOOT: System starting up
- HALT: System shutting down
- START: Service initializing

No metrics dashboard shown during these states.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import time
import math
from enum import Enum
from pathlib import Path
from typing import Optional
from PIL import Image, ImageDraw, ImageFilter

WIDTH = HEIGHT = 480
CENTER = 240

# Splash logo path
LOGO_PATH = Path(__file__).parent.parent.parent / "assets" / "splash" / "phoenix_logo.png"


class SplashState(Enum):
    BOOT = "boot"
    START = "start"
    HALT = "halt"
    REBOOT = "reboot"


class SplashScreen:
    """Splash screen with animated logo for boot/halt states."""

    def __init__(self):
        self._start_time = time.time()
        self._state = SplashState.BOOT
        self._logo: Optional[Image.Image] = None
        self._logo_small: Optional[Image.Image] = None
        self._load_logo()

    def _load_logo(self):
        """Load and prepare logo image."""
        try:
            if LOGO_PATH.exists():
                self._logo = Image.open(LOGO_PATH).convert('RGBA')
                # Resize to fit in center (about 300px)
                self._logo = self._logo.resize((300, 300), Image.Resampling.LANCZOS)
                self._logo_small = self._logo.resize((150, 150), Image.Resampling.LANCZOS)
        except Exception as e:
            print(f"Logo load error: {e}")
            self._logo = None

    @property
    def state(self) -> SplashState:
        return self._state

    @state.setter
    def state(self, value: SplashState):
        self._state = value
        self._start_time = time.time()

    def render(self) -> Image.Image:
        """Render splash screen with animated logo."""
        elapsed = time.time() - self._start_time
        pulse = (math.sin(elapsed * 2) + 1) / 2  # 0-1 pulse

        img = Image.new('RGBA', (WIDTH, HEIGHT), (5, 5, 12, 255))
        draw = ImageDraw.Draw(img)

        # Animated background glow
        self._draw_background_glow(draw, elapsed, pulse)

        # Logo with effects
        if self._logo:
            self._draw_logo(img, elapsed, pulse)
        else:
            self._draw_fallback_logo(draw, elapsed, pulse)

        # State text
        self._draw_state_text(draw, pulse)

        # Progress indicator
        self._draw_progress(draw, elapsed)

        return img

    def _draw_background_glow(self, draw, elapsed, pulse):
        """Draw animated background glow rings."""
        # Phoenix fire colors
        colors = [
            (255, 100, 20),   # Orange
            (255, 60, 10),    # Red-orange
            (255, 40, 0),     # Red
        ]

        for i, color in enumerate(colors):
            r = 200 + i * 30 + math.sin(elapsed + i) * 20
            alpha = int((50 + pulse * 30) * (1 - i * 0.2))
            glow_color = (color[0], color[1], color[2], alpha)

            # Multiple rings with offset
            for offset in range(0, 360, 30):
                angle = math.radians(offset + elapsed * 20)
                ox = math.cos(angle) * 5
                oy = math.sin(angle) * 5
                draw.ellipse([
                    CENTER - r + ox, CENTER - r + oy,
                    CENTER + r + ox, CENTER + r + oy
                ], outline=glow_color, width=3)

    def _draw_logo(self, img: Image.Image, elapsed: float, pulse: float):
        """Draw the logo with animation effects."""
        if self._logo is None:
            return

        # Pulsing scale
        scale = 1.0 + pulse * 0.05

        # Rotate slightly
        rotation = math.sin(elapsed * 0.5) * 3  # ±3 degrees

        # Prepare logo
        logo = self._logo.copy()
        if rotation != 0:
            logo = logo.rotate(rotation, Image.Resampling.BILINEAR, expand=False)

        # Scale
        new_size = int(300 * scale)
        logo = logo.resize((new_size, new_size), Image.Resampling.LANCZOS)

        # Add glow effect
        glow_intensity = int(pulse * 30)
        if glow_intensity > 0:
            glow = logo.filter(ImageFilter.GaussianBlur(radius=10))
            # Enhance glow
            glow_layer = Image.new('RGBA', (WIDTH, HEIGHT), (0, 0, 0, 0))
            glow_pos = (CENTER - new_size // 2, CENTER - new_size // 2 - 20)
            glow_layer.paste(glow, glow_pos, glow)
            img.alpha_composite(glow_layer)

        # Paste logo
        pos = (CENTER - new_size // 2, CENTER - new_size // 2 - 20)
        img.paste(logo, pos, logo)

    def _draw_fallback_logo(self, draw, elapsed, pulse):
        """Draw fallback phoenix symbol if no logo image."""
        # Phoenix-like symbol using shapes
        r = 80 + pulse * 10

        # Fire colors
        colors = [
            (255, 120, 20, int(200 + pulse * 55)),
            (255, 80, 0, int(180 + pulse * 55)),
            (255, 40, 0, int(160 + pulse * 55)),
        ]

        # Central orb
        for i, color in enumerate(colors):
            size = r - i * 15
            draw.ellipse([
                CENTER - size, CENTER - size - 20,
                CENTER + size, CENTER + size - 20
            ], fill=color)

        # Wings (arcs)
        for side in [-1, 1]:
            for i in range(3):
                offset = i * 20
                wing_r = 100 + offset
                start = 180 + side * 30 + math.sin(elapsed * 2) * 10
                end = start + side * 60
                color = colors[min(i, 2)]
                draw.arc([
                    CENTER - wing_r + side * 20, CENTER - wing_r - 20,
                    CENTER + wing_r + side * 20, CENTER + wing_r - 20
                ], start, end, fill=color, width=8 - i * 2)

        # Inner dark circle (eye)
        draw.ellipse([
            CENTER - 25, CENTER - 45,
            CENTER + 25, CENTER + 5
        ], fill=(10, 10, 20))

    def _draw_state_text(self, draw, pulse):
        """Draw state text at bottom."""
        state_texts = {
            SplashState.BOOT: ("BOOTING", (255, 150, 50)),
            SplashState.START: ("STARTING", (100, 255, 150)),
            SplashState.HALT: ("SHUTTING DOWN", (255, 80, 80)),
            SplashState.REBOOT: ("REBOOTING", (255, 200, 50)),
        }

        text, color = state_texts.get(self._state, ("SECUBOX", (200, 200, 200)))

        # Pulsing alpha
        alpha = int(180 + pulse * 75)
        text_color = (color[0], color[1], color[2], alpha)

        # Center text
        draw.text((CENTER - len(text) * 5, 400), text, fill=text_color)

        # SecuBox branding
        draw.text((CENTER - 35, 430), "SECUBOX", fill=(100, 100, 120))
        draw.text((CENTER - 40, 450), "EYE REMOTE", fill=(80, 80, 100))

    def _draw_progress(self, draw, elapsed):
        """Draw animated progress indicator."""
        # Rotating dots
        num_dots = 8
        dot_r = 180

        for i in range(num_dots):
            angle = (i / num_dots) * 2 * math.pi + elapsed * 2
            x = CENTER + dot_r * math.cos(angle)
            y = 420 + 15 * math.sin(angle)

            # Fade based on position
            alpha = int(100 + 155 * ((math.sin(angle - elapsed * 2) + 1) / 2))
            size = 3 + 2 * ((math.sin(angle - elapsed * 2) + 1) / 2)

            draw.ellipse([x - size, y - size, x + size, y + size],
                        fill=(255, 150, 50, alpha))


def show_splash(state: SplashState = SplashState.BOOT, duration: float = 0):
    """Show splash screen for specified duration (0 = indefinite)."""
    splash = SplashScreen()
    splash.state = state

    start = time.time()
    try:
        while True:
            if duration > 0 and (time.time() - start) > duration:
                break

            img = splash.render()
            rgba = img.convert('RGBA')
            with open('/dev/fb0', 'wb') as fb:
                fb.write(rgba.tobytes('raw', 'BGRA'))

            time.sleep(0.033)  # 30 FPS

    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    import sys
    state = SplashState.BOOT
    if len(sys.argv) > 1:
        state_map = {
            'boot': SplashState.BOOT,
            'start': SplashState.START,
            'halt': SplashState.HALT,
            'reboot': SplashState.REBOOT,
        }
        state = state_map.get(sys.argv[1].lower(), SplashState.BOOT)

    print(f"Showing {state.value} splash...")
    show_splash(state)
