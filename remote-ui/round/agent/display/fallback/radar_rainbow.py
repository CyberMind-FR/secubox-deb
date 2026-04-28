#!/usr/bin/env python3
"""
Radar Metrics with Rainbow/Arc-en-ciel colorization.
"""
import time
import math
import random
import colorsys
from PIL import Image, ImageDraw

WIDTH = HEIGHT = 480
CENTER = 240
RADIUS = 200
TRACE_SAMPLES = 360
ROTATION_SPEED = 2.0  # RPM


class RainbowRadar:
    def __init__(self):
        self._start_time = time.time()
        self._trace_buffer = [0.0] * TRACE_SAMPLES
        self._trace_decay = 0.92

    @property
    def current_angle(self):
        elapsed = time.time() - self._start_time
        rotations = elapsed * (ROTATION_SPEED / 60.0)
        return (rotations * 2 * math.pi) % (2 * math.pi)

    def angle_to_color(self, angle):
        """Convert angle to rainbow color (HSV hue rotation)."""
        hue = (angle / (2 * math.pi)) % 1.0
        r, g, b = colorsys.hsv_to_rgb(hue, 1.0, 1.0)
        return (int(r * 255), int(g * 255), int(b * 255))

    def add_sample(self, value):
        angle = self.current_angle
        idx = int((angle / (2 * math.pi)) * TRACE_SAMPLES) % TRACE_SAMPLES
        self._trace_buffer[idx] = min(100, max(0, value))

    def decay_trace(self):
        for i in range(len(self._trace_buffer)):
            self._trace_buffer[i] *= self._trace_decay

    def render(self):
        self.decay_trace()
        img = Image.new('RGBA', (WIDTH, HEIGHT), (8, 8, 12, 255))
        draw = ImageDraw.Draw(img)

        # Grid circles (subtle rainbow tint)
        for level in [25, 50, 75, 100]:
            r = int(RADIUS * level / 100)
            # Rainbow gradient for grid
            for deg in range(0, 360, 2):
                angle = math.radians(deg)
                color = self.angle_to_color(angle)
                # Dim the grid color
                color = (color[0] // 6, color[1] // 6, color[2] // 6)
                x1 = CENTER + r * math.sin(angle)
                y1 = CENTER - r * math.cos(angle)
                x2 = CENTER + r * math.sin(angle + 0.04)
                y2 = CENTER - r * math.cos(angle + 0.04)
                draw.line([(x1, y1), (x2, y2)], fill=color, width=1)

        # Radial lines with rainbow
        for angle_deg in range(0, 360, 30):
            angle = math.radians(angle_deg)
            color = self.angle_to_color(angle)
            color = (color[0] // 4, color[1] // 4, color[2] // 4)
            x2 = CENTER + RADIUS * math.sin(angle)
            y2 = CENTER - RADIUS * math.cos(angle)
            draw.line([(CENTER, CENTER), (x2, y2)], fill=color, width=1)

        # Rainbow trace
        for i in range(TRACE_SAMPLES):
            angle = (i / TRACE_SAMPLES) * 2 * math.pi
            value = self._trace_buffer[i]
            if value > 3:
                r = RADIUS * (value / 100.0)
                x = CENTER + r * math.sin(angle)
                y = CENTER - r * math.cos(angle)

                # Rainbow color based on angle
                color = self.angle_to_color(angle)
                alpha = int(220 * (value / 100.0))

                # Draw point with glow
                size = 2 + int(value / 30)
                draw.ellipse([x-size, y-size, x+size, y+size],
                            fill=(color[0], color[1], color[2], alpha))

        # Sweep line - white bright sweep
        angle = self.current_angle
        sweep_color = self.angle_to_color(angle)

        # Trailing glow
        for i in range(25):
            offset = -0.2 * (i / 25)
            a = angle + offset
            trail_color = self.angle_to_color(a)
            alpha = int(255 * (1 - i / 25))
            x2 = CENTER + RADIUS * math.sin(a)
            y2 = CENTER - RADIUS * math.cos(a)
            draw.line([(CENTER, CENTER), (x2, y2)],
                     fill=(trail_color[0], trail_color[1], trail_color[2], alpha),
                     width=3)

        # Main sweep line (bright white-ish)
        x2 = CENTER + RADIUS * math.sin(angle)
        y2 = CENTER - RADIUS * math.cos(angle)
        draw.line([(CENTER, CENTER), (x2, y2)],
                 fill=(255, 255, 255), width=4)

        # Sweep head dot
        draw.ellipse([x2-6, y2-6, x2+6, y2+6],
                    fill=sweep_color)

        # Center dot - rainbow rotating
        draw.ellipse([CENTER - 10, CENTER - 10, CENTER + 10, CENTER + 10],
                    fill=sweep_color, outline=(255, 255, 255), width=2)

        # Title with rainbow
        draw.text((10, 10), "SECUBOX RADAR", fill=(255, 255, 255))
        draw.text((10, 30), "Arc-en-ciel Mode", fill=sweep_color)

        return img


def main():
    print("SecuBox Rainbow Radar")
    radar = RainbowRadar()
    frame = 0

    try:
        while True:
            # Simulate varying metrics
            cpu = 40 + math.sin(frame * 0.03) * 25 + random.random() * 15
            radar.add_sample(cpu)

            # Render
            img = radar.render()
            rgba = img.convert('RGBA')
            with open('/dev/fb0', 'wb') as fb:
                fb.write(rgba.tobytes('raw', 'BGRA'))

            frame += 1
            time.sleep(0.04)  # 25 FPS

    except KeyboardInterrupt:
        print("\nStopped")


if __name__ == "__main__":
    main()
