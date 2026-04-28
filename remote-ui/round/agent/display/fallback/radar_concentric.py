#!/usr/bin/env python3
"""
SecuBox Radar - Concentric Balanced Metrics
- 6 concentric rings for 6 modules
- Balanced arc lengths proportional to values
- Original SecuBox module colors
- Rotating sweep with rainbow trail
"""
import time
import math
import random
import colorsys
from PIL import Image, ImageDraw

WIDTH = HEIGHT = 480
CENTER = 240

# Module rings from outer to inner (original colors)
MODULES = [
    {'name': 'AUTH', 'color': (192, 78, 36),   'r': 214, 'metric': 'CPU'},
    {'name': 'WALL', 'color': (154, 96, 16),   'r': 188, 'metric': 'MEM'},
    {'name': 'BOOT', 'color': (128, 48, 24),   'r': 162, 'metric': 'DISK'},
    {'name': 'MIND', 'color': (61, 53, 160),   'r': 136, 'metric': 'LOAD'},
    {'name': 'ROOT', 'color': (10, 88, 64),    'r': 110, 'metric': 'TEMP'},
    {'name': 'MESH', 'color': (16, 74, 136),   'r': 84,  'metric': 'NET'},
]

RING_WIDTH = 20


class ConcentricRadar:
    def __init__(self):
        self._start_time = time.time()
        self._sweep_speed = 2.5  # RPM
        self._values = {m['name']: 50 + random.random() * 30 for m in MODULES}

    @property
    def sweep_angle(self):
        elapsed = time.time() - self._start_time
        return (elapsed * (self._sweep_speed / 60.0) * 2 * math.pi) % (2 * math.pi)

    def update_values(self):
        for m in MODULES:
            name = m['name']
            delta = (random.random() - 0.5) * 4
            self._values[name] = max(15, min(95, self._values[name] + delta))

    def render(self):
        self.update_values()
        img = Image.new('RGBA', (WIDTH, HEIGHT), (8, 8, 12, 255))
        draw = ImageDraw.Draw(img)

        sweep_angle = self.sweep_angle

        # 1. Draw concentric ring backgrounds (dark)
        for m in MODULES:
            r = m['r']
            draw.ellipse([CENTER - r, CENTER - r, CENTER + r, CENTER + r],
                        outline=(25, 25, 30), width=RING_WIDTH)

        # 2. Draw balanced metric arcs on each ring
        for m in MODULES:
            self._draw_balanced_arc(draw, m, sweep_angle)

        # 3. Draw sweep line across all rings
        self._draw_sweep(draw, sweep_angle)

        # 4. Draw center
        self._draw_center(draw, sweep_angle)

        # 5. Draw labels
        self._draw_labels(draw)

        return img

    def _draw_balanced_arc(self, draw, module, sweep_angle):
        """Draw balanced arc - centered on value position"""
        r = module['r']
        color = module['color']
        value = self._values[module['name']]

        # Arc spans proportional to value, centered at 12 o'clock
        # Value 100% = full circle, value 50% = half circle
        arc_extent = (value / 100) * 360

        # Center the arc at top (12 o'clock position)
        # PIL uses 0=3 o'clock, counter-clockwise
        half_arc = arc_extent / 2
        pil_start = 90 + half_arc   # right side of arc
        pil_end = 90 - half_arc     # left side of arc

        # Glow effect - multiple layers
        for i in range(3):
            alpha = 255 - (i * 60)
            glow_color = (
                min(255, color[0] + 20),
                min(255, color[1] + 20),
                min(255, color[2] + 20),
                alpha
            )
            offset = i * 2
            bbox = [CENTER - r - offset, CENTER - r - offset,
                   CENTER + r + offset, CENTER + r + offset]
            draw.arc(bbox, pil_end, pil_start, fill=glow_color, width=RING_WIDTH - 4)

        # Main arc
        bbox = [CENTER - r, CENTER - r, CENTER + r, CENTER + r]
        draw.arc(bbox, pil_end, pil_start, fill=color, width=RING_WIDTH - 2)

        # Arc end caps (dots)
        for angle_deg in [90 - half_arc, 90 + half_arc]:
            angle_rad = math.radians(angle_deg)
            x = CENTER + r * math.cos(angle_rad)
            y = CENTER - r * math.sin(angle_rad)
            draw.ellipse([x-4, y-4, x+4, y+4], fill=color)

    def _draw_sweep(self, draw, sweep_angle):
        """Draw sweep line with rainbow gradient"""
        max_r = MODULES[0]['r'] + 15
        min_r = MODULES[-1]['r'] - 15

        # Rainbow trail
        for i in range(25):
            offset = -0.2 * (i / 25)
            a = sweep_angle + offset

            hue = ((a + offset) / (2 * math.pi)) % 1.0
            r, g, b = colorsys.hsv_to_rgb(hue, 0.8, 1.0)
            alpha = int(220 * (1 - i / 25))
            color = (int(r * 255), int(g * 255), int(b * 255), alpha)

            x1 = CENTER + min_r * math.sin(a)
            y1 = CENTER - min_r * math.cos(a)
            x2 = CENTER + max_r * math.sin(a)
            y2 = CENTER - max_r * math.cos(a)

            draw.line([(x1, y1), (x2, y2)], fill=color, width=3)

        # Main sweep (white)
        x1 = CENTER + min_r * math.sin(sweep_angle)
        y1 = CENTER - min_r * math.cos(sweep_angle)
        x2 = CENTER + max_r * math.sin(sweep_angle)
        y2 = CENTER - max_r * math.cos(sweep_angle)
        draw.line([(x1, y1), (x2, y2)], fill=(255, 255, 255), width=4)

        # Sweep dots at each ring intersection
        for m in MODULES:
            r = m['r']
            x = CENTER + r * math.sin(sweep_angle)
            y = CENTER - r * math.cos(sweep_angle)
            hue = (sweep_angle / (2 * math.pi)) % 1.0
            rc, gc, bc = colorsys.hsv_to_rgb(hue, 1.0, 1.0)
            draw.ellipse([x-5, y-5, x+5, y+5],
                        fill=(int(rc*255), int(gc*255), int(bc*255)))

    def _draw_center(self, draw, sweep_angle):
        """Draw center status area"""
        inner_r = 55

        # Dark center
        draw.ellipse([CENTER - inner_r, CENTER - inner_r,
                     CENTER + inner_r, CENTER + inner_r],
                    fill=(12, 12, 18), outline=(40, 40, 50), width=2)

        # Rotating accent ring
        hue = (sweep_angle / (2 * math.pi)) % 1.0
        r, g, b = colorsys.hsv_to_rgb(hue, 0.9, 0.8)
        accent = (int(r * 255), int(g * 255), int(b * 255))

        for deg in range(0, 360, 15):
            angle = math.radians(deg) + sweep_angle
            x = CENTER + (inner_r - 8) * math.sin(angle)
            y = CENTER - (inner_r - 8) * math.cos(angle)
            draw.ellipse([x-2, y-2, x+2, y+2], fill=accent)

        # Title
        draw.text((CENTER - 35, CENTER - 25), "SECUBOX", fill=(200, 200, 210))

        # Time
        time_str = time.strftime("%H:%M")
        draw.text((CENTER - 20, CENTER - 5), time_str, fill=accent)

        # Status dot
        max_val = max(self._values.values())
        if max_val > 85:
            status_color = (255, 50, 50)
        elif max_val > 70:
            status_color = (255, 180, 0)
        else:
            status_color = (0, 255, 100)

        draw.ellipse([CENTER - 5, CENTER + 15, CENTER + 5, CENTER + 25],
                    fill=status_color)

    def _draw_labels(self, draw):
        """Draw module labels at fixed positions"""
        # Labels at cardinal positions
        label_positions = [
            (CENTER, 15),           # top
            (440, CENTER - 50),     # right-top
            (440, CENTER + 50),     # right-bottom
            (CENTER, 450),          # bottom
            (10, CENTER + 50),      # left-bottom
            (10, CENTER - 50),      # left-top
        ]

        for i, m in enumerate(MODULES):
            x, y = label_positions[i]
            color = m['color']
            value = int(self._values[m['name']])

            # Module name
            draw.text((x, y), m['name'], fill=color)
            # Value
            draw.text((x, y + 12), f"{value}%", fill=(180, 180, 200))


def main():
    print("SecuBox Concentric Balanced Radar")
    radar = ConcentricRadar()

    try:
        while True:
            img = radar.render()
            rgba = img.convert('RGBA')
            with open('/dev/fb0', 'wb') as fb:
                fb.write(rgba.tobytes('raw', 'BGRA'))

            time.sleep(0.04)  # 25 FPS

    except KeyboardInterrupt:
        print("\nStopped")


if __name__ == "__main__":
    main()
