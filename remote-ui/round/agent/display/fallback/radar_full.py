#!/usr/bin/env python3
"""
SecuBox Radar Metrics - Full Dashboard
- Rotating base grid
- Equilibrated metric values around circle
- Central icons with status
- Rainbow colorization
"""
import time
import math
import random
import colorsys
from PIL import Image, ImageDraw, ImageFont

WIDTH = HEIGHT = 480
CENTER = 240
RADIUS = 190
INNER_RADIUS = 80

# Modules with colors and metrics
MODULES = [
    {'name': 'AUTH', 'color': '#C04E24', 'metric': 'CPU', 'unit': '%'},
    {'name': 'WALL', 'color': '#9A6010', 'metric': 'MEM', 'unit': '%'},
    {'name': 'BOOT', 'color': '#803018', 'metric': 'DISK', 'unit': '%'},
    {'name': 'MIND', 'color': '#3D35A0', 'metric': 'LOAD', 'unit': ''},
    {'name': 'ROOT', 'color': '#0A5840', 'metric': 'TEMP', 'unit': 'C'},
    {'name': 'MESH', 'color': '#104A88', 'metric': 'NET', 'unit': '%'},
]

def hex_to_rgb(hex_color):
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

def angle_to_rainbow(angle):
    hue = (angle / (2 * math.pi)) % 1.0
    r, g, b = colorsys.hsv_to_rgb(hue, 0.9, 1.0)
    return (int(r * 255), int(g * 255), int(b * 255))


class RadarDashboard:
    def __init__(self):
        self._start_time = time.time()
        self._rotation_speed = 1.5  # RPM for base
        self._sweep_speed = 3.0     # RPM for sweep
        self._values = {m['name']: 50 + random.random() * 30 for m in MODULES}
        self._status = 'NOMINAL'

    @property
    def base_angle(self):
        elapsed = time.time() - self._start_time
        return (elapsed * (self._rotation_speed / 60.0) * 2 * math.pi) % (2 * math.pi)

    @property
    def sweep_angle(self):
        elapsed = time.time() - self._start_time
        return (elapsed * (self._sweep_speed / 60.0) * 2 * math.pi) % (2 * math.pi)

    def update_values(self):
        """Simulate metric changes"""
        for m in MODULES:
            name = m['name']
            # Smooth random walk
            delta = (random.random() - 0.5) * 5
            self._values[name] = max(10, min(95, self._values[name] + delta))

        # Update status based on values
        max_val = max(self._values.values())
        if max_val > 85:
            self._status = 'CRITICAL'
        elif max_val > 70:
            self._status = 'WARNING'
        else:
            self._status = 'NOMINAL'

    def render(self):
        self.update_values()

        img = Image.new('RGBA', (WIDTH, HEIGHT), (8, 8, 12, 255))
        draw = ImageDraw.Draw(img)

        base_angle = self.base_angle
        sweep_angle = self.sweep_angle

        # 1. Draw rotating grid
        self._draw_rotating_grid(draw, base_angle)

        # 2. Draw metric arcs (equilibrated around circle)
        self._draw_metric_arcs(draw, base_angle)

        # 3. Draw sweep line
        self._draw_sweep(draw, sweep_angle)

        # 4. Draw center with icons and status
        self._draw_center(draw, sweep_angle)

        # 5. Draw module labels
        self._draw_labels(draw, base_angle)

        return img

    def _draw_rotating_grid(self, draw, base_angle):
        # Concentric circles
        for r_pct in [25, 50, 75, 100]:
            r = int(RADIUS * r_pct / 100)
            # Rainbow tinted grid
            for deg in range(0, 360, 3):
                angle = math.radians(deg) + base_angle
                color = angle_to_rainbow(angle)
                color = (color[0] // 8, color[1] // 8, color[2] // 8)
                x1 = CENTER + r * math.sin(angle)
                y1 = CENTER - r * math.cos(angle)
                x2 = CENTER + r * math.sin(angle + 0.06)
                y2 = CENTER - r * math.cos(angle + 0.06)
                draw.line([(x1, y1), (x2, y2)], fill=color, width=1)

        # Radial lines (6 sections for 6 modules)
        for i in range(6):
            angle = (i * math.pi / 3) + base_angle
            color = angle_to_rainbow(angle)
            color = (color[0] // 5, color[1] // 5, color[2] // 5)
            x2 = CENTER + RADIUS * math.sin(angle)
            y2 = CENTER - RADIUS * math.cos(angle)
            draw.line([(CENTER, CENTER), (x2, y2)], fill=color, width=1)

    def _draw_metric_arcs(self, draw, base_angle):
        """Draw equilibrated metric arcs around the circle"""
        arc_width = 12

        for i, m in enumerate(MODULES):
            # Each module gets a 60-degree sector
            start_angle = (i * 60) + math.degrees(base_angle)
            value = self._values[m['name']]

            # Arc length proportional to value
            arc_extent = (value / 100) * 55  # max 55 degrees per sector

            # Module color with rainbow blend
            base_color = hex_to_rgb(m['color'])
            sector_angle = math.radians(start_angle + 30)  # center of sector
            rainbow = angle_to_rainbow(sector_angle)

            # Blend colors
            color = (
                (base_color[0] + rainbow[0]) // 2,
                (base_color[1] + rainbow[1]) // 2,
                (base_color[2] + rainbow[2]) // 2,
            )

            # Draw arc at different radii for layered effect
            for r_offset in range(3):
                r = RADIUS - 20 - (r_offset * arc_width)
                alpha = 255 - (r_offset * 60)

                bbox = [CENTER - r, CENTER - r, CENTER + r, CENTER + r]
                # PIL arc uses degrees, 0 = 3 o'clock, counter-clockwise
                # We want 0 = 12 o'clock, clockwise
                pil_start = 90 - start_angle - arc_extent
                pil_end = 90 - start_angle

                draw.arc(bbox, pil_start, pil_end,
                        fill=(color[0], color[1], color[2], alpha),
                        width=arc_width - 2)

    def _draw_sweep(self, draw, sweep_angle):
        # Trailing glow
        for i in range(30):
            offset = -0.25 * (i / 30)
            a = sweep_angle + offset
            rainbow = angle_to_rainbow(a)
            alpha = int(255 * (1 - i / 30))

            x2 = CENTER + RADIUS * math.sin(a)
            y2 = CENTER - RADIUS * math.cos(a)
            draw.line([(CENTER, CENTER), (x2, y2)],
                     fill=(rainbow[0], rainbow[1], rainbow[2], alpha),
                     width=3)

        # Main sweep line (white)
        x2 = CENTER + RADIUS * math.sin(sweep_angle)
        y2 = CENTER - RADIUS * math.cos(sweep_angle)
        draw.line([(CENTER, CENTER), (x2, y2)],
                 fill=(255, 255, 255), width=4)

        # Sweep head
        rainbow = angle_to_rainbow(sweep_angle)
        draw.ellipse([x2-8, y2-8, x2+8, y2+8], fill=rainbow)

    def _draw_center(self, draw, sweep_angle):
        # Central dark circle
        draw.ellipse([CENTER - INNER_RADIUS, CENTER - INNER_RADIUS,
                     CENTER + INNER_RADIUS, CENTER + INNER_RADIUS],
                    fill=(15, 15, 20), outline=(40, 40, 50), width=2)

        # Rotating ring
        rainbow = angle_to_rainbow(sweep_angle)
        for deg in range(0, 360, 10):
            angle = math.radians(deg) + sweep_angle
            r = INNER_RADIUS - 5
            x = CENTER + r * math.sin(angle)
            y = CENTER - r * math.cos(angle)
            size = 2
            draw.ellipse([x-size, y-size, x+size, y+size],
                        fill=(rainbow[0]//2, rainbow[1]//2, rainbow[2]//2))

        # Status text
        status_colors = {
            'NOMINAL': (0, 255, 100),
            'WARNING': (255, 180, 0),
            'CRITICAL': (255, 50, 50),
        }
        status_color = status_colors.get(self._status, (100, 100, 100))

        # Title
        draw.text((CENTER - 45, CENTER - 35), "SECUBOX", fill=(200, 200, 200))

        # Status indicator
        draw.ellipse([CENTER - 6, CENTER - 5, CENTER + 6, CENTER + 7],
                    fill=status_color)
        draw.text((CENTER - 35, CENTER + 15), self._status, fill=status_color)

        # Time
        time_str = time.strftime("%H:%M:%S")
        draw.text((CENTER - 30, CENTER + 35), time_str, fill=(150, 150, 180))

    def _draw_labels(self, draw, base_angle):
        """Draw module labels at sector positions"""
        label_radius = RADIUS + 15

        for i, m in enumerate(MODULES):
            # Center of each 60-degree sector
            angle = (i * math.pi / 3) + (math.pi / 6) + base_angle

            x = CENTER + label_radius * math.sin(angle)
            y = CENTER - label_radius * math.cos(angle)

            # Module color
            color = hex_to_rgb(m['color'])
            value = int(self._values[m['name']])

            # Label text
            label = f"{m['name']}"
            value_text = f"{value}{m['unit']}"

            # Offset text to center it
            draw.text((x - 15, y - 8), label, fill=color)
            draw.text((x - 12, y + 5), value_text, fill=(180, 180, 200))


def main():
    print("SecuBox Radar Full Dashboard")
    dashboard = RadarDashboard()

    try:
        while True:
            img = dashboard.render()
            rgba = img.convert('RGBA')
            with open('/dev/fb0', 'wb') as fb:
                fb.write(rgba.tobytes('raw', 'BGRA'))

            time.sleep(0.04)  # 25 FPS

    except KeyboardInterrupt:
        print("\nStopped")


if __name__ == "__main__":
    main()
