#!/usr/bin/env python3
"""
SecuBox Eye Remote - Fallback Display Manager

States:
- OFFLINE: No connection - show local metrics radar (concentric rings)
- CONNECTING: Attempting connection - show rotating dice/cube
- ONLINE: Connected to SecuBox - show full dashboard with cube
- COMMUNICATING: Active data transfer - animated dice

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import time
import math
import random
import colorsys
import subprocess
from enum import Enum
from typing import Optional, Tuple
from PIL import Image, ImageDraw

WIDTH = HEIGHT = 480
CENTER = 240


class FallbackMode(Enum):
    OFFLINE = "offline"           # No connection - local metrics
    CONNECTING = "connecting"     # Trying to connect - dice animation
    ONLINE = "online"             # Connected - full dashboard
    COMMUNICATING = "comm"        # Active transfer - fast dice


# Flashy module colors
MODULES = [
    {'name': 'AUTH', 'color': (255, 80, 40),   'r': 214, 'glow': (255, 120, 80)},
    {'name': 'WALL', 'color': (255, 160, 20),  'r': 188, 'glow': (255, 200, 60)},
    {'name': 'BOOT', 'color': (255, 60, 100),  'r': 162, 'glow': (255, 100, 140)},
    {'name': 'MIND', 'color': (120, 80, 255),  'r': 136, 'glow': (160, 120, 255)},
    {'name': 'ROOT', 'color': (0, 255, 120),   'r': 110, 'glow': (80, 255, 160)},
    {'name': 'MESH', 'color': (0, 180, 255),   'r': 84,  'glow': (80, 220, 255)},
]

RING_WIDTH = 22

# 3D Cube
CUBE_VERTICES = [
    (-1, -1, -1), (1, -1, -1), (1, 1, -1), (-1, 1, -1),
    (-1, -1, 1),  (1, -1, 1),  (1, 1, 1),  (-1, 1, 1),
]
CUBE_EDGES = [
    (0, 1), (1, 2), (2, 3), (3, 0),
    (4, 5), (5, 6), (6, 7), (7, 4),
    (0, 4), (1, 5), (2, 6), (3, 7),
]
CUBE_FACES = [
    (0, 1, 2, 3), (4, 5, 6, 7), (0, 1, 5, 4),
    (2, 3, 7, 6), (0, 3, 7, 4), (1, 2, 6, 5),
]


class FallbackManager:
    """Manages fallback display modes based on connection state."""

    def __init__(self):
        self._start_time = time.time()
        self._mode = FallbackMode.OFFLINE
        self._values = {m['name']: 50 + random.random() * 30 for m in MODULES}
        self._pulse_phase = 0
        self._last_check = 0
        self._check_interval = 5.0  # Check connection every 5s
        self._comm_active = False
        self._comm_start = 0

    @property
    def mode(self) -> FallbackMode:
        return self._mode

    @mode.setter
    def mode(self, value: FallbackMode):
        self._mode = value

    def set_communicating(self, active: bool = True):
        """Signal active data transfer."""
        self._comm_active = active
        if active:
            self._comm_start = time.time()
            self._mode = FallbackMode.COMMUNICATING

    def check_connection(self) -> FallbackMode:
        """Check OTG/WiFi connection status."""
        now = time.time()
        if now - self._last_check < self._check_interval:
            return self._mode

        self._last_check = now

        # Check OTG first (10.55.0.1)
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', '10.55.0.1'],
                capture_output=True, timeout=2
            )
            if result.returncode == 0:
                self._mode = FallbackMode.ONLINE
                return self._mode
        except:
            pass

        # Check WiFi (secubox.local or gateway)
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', 'secubox.local'],
                capture_output=True, timeout=2
            )
            if result.returncode == 0:
                self._mode = FallbackMode.ONLINE
                return self._mode
        except:
            pass

        # No connection
        self._mode = FallbackMode.OFFLINE
        return self._mode

    @property
    def sweep_angle(self) -> float:
        elapsed = time.time() - self._start_time
        speed = 3.0 if self._mode == FallbackMode.ONLINE else 1.5
        return (elapsed * (speed / 60.0) * 2 * math.pi) % (2 * math.pi)

    @property
    def cube_speed(self) -> float:
        """Cube rotation speed based on mode."""
        if self._mode == FallbackMode.COMMUNICATING:
            return 3.0  # Fast spin during comm
        elif self._mode == FallbackMode.CONNECTING:
            return 1.5  # Medium spin connecting
        elif self._mode == FallbackMode.ONLINE:
            return 0.8  # Slow spin online
        return 0.3  # Very slow offline

    @property
    def cube_angle(self) -> float:
        elapsed = time.time() - self._start_time
        return elapsed * self.cube_speed * 2 * math.pi

    def update_local_metrics(self):
        """Update simulated local metrics."""
        self._pulse_phase += 0.12
        for m in MODULES:
            name = m['name']
            delta = (random.random() - 0.5) * 2
            self._values[name] = max(20, min(95, self._values[name] + delta))

    def rotate_point(self, x, y, z, ax, ay, az) -> Tuple[float, float, float]:
        """Rotate 3D point."""
        cos_x, sin_x = math.cos(ax), math.sin(ax)
        y, z = y * cos_x - z * sin_x, y * sin_x + z * cos_x
        cos_y, sin_y = math.cos(ay), math.sin(ay)
        x, z = x * cos_y + z * sin_y, -x * sin_y + z * cos_y
        cos_z, sin_z = math.cos(az), math.sin(az)
        x, y = x * cos_z - y * sin_z, x * sin_z + y * cos_z
        return x, y, z

    def project_3d(self, x, y, z, scale=25) -> Tuple[int, int]:
        """Project 3D to 2D."""
        fov, z_off = 3.0, 4.0
        factor = fov / (z_off + z)
        return int(CENTER + x * scale * factor), int(CENTER + y * scale * factor)

    def render(self) -> Image.Image:
        """Render current display based on mode."""
        self.update_local_metrics()
        self.check_connection()

        img = Image.new('RGBA', (WIDTH, HEIGHT), (5, 5, 10, 255))
        draw = ImageDraw.Draw(img)

        pulse = (math.sin(self._pulse_phase) + 1) / 2
        sweep = self.sweep_angle
        cube_ang = self.cube_angle

        # Always draw rings (local metrics as fallback)
        self._draw_rings(draw, pulse)
        self._draw_arcs(draw, pulse)
        self._draw_sweep(draw, sweep, pulse)

        # Draw cube based on mode
        if self._mode in (FallbackMode.ONLINE, FallbackMode.COMMUNICATING):
            # Full cube with icons when connected
            self._draw_cube(draw, cube_ang, pulse, show_icons=True)
        elif self._mode == FallbackMode.CONNECTING:
            # Spinning cube when connecting
            self._draw_cube(draw, cube_ang, pulse, show_icons=False)
        else:
            # Simple center for offline
            self._draw_offline_center(draw, pulse)

        # Mode indicator
        self._draw_mode_indicator(draw, pulse)

        return img

    def _draw_rings(self, draw, pulse):
        """Draw concentric ring backgrounds."""
        for m in MODULES:
            r = m['r']
            glow = m['glow']
            intensity = int(30 + pulse * 20)
            draw.ellipse([CENTER - r - 2, CENTER - r - 2, CENTER + r + 2, CENTER + r + 2],
                        outline=(glow[0]//5, glow[1]//5, glow[2]//5, intensity),
                        width=RING_WIDTH + 4)
            draw.ellipse([CENTER - r, CENTER - r, CENTER + r, CENTER + r],
                        outline=(20, 20, 25), width=RING_WIDTH)

    def _draw_arcs(self, draw, pulse):
        """Draw balanced metric arcs."""
        for m in MODULES:
            r = m['r']
            color = m['color']
            glow = m['glow']
            value = self._values[m['name']]

            arc_extent = (value / 100) * 360
            half = arc_extent / 2
            start, end = 90 + half, 90 - half

            # Glow
            for i in range(3):
                alpha = int((180 - i * 50) * (0.7 + pulse * 0.3))
                g = (glow[0], glow[1], glow[2], alpha)
                off = i * 2
                bbox = [CENTER - r - off, CENTER - r - off, CENTER + r + off, CENTER + r + off]
                draw.arc(bbox, end, start, fill=g, width=RING_WIDTH - 2)

            # Main arc
            bbox = [CENTER - r, CENTER - r, CENTER + r, CENTER + r]
            draw.arc(bbox, end, start, fill=color, width=RING_WIDTH - 4)

    def _draw_sweep(self, draw, angle, pulse):
        """Draw rainbow sweep line."""
        max_r, min_r = MODULES[0]['r'] + 15, MODULES[-1]['r'] - 15

        for i in range(30):
            off = -0.25 * (i / 30)
            a = angle + off
            hue = ((a + off) / (2 * math.pi)) % 1.0
            r, g, b = colorsys.hsv_to_rgb(hue, 0.9, 1.0)
            alpha = int(240 * (1 - i / 30))
            color = (int(r * 255), int(g * 255), int(b * 255), alpha)
            x1 = CENTER + min_r * math.sin(a)
            y1 = CENTER - min_r * math.cos(a)
            x2 = CENTER + max_r * math.sin(a)
            y2 = CENTER - max_r * math.cos(a)
            draw.line([(x1, y1), (x2, y2)], fill=color, width=3)

        # Main line
        x1 = CENTER + min_r * math.sin(angle)
        y1 = CENTER - min_r * math.cos(angle)
        x2 = CENTER + max_r * math.sin(angle)
        y2 = CENTER - max_r * math.cos(angle)
        draw.line([(x1, y1), (x2, y2)], fill=(255, 255, 255), width=4)

    def _draw_cube(self, draw, angle, pulse, show_icons=True):
        """Draw 3D rotating cube."""
        inner_r = 55
        draw.ellipse([CENTER - inner_r, CENTER - inner_r,
                     CENTER + inner_r, CENTER + inner_r],
                    fill=(8, 8, 15), outline=(60, 60, 80), width=2)

        ax = angle * 0.7
        ay = angle
        az = angle * 0.3

        transformed = [self.rotate_point(*v, ax, ay, az) for v in CUBE_VERTICES]

        face_depths = [(sum(transformed[v][2] for v in f) / 4, i, f)
                       for i, f in enumerate(CUBE_FACES)]
        face_depths.sort(key=lambda x: x[0])

        icons = ['A', 'W', 'B', 'M', 'R', 'X']

        for depth, i, face in face_depths:
            points = [self.project_3d(*transformed[v]) for v in face]
            base = MODULES[i % 6]['color']
            shade = min(1.0, max(0.3, 0.4 + (depth + 1) * 0.3))
            fill = (
                int(base[0] * shade * (0.8 + pulse * 0.2)),
                int(base[1] * shade * (0.8 + pulse * 0.2)),
                int(base[2] * shade * (0.8 + pulse * 0.2)),
            )
            draw.polygon(points, fill=fill, outline=(255, 255, 255, 100))

            if show_icons and depth > 0:
                cx = sum(p[0] for p in points) // 4
                cy = sum(p[1] for p in points) // 4
                draw.text((cx - 5, cy - 6), icons[i % 6], fill=(255, 255, 255))

        for e in CUBE_EDGES:
            p1 = self.project_3d(*transformed[e[0]])
            p2 = self.project_3d(*transformed[e[1]])
            draw.line([p1, p2], fill=(255, 255, 255, 180), width=2)

    def _draw_offline_center(self, draw, pulse):
        """Draw simple center when offline."""
        inner_r = 55
        draw.ellipse([CENTER - inner_r, CENTER - inner_r,
                     CENTER + inner_r, CENTER + inner_r],
                    fill=(10, 10, 18), outline=(50, 50, 60), width=2)

        # Pulsing ring
        ring_alpha = int(100 + pulse * 80)
        draw.ellipse([CENTER - 45, CENTER - 45, CENTER + 45, CENTER + 45],
                    outline=(100, 100, 120, ring_alpha), width=2)

        draw.text((CENTER - 35, CENTER - 20), "SECUBOX", fill=(150, 150, 160))
        draw.text((CENTER - 28, CENTER), "OFFLINE", fill=(255, 100, 100))
        draw.text((CENTER - 25, CENTER + 20), time.strftime("%H:%M"), fill=(100, 100, 120))

    def _draw_mode_indicator(self, draw, pulse):
        """Draw connection mode indicator."""
        mode_colors = {
            FallbackMode.OFFLINE: (255, 80, 80),
            FallbackMode.CONNECTING: (255, 200, 0),
            FallbackMode.ONLINE: (0, 255, 100),
            FallbackMode.COMMUNICATING: (0, 200, 255),
        }
        mode_labels = {
            FallbackMode.OFFLINE: "OFFLINE",
            FallbackMode.CONNECTING: "CONNECTING",
            FallbackMode.ONLINE: "ONLINE",
            FallbackMode.COMMUNICATING: "SYNC",
        }

        color = mode_colors.get(self._mode, (100, 100, 100))
        label = mode_labels.get(self._mode, "?")

        # Pulsing dot
        size = int(5 + pulse * 3)
        draw.ellipse([15 - size, 15 - size, 15 + size, 15 + size], fill=color)
        draw.text((25, 10), label, fill=color)


def run_fallback_display():
    """Run the fallback display loop."""
    print("SecuBox Eye Remote - Fallback Display")
    manager = FallbackManager()

    try:
        while True:
            img = manager.render()
            rgba = img.convert('RGBA')
            with open('/dev/fb0', 'wb') as fb:
                fb.write(rgba.tobytes('raw', 'BGRA'))
            time.sleep(0.033)  # 30 FPS

    except KeyboardInterrupt:
        print("\nStopped")


if __name__ == "__main__":
    run_fallback_display()
