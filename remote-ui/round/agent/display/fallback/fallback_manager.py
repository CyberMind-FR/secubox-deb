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

import os
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
        self._values = {m['name']: 50 for m in MODULES}
        self._pulse_phase = 0
        self._last_check = 0
        self._check_interval = 5.0  # Check connection every 5s
        self._comm_active = False
        self._comm_start = 0
        self._last_cpu_idle = 0
        self._last_cpu_total = 0
        self._metrics_interval = 1.0  # Read metrics every 1s
        self._last_metrics = 0

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
        """Update real Pi Zero metrics."""
        self._pulse_phase += 0.12

        now = time.time()
        if now - self._last_metrics < self._metrics_interval:
            return
        self._last_metrics = now

        try:
            # CPU usage from /proc/stat
            with open('/proc/stat', 'r') as f:
                line = f.readline()
                parts = line.split()
                idle = int(parts[4])
                total = sum(int(p) for p in parts[1:8])

                if self._last_cpu_total > 0:
                    diff_idle = idle - self._last_cpu_idle
                    diff_total = total - self._last_cpu_total
                    if diff_total > 0:
                        cpu_pct = 100 * (1 - diff_idle / diff_total)
                        self._values['AUTH'] = max(5, min(95, cpu_pct))

                self._last_cpu_idle = idle
                self._last_cpu_total = total

            # Memory from /proc/meminfo
            with open('/proc/meminfo', 'r') as f:
                meminfo = {}
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        meminfo[parts[0].rstrip(':')] = int(parts[1])

                total = meminfo.get('MemTotal', 1)
                avail = meminfo.get('MemAvailable', meminfo.get('MemFree', total))
                mem_pct = 100 * (1 - avail / total)
                self._values['WALL'] = max(5, min(95, mem_pct))

            # Disk from os.statvfs
            import os
            st = os.statvfs('/')
            disk_pct = 100 * (1 - st.f_bavail / st.f_blocks)
            self._values['BOOT'] = max(5, min(95, disk_pct))

            # Load average - logarithmic scale for spikes
            load1, _, _ = os.getloadavg()
            # Pi Zero has 1 core: load 0.1=10%, 1.0=50%, 10.0=90% (log scale)
            if load1 > 0:
                load_pct = 50 + 20 * math.log10(max(0.1, min(10, load1)))
            else:
                load_pct = 5
            self._values['MIND'] = max(5, min(95, load_pct))

            # CPU temperature
            try:
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                    temp_c = int(f.read().strip()) / 1000
                    # Scale: 30°C=0%, 85°C=100%
                    temp_pct = max(0, min(100, (temp_c - 30) / 55 * 100))
                    self._values['ROOT'] = max(5, min(95, temp_pct))
            except:
                pass

            # Network - logarithmic scale for traffic variation
            try:
                with open('/proc/net/dev', 'r') as f:
                    for line in f:
                        if 'usb' in line:
                            parts = line.split()
                            rx = int(parts[1])
                            tx = int(parts[9])
                            total_bytes = rx + tx
                            # Log scale: 1KB=20%, 1MB=50%, 1GB=80%
                            if total_bytes > 0:
                                net_pct = 10 * math.log10(max(1, total_bytes / 100))
                                net_pct = max(5, min(95, net_pct))
                            else:
                                net_pct = 5
                            self._values['MESH'] = net_pct
                            break
            except:
                pass

        except Exception as e:
            # Fallback to small random drift if metrics fail
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

        img = Image.new('RGBA', (WIDTH, HEIGHT), (8, 8, 12, 255))
        draw = ImageDraw.Draw(img)

        pulse = (math.sin(self._pulse_phase) + 1) / 2
        sweep = self.sweep_angle
        cube_ang = self.cube_angle

        if self._mode == FallbackMode.OFFLINE:
            # Original simple concentric radar for OFFLINE
            self._draw_offline_radar(draw, sweep, pulse)
        else:
            # Flashy version with cube for ONLINE/CONNECTING/COMMUNICATING
            self._draw_rings(draw, pulse)
            self._draw_arcs(draw, pulse)
            self._draw_sweep(draw, sweep, pulse)

            if self._mode in (FallbackMode.ONLINE, FallbackMode.COMMUNICATING):
                self._draw_cube(draw, cube_ang, pulse, show_icons=True)
            elif self._mode == FallbackMode.CONNECTING:
                self._draw_cube(draw, cube_ang, pulse, show_icons=False)

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

    def _draw_offline_radar(self, draw, sweep, pulse):
        """Draw radar with 2.5D depth effect - shadows and highlights."""
        # Ring backgrounds with inset shadow effect
        for m in MODULES:
            r = m['r']
            # Outer shadow (darker, offset down-right)
            draw.ellipse([CENTER - r + 2, CENTER - r + 2, CENTER + r + 2, CENTER + r + 2],
                        outline=(10, 10, 15), width=RING_WIDTH + 2)
            # Inner highlight (lighter, offset up-left)
            draw.ellipse([CENTER - r - 1, CENTER - r - 1, CENTER + r - 1, CENTER + r - 1],
                        outline=(40, 40, 50), width=RING_WIDTH)
            # Main groove
            draw.ellipse([CENTER - r, CENTER - r, CENTER + r, CENTER + r],
                        outline=(20, 20, 28), width=RING_WIDTH)

        # Light source position from sweep angle
        light_x = math.sin(sweep)
        light_y = -math.cos(sweep)

        # Balanced arcs with dynamic lighting from sweep
        for m in MODULES:
            r = m['r']
            color = m['color']
            value = self._values[m['name']]

            arc_extent = (value / 100) * 360
            half = arc_extent / 2
            start = 90 + half
            end = 90 - half

            # Shadow offset based on light direction (opposite of light)
            shadow_ox = int(-light_x * 3)
            shadow_oy = int(-light_y * 3)

            # Highlight offset (toward light)
            highlight_ox = int(light_x * 2)
            highlight_oy = int(light_y * 2)

            # Shadow layer (opposite to light source)
            shadow = (color[0]//4, color[1]//4, color[2]//4)
            draw.arc([CENTER - r + shadow_ox, CENTER - r + shadow_oy,
                     CENTER + r + shadow_ox, CENTER + r + shadow_oy],
                    end, start, fill=shadow, width=RING_WIDTH - 2)

            # Main arc body
            draw.arc([CENTER - r, CENTER - r, CENTER + r, CENTER + r],
                    end, start, fill=color, width=RING_WIDTH - 4)

            # Highlight layer (toward light source)
            highlight = (min(255, color[0] + 100), min(255, color[1] + 100), min(255, color[2] + 100))
            draw.arc([CENTER - r + highlight_ox, CENTER - r + highlight_oy,
                     CENTER + r + highlight_ox, CENTER + r + highlight_oy],
                    end, start, fill=highlight, width=3)

            # Dynamic specular at arc tips
            for angle_deg in [90 - half, 90 + half]:
                angle_rad = math.radians(angle_deg)
                x = CENTER + r * math.cos(angle_rad)
                y = CENTER - r * math.sin(angle_rad)

                # Calculate how lit this point is (dot product with light direction)
                point_x = math.cos(angle_rad)
                point_y = -math.sin(angle_rad)
                light_intensity = max(0, point_x * light_x + point_y * light_y)

                # Shadow (away from light)
                draw.ellipse([x - shadow_ox - 2, y - shadow_oy - 2,
                             x - shadow_ox + 4, y - shadow_oy + 4], fill=shadow)
                # Main dot
                draw.ellipse([x-3, y-3, x+3, y+3], fill=color)
                # Specular highlight (stronger when facing light)
                spec_alpha = int(100 + light_intensity * 155)
                draw.ellipse([x + highlight_ox - 2, y + highlight_oy - 2,
                             x + highlight_ox + 1, y + highlight_oy + 1],
                            fill=(255, 255, 255, spec_alpha))

        # Rainbow sweep line with 3D effect
        max_r = MODULES[0]['r'] + 15
        min_r = MODULES[-1]['r'] - 15

        # Rainbow trail with shadow
        for i in range(25):
            offset = -0.2 * (i / 25)
            a = sweep + offset
            hue = ((a + offset) / (2 * math.pi)) % 1.0
            rc, gc, bc = colorsys.hsv_to_rgb(hue, 0.9, 1.0)
            alpha = int(220 * (1 - i / 25))

            x1 = CENTER + min_r * math.sin(a)
            y1 = CENTER - min_r * math.cos(a)
            x2 = CENTER + max_r * math.sin(a)
            y2 = CENTER - max_r * math.cos(a)

            # Shadow
            draw.line([(x1+2, y1+2), (x2+2, y2+2)], fill=(10, 10, 15, alpha//2), width=4)
            # Main color
            draw.line([(x1, y1), (x2, y2)], fill=(int(rc*255), int(gc*255), int(bc*255), alpha), width=3)

        # Main sweep line with 3D raised effect
        x1 = CENTER + min_r * math.sin(sweep)
        y1 = CENTER - min_r * math.cos(sweep)
        x2 = CENTER + max_r * math.sin(sweep)
        y2 = CENTER - max_r * math.cos(sweep)
        # Shadow
        draw.line([(x1+2, y1+2), (x2+2, y2+2)], fill=(20, 20, 30), width=6)
        # Main white
        draw.line([(x1, y1), (x2, y2)], fill=(220, 220, 230), width=4)
        # Highlight
        draw.line([(x1-1, y1-1), (x2-1, y2-1)], fill=(255, 255, 255), width=2)

        # Rainbow dots at rings with 3D sphere effect
        for m in MODULES:
            r = m['r']
            x = CENTER + r * math.sin(sweep)
            y = CENTER - r * math.cos(sweep)
            hue = (sweep / (2 * math.pi)) % 1.0
            rc, gc, bc = colorsys.hsv_to_rgb(hue, 1.0, 1.0)
            base_color = (int(rc*255), int(gc*255), int(bc*255))
            dark_color = (int(rc*128), int(gc*128), int(bc*128))

            # Shadow
            draw.ellipse([x-4, y-4, x+8, y+8], fill=(10, 10, 15))
            # Base sphere
            draw.ellipse([x-6, y-6, x+6, y+6], fill=base_color)
            # Highlight crescent
            draw.ellipse([x-5, y-5, x+2, y+2], fill=(255, 255, 255, 150))

        # Center hub with 3D inset effect
        inner_r = 55
        # Outer shadow ring
        draw.ellipse([CENTER - inner_r + 3, CENTER - inner_r + 3,
                     CENTER + inner_r + 3, CENTER + inner_r + 3],
                    fill=(5, 5, 10))
        # Main hub
        draw.ellipse([CENTER - inner_r, CENTER - inner_r,
                     CENTER + inner_r, CENTER + inner_r],
                    fill=(15, 15, 25))
        # Inner highlight ring
        draw.ellipse([CENTER - inner_r + 4, CENTER - inner_r + 4,
                     CENTER + inner_r - 4, CENTER + inner_r - 4],
                    outline=(50, 50, 65), width=2)
        # Glossy top edge
        draw.arc([CENTER - inner_r, CENTER - inner_r,
                 CENTER + inner_r, CENTER + inner_r],
                200, 340, fill=(60, 60, 80), width=3)

        # Rotating accent dots with 3D
        hue = (sweep / (2 * math.pi)) % 1.0
        rc, gc, bc = colorsys.hsv_to_rgb(hue, 0.9, 0.9)
        accent = (int(rc * 255), int(gc * 255), int(bc * 255))
        for deg in range(0, 360, 30):
            angle = math.radians(deg) + sweep
            x = CENTER + 42 * math.sin(angle)
            y = CENTER - 42 * math.cos(angle)
            # Shadow
            draw.ellipse([x, y, x+4, y+4], fill=(10, 10, 15))
            # Dot
            draw.ellipse([x-2, y-2, x+2, y+2], fill=accent)
            # Highlight
            draw.ellipse([x-1, y-1, x+1, y+1], fill=(255, 255, 255, 100))

        # Time display with shadow
        draw.text((CENTER - 34, CENTER - 19), "SECUBOX", fill=(30, 30, 40))  # Shadow
        draw.text((CENTER - 35, CENTER - 20), "SECUBOX", fill=(200, 200, 210))
        draw.text((CENTER - 21, CENTER + 1), time.strftime("%H:%M"), fill=(30, 30, 40))  # Shadow
        draw.text((CENTER - 22, CENTER), time.strftime("%H:%M"), fill=accent)

        # Status LED with 3D glass effect
        max_val = max(self._values.values())
        if max_val > 85:
            status_color = (255, 60, 60)
        elif max_val > 70:
            status_color = (255, 180, 0)
        else:
            status_color = (0, 220, 100)

        # LED shadow
        draw.ellipse([CENTER - 3, CENTER + 22, CENTER + 9, CENTER + 34], fill=(10, 10, 15))
        # LED base
        draw.ellipse([CENTER - 6, CENTER + 18, CENTER + 6, CENTER + 30], fill=status_color)
        # LED highlight
        draw.ellipse([CENTER - 4, CENTER + 20, CENTER + 1, CENTER + 25], fill=(255, 255, 255, 150))

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
