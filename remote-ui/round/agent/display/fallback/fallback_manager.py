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
from pathlib import Path
from enum import Enum
from typing import Optional, Tuple, List
from PIL import Image, ImageDraw, ImageFilter, ImageEnhance

WIDTH = HEIGHT = 480
CENTER = 240


class FallbackMode(Enum):
    OFFLINE = "offline"           # No connection - local metrics
    CONNECTING = "connecting"     # Trying to connect - dice animation
    ONLINE = "online"             # Connected - full dashboard
    COMMUNICATING = "comm"        # Active transfer - fast dice


# Flashy module colors - thinner rings, larger center
MODULES = [
    {'name': 'AUTH', 'color': (255, 80, 40),   'r': 220, 'glow': (255, 120, 80)},
    {'name': 'WALL', 'color': (255, 160, 20),  'r': 200, 'glow': (255, 200, 60)},
    {'name': 'BOOT', 'color': (255, 60, 100),  'r': 180, 'glow': (255, 100, 140)},
    {'name': 'MIND', 'color': (120, 80, 255),  'r': 160, 'glow': (160, 120, 255)},
    {'name': 'ROOT', 'color': (0, 255, 120),   'r': 140, 'glow': (80, 255, 160)},
    {'name': 'MESH', 'color': (0, 180, 255),   'r': 120, 'glow': (80, 220, 255)},
]

RING_WIDTH = 14

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


# Logo paths
LOGO_PATHS = [
    Path("/tmp/assets/splash/phoenix_logo.png"),
    Path("/etc/secubox/eye-remote/assets/phoenix_logo.png"),
]

# Icon paths - module icons
ICON_PATHS = [
    Path("/tmp/assets/icons"),
    Path("/etc/secubox/eye-remote/assets/icons"),
    Path(__file__).parent.parent.parent.parent / "assets" / "icons",
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
        self._logo: Optional[Image.Image] = None
        self._logo_dark: Optional[Image.Image] = None
        self._icons: dict = {}  # Module icons
        self._load_logo()
        self._load_icons()

    def _load_logo(self):
        """Load and prepare logo as dark background."""
        for path in LOGO_PATHS:
            try:
                if path.exists():
                    logo = Image.open(path).convert('RGBA')
                    # Resize to fill screen
                    logo = logo.resize((400, 400), Image.Resampling.LANCZOS)
                    # Darken significantly for background
                    enhancer = ImageEnhance.Brightness(logo)
                    self._logo = logo
                    self._logo_dark = enhancer.enhance(0.15)  # 15% brightness
                    print(f"Logo loaded from {path}")
                    return
            except Exception as e:
                print(f"Logo load error: {e}")

    def _load_icons(self):
        """Load module icons (48px for center and cube)."""
        icon_names = ['auth', 'wall', 'boot', 'mind', 'root', 'mesh']
        for icon_dir in ICON_PATHS:
            if not icon_dir.exists():
                continue
            try:
                for name in icon_names:
                    # Load 48px icons
                    path_48 = icon_dir / f"{name}-48.png"
                    if path_48.exists() and name not in self._icons:
                        img = Image.open(path_48).convert('RGBA')
                        self._icons[name] = img
                        print(f"Loaded icon: {name}")
                if len(self._icons) == 6:
                    print("All icons loaded")
                    return
            except Exception as e:
                print(f"Icon load error: {e}")

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

        # Add logo as dark background
        if self._logo_dark:
            logo_pos = (CENTER - 200, CENTER - 200)
            img.paste(self._logo_dark, logo_pos, self._logo_dark)

        draw = ImageDraw.Draw(img)

        pulse = (math.sin(self._pulse_phase) + 1) / 2
        sweep = self.sweep_angle
        cube_ang = self.cube_angle

        # Radar for all modes
        self._draw_offline_radar(draw, sweep, pulse)

        # OFFLINE: show single cycling icon, ONLINE: show all icons
        if self._mode == FallbackMode.OFFLINE:
            self._draw_center_icons(draw, sweep, pulse, single_mode=True)
        elif self._mode in (FallbackMode.ONLINE, FallbackMode.COMMUNICATING, FallbackMode.CONNECTING):
            self._draw_center_icons(draw, sweep, pulse, single_mode=False)

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

    def _draw_center_icons(self, draw, sweep, pulse, single_mode=False):
        """Draw 6 module icons in hexagon - with 48px PNG icons, static position.

        If single_mode=True, only show one icon at a time (cycling).
        """
        icon_r = 62  # Radius for icon placement (further from center)
        icon_names = ['auth', 'wall', 'boot', 'mind', 'root', 'mesh']

        # Determine which icon to show in single mode (cycle every 2 seconds)
        if single_mode:
            cycle_index = int(time.time() / 2) % 6
        else:
            cycle_index = -1  # Show all

        # 6 icons in hexagon - static, no rotation
        for i, m in enumerate(MODULES):
            # In single mode, only draw the current cycling icon
            if single_mode and i != cycle_index:
                continue

            angle = -math.pi/2 + (i / 6) * 2 * math.pi  # Fixed position
            ix = int(CENTER + icon_r * math.cos(angle))
            iy = int(CENTER + icon_r * math.sin(angle))

            name = icon_names[i]
            if name in self._icons:
                # Draw 48px PNG icon (centered)
                icon = self._icons[name]
                pos = (ix - 24, iy - 24)  # 48/2 = 24
                img = draw._image
                img.paste(icon, pos, icon)
            else:
                # Fallback to letter
                bg = (m['color'][0]//3, m['color'][1]//3, m['color'][2]//3)
                draw.ellipse([ix - 20, iy - 20, ix + 20, iy + 20], fill=bg)
                draw.text((ix - 8, iy - 10), m['name'][0], fill=m['color'])

    def _draw_cube(self, draw, angle, pulse, show_icons=True):
        """Draw simple 3D rotating cube with PNG icons."""
        ax = angle * 0.7
        ay = angle
        az = angle * 0.3

        transformed = [self.rotate_point(*v, ax, ay, az) for v in CUBE_VERTICES]

        # Sort faces by depth
        face_depths = [(sum(transformed[v][2] for v in f) / 4, i, f)
                       for i, f in enumerate(CUBE_FACES)]
        face_depths.sort(key=lambda x: x[0])

        icon_names = ['auth', 'wall', 'boot', 'mind', 'root', 'mesh']

        for depth, i, face in face_depths:
            points = [self.project_3d(*transformed[v], scale=28) for v in face]
            base = MODULES[i % 6]['color']

            # Simple depth-based shading
            shade = min(1.2, max(0.4, 0.5 + (depth + 1) * 0.35))
            fill = (
                int(base[0] * shade),
                int(base[1] * shade),
                int(base[2] * shade)
            )

            draw.polygon(points, fill=fill, outline=(50, 50, 60))

            # Icon on visible faces (48px icons)
            if show_icons and depth > -0.3:
                cx = sum(p[0] for p in points) // 4
                cy = sum(p[1] for p in points) // 4
                name = icon_names[i % 6]
                if name in self._icons:
                    icon = self._icons[name]
                    img = draw._image
                    img.paste(icon, (cx - 24, cy - 24), icon)  # 48/2 = 24
                else:
                    draw.text((cx - 8, cy - 10), MODULES[i % 6]['name'][0], fill=(255, 255, 255))

        # Edges
        for e in CUBE_EDGES:
            p1 = self.project_3d(*transformed[e[0]], scale=28)
            p2 = self.project_3d(*transformed[e[1]], scale=28)
            draw.line([p1, p2], fill=(90, 90, 110), width=1)

    def _draw_offline_center(self, draw, pulse):
        """Draw simple center when offline - clean, no text."""
        inner_r = 55
        draw.ellipse([CENTER - inner_r, CENTER - inner_r,
                     CENTER + inner_r, CENTER + inner_r],
                    fill=(12, 12, 22), outline=(50, 50, 60), width=2)

    def _draw_offline_radar(self, draw, sweep, pulse):
        """Draw clean radar - no shadows, no dots, just fast and clean."""
        # Ring backgrounds - solid colors
        for m in MODULES:
            r = m['r']
            draw.ellipse([CENTER - r, CENTER - r, CENTER + r, CENTER + r],
                        outline=(20, 20, 28), width=RING_WIDTH)

        # Tube-style arcs - darker outside, lighter inside
        for m in MODULES:
            r = m['r']
            color = m['color']
            value = self._values[m['name']]

            arc_extent = (value / 100) * 360
            half = arc_extent / 2
            start = 90 + half
            end = 90 - half

            # Outer dark edge
            dark = (color[0]//3, color[1]//3, color[2]//3)
            draw.arc([CENTER - r - 2, CENTER - r - 2, CENTER + r + 2, CENTER + r + 2],
                    end, start, fill=dark, width=RING_WIDTH - 2)

            # Main color
            draw.arc([CENTER - r, CENTER - r, CENTER + r, CENTER + r],
                    end, start, fill=color, width=RING_WIDTH - 6)

            # Inner light center (tube highlight)
            light = (min(255, color[0] + 80), min(255, color[1] + 80), min(255, color[2] + 80))
            draw.arc([CENTER - r + 2, CENTER - r + 2, CENTER + r - 2, CENTER + r - 2],
                    end, start, fill=light, width=4)

        # Sweep line - each segment colored by the ring it crosses
        max_r = MODULES[0]['r'] + 8
        min_r = MODULES[-1]['r'] - 8

        # Draw sweep segments per ring - each colored by that ring's metric
        for idx, m in enumerate(MODULES):
            r = m['r']
            color = m['color']
            value = self._values[m['name']] / 100.0

            # Segment bounds
            if idx == 0:
                r_outer = max_r
            else:
                r_outer = (MODULES[idx-1]['r'] + r) // 2
            if idx == len(MODULES) - 1:
                r_inner = min_r
            else:
                r_inner = (r + MODULES[idx+1]['r']) // 2

            # Trail for this segment
            for i in range(15):
                offset = -0.15 * (i / 15)
                a = sweep + offset
                fade = 1 - i / 15

                x1 = CENTER + r_inner * math.sin(a)
                y1 = CENTER - r_inner * math.cos(a)
                x2 = CENTER + r_outer * math.sin(a)
                y2 = CENTER - r_outer * math.cos(a)

                # Color intensity based on metric value
                intensity = 0.5 + value * 0.5
                seg_color = (
                    int(color[0] * fade * intensity),
                    int(color[1] * fade * intensity),
                    int(color[2] * fade * intensity)
                )
                draw.line([(x1, y1), (x2, y2)], fill=seg_color, width=2)

            # Main sweep segment
            x1 = CENTER + r_inner * math.sin(sweep)
            y1 = CENTER - r_inner * math.cos(sweep)
            x2 = CENTER + r_outer * math.sin(sweep)
            y2 = CENTER - r_outer * math.cos(sweep)
            bright = (min(255, color[0] + 60), min(255, color[1] + 60), min(255, color[2] + 60))
            draw.line([(x1, y1), (x2, y2)], fill=bright, width=3)

        # Sweep head dot - color of outermost ring
        head_color = MODULES[0]['color']

        outer_r = MODULES[0]['r']
        hx = CENTER + outer_r * math.sin(sweep)
        hy = CENTER - outer_r * math.cos(sweep)
        draw.ellipse([hx-4, hy-4, hx+4, hy+4], fill=head_color)

        # Clean center hub - larger
        inner_r = 85
        draw.ellipse([CENTER - inner_r, CENTER - inner_r,
                     CENTER + inner_r, CENTER + inner_r],
                    fill=(12, 12, 22))

        # Center is left clean for icons (no text)

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

    # Hide cursor on framebuffer console
    try:
        with open('/sys/class/graphics/fbcon/cursor_blink', 'w') as f:
            f.write('0')
    except:
        pass
    try:
        # Also try via escape sequence
        import sys
        sys.stdout.write('\033[?25l')
        sys.stdout.flush()
    except:
        pass

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
