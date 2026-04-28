#!/usr/bin/env python3
"""
SecuBox Radar - Flashy Edition with Rotating Cube
- Vibrant flashy module colors
- 3D rotating cube in center with module icons
- Pulsing glow effects
- Original concentric balanced metrics
"""
import time
import math
import random
import colorsys
from PIL import Image, ImageDraw

WIDTH = HEIGHT = 480
CENTER = 240

# Flashy vibrant colors (saturated versions)
MODULES = [
    {'name': 'AUTH', 'color': (255, 80, 40),   'r': 214, 'icon': 'A', 'glow': (255, 120, 80)},
    {'name': 'WALL', 'color': (255, 160, 20),  'r': 188, 'icon': 'W', 'glow': (255, 200, 60)},
    {'name': 'BOOT', 'color': (255, 60, 100),  'r': 162, 'icon': 'B', 'glow': (255, 100, 140)},
    {'name': 'MIND', 'color': (120, 80, 255),  'r': 136, 'icon': 'M', 'glow': (160, 120, 255)},
    {'name': 'ROOT', 'color': (0, 255, 120),   'r': 110, 'icon': 'R', 'glow': (80, 255, 160)},
    {'name': 'MESH', 'color': (0, 180, 255),   'r': 84,  'icon': 'X', 'glow': (80, 220, 255)},
]

RING_WIDTH = 22

# 3D Cube vertices (unit cube centered at origin)
CUBE_VERTICES = [
    (-1, -1, -1), (1, -1, -1), (1, 1, -1), (-1, 1, -1),  # back face
    (-1, -1, 1),  (1, -1, 1),  (1, 1, 1),  (-1, 1, 1),   # front face
]

CUBE_EDGES = [
    (0, 1), (1, 2), (2, 3), (3, 0),  # back
    (4, 5), (5, 6), (6, 7), (7, 4),  # front
    (0, 4), (1, 5), (2, 6), (3, 7),  # connecting
]

CUBE_FACES = [
    (0, 1, 2, 3),  # back
    (4, 5, 6, 7),  # front
    (0, 1, 5, 4),  # bottom
    (2, 3, 7, 6),  # top
    (0, 3, 7, 4),  # left
    (1, 2, 6, 5),  # right
]


class FlashyRadar:
    def __init__(self):
        self._start_time = time.time()
        self._sweep_speed = 3.0
        self._cube_speed = 0.8  # rotations per second
        self._values = {m['name']: 50 + random.random() * 30 for m in MODULES}
        self._pulse_phase = 0

    @property
    def sweep_angle(self):
        elapsed = time.time() - self._start_time
        return (elapsed * (self._sweep_speed / 60.0) * 2 * math.pi) % (2 * math.pi)

    @property
    def cube_angle(self):
        elapsed = time.time() - self._start_time
        return elapsed * self._cube_speed * 2 * math.pi

    def update_values(self):
        self._pulse_phase += 0.15
        for m in MODULES:
            name = m['name']
            delta = (random.random() - 0.5) * 3
            self._values[name] = max(20, min(95, self._values[name] + delta))

    def rotate_point(self, x, y, z, angle_x, angle_y, angle_z):
        """Rotate 3D point around all axes"""
        # Rotate around X
        cos_x, sin_x = math.cos(angle_x), math.sin(angle_x)
        y, z = y * cos_x - z * sin_x, y * sin_x + z * cos_x

        # Rotate around Y
        cos_y, sin_y = math.cos(angle_y), math.sin(angle_y)
        x, z = x * cos_y + z * sin_y, -x * sin_y + z * cos_y

        # Rotate around Z
        cos_z, sin_z = math.cos(angle_z), math.sin(angle_z)
        x, y = x * cos_z - y * sin_z, x * sin_z + y * cos_z

        return x, y, z

    def project_3d(self, x, y, z, scale=25):
        """Project 3D point to 2D with perspective"""
        fov = 3.0
        z_offset = 4.0
        factor = fov / (z_offset + z)
        px = CENTER + x * scale * factor
        py = CENTER + y * scale * factor
        return int(px), int(py)

    def render(self):
        self.update_values()
        img = Image.new('RGBA', (WIDTH, HEIGHT), (5, 5, 10, 255))
        draw = ImageDraw.Draw(img)

        sweep_angle = self.sweep_angle
        cube_angle = self.cube_angle
        pulse = (math.sin(self._pulse_phase) + 1) / 2  # 0-1 pulse

        # 1. Draw pulsing background glow
        self._draw_background_glow(draw, pulse)

        # 2. Draw concentric rings with flashy colors
        for m in MODULES:
            self._draw_flashy_ring(draw, m, pulse)

        # 3. Draw balanced metric arcs
        for m in MODULES:
            self._draw_balanced_arc(draw, m, pulse)

        # 4. Draw sweep line
        self._draw_sweep(draw, sweep_angle, pulse)

        # 5. Draw rotating 3D cube in center
        self._draw_rotating_cube(draw, cube_angle, pulse)

        # 6. Draw labels
        self._draw_labels(draw, pulse)

        return img

    def _draw_background_glow(self, draw, pulse):
        """Subtle pulsing background"""
        for r in range(240, 50, -30):
            alpha = int(15 + pulse * 10)
            hue = (r / 240) * 0.3
            rc, gc, bc = colorsys.hsv_to_rgb(hue, 0.5, 0.15)
            draw.ellipse([CENTER - r, CENTER - r, CENTER + r, CENTER + r],
                        fill=(int(rc*255), int(gc*255), int(bc*255), alpha))

    def _draw_flashy_ring(self, draw, module, pulse):
        """Draw ring background with glow"""
        r = module['r']
        glow = module['glow']

        # Outer glow
        glow_intensity = int(40 + pulse * 30)
        draw.ellipse([CENTER - r - 3, CENTER - r - 3, CENTER + r + 3, CENTER + r + 3],
                    outline=(glow[0]//4, glow[1]//4, glow[2]//4, glow_intensity),
                    width=RING_WIDTH + 6)

        # Ring background
        draw.ellipse([CENTER - r, CENTER - r, CENTER + r, CENTER + r],
                    outline=(20, 20, 25), width=RING_WIDTH)

    def _draw_balanced_arc(self, draw, module, pulse):
        """Draw flashy balanced arc"""
        r = module['r']
        color = module['color']
        glow = module['glow']
        value = self._values[module['name']]

        arc_extent = (value / 100) * 360
        half_arc = arc_extent / 2
        pil_start = 90 + half_arc
        pil_end = 90 - half_arc

        # Pulsing glow layers
        for i in range(4):
            glow_alpha = int((200 - i * 40) * (0.7 + pulse * 0.3))
            glow_color = (
                min(255, glow[0]),
                min(255, glow[1]),
                min(255, glow[2]),
                glow_alpha
            )
            offset = i * 3
            bbox = [CENTER - r - offset, CENTER - r - offset,
                   CENTER + r + offset, CENTER + r + offset]
            draw.arc(bbox, pil_end, pil_start, fill=glow_color, width=RING_WIDTH - 2)

        # Main bright arc
        bbox = [CENTER - r, CENTER - r, CENTER + r, CENTER + r]
        bright_color = (
            min(255, int(color[0] * (0.9 + pulse * 0.1))),
            min(255, int(color[1] * (0.9 + pulse * 0.1))),
            min(255, int(color[2] * (0.9 + pulse * 0.1))),
        )
        draw.arc(bbox, pil_end, pil_start, fill=bright_color, width=RING_WIDTH - 4)

        # Bright caps
        for angle_deg in [90 - half_arc, 90 + half_arc]:
            angle_rad = math.radians(angle_deg)
            x = CENTER + r * math.cos(angle_rad)
            y = CENTER - r * math.sin(angle_rad)
            draw.ellipse([x-6, y-6, x+6, y+6], fill=glow)
            draw.ellipse([x-3, y-3, x+3, y+3], fill=(255, 255, 255))

    def _draw_sweep(self, draw, sweep_angle, pulse):
        """Flashy rainbow sweep"""
        max_r = MODULES[0]['r'] + 20
        min_r = MODULES[-1]['r'] - 20

        # Wide rainbow trail
        for i in range(35):
            offset = -0.3 * (i / 35)
            a = sweep_angle + offset

            hue = ((a + offset * 2) / (2 * math.pi)) % 1.0
            sat = 0.9 + pulse * 0.1
            r, g, b = colorsys.hsv_to_rgb(hue, sat, 1.0)
            alpha = int(255 * (1 - i / 35))
            color = (int(r * 255), int(g * 255), int(b * 255), alpha)

            x1 = CENTER + min_r * math.sin(a)
            y1 = CENTER - min_r * math.cos(a)
            x2 = CENTER + max_r * math.sin(a)
            y2 = CENTER - max_r * math.cos(a)

            draw.line([(x1, y1), (x2, y2)], fill=color, width=4)

        # Bright white core
        x1 = CENTER + min_r * math.sin(sweep_angle)
        y1 = CENTER - min_r * math.cos(sweep_angle)
        x2 = CENTER + max_r * math.sin(sweep_angle)
        y2 = CENTER - max_r * math.cos(sweep_angle)
        draw.line([(x1, y1), (x2, y2)], fill=(255, 255, 255), width=5)

        # Sweep head with flare
        hue = (sweep_angle / (2 * math.pi)) % 1.0
        rc, gc, bc = colorsys.hsv_to_rgb(hue, 1.0, 1.0)
        draw.ellipse([x2-12, y2-12, x2+12, y2+12],
                    fill=(int(rc*255)//2, int(gc*255)//2, int(bc*255)//2, 150))
        draw.ellipse([x2-8, y2-8, x2+8, y2+8],
                    fill=(int(rc*255), int(gc*255), int(bc*255)))
        draw.ellipse([x2-4, y2-4, x2+4, y2+4], fill=(255, 255, 255))

    def _draw_rotating_cube(self, draw, cube_angle, pulse):
        """Draw 3D rotating cube with module icons on faces"""
        # Background circle
        inner_r = 55
        draw.ellipse([CENTER - inner_r, CENTER - inner_r,
                     CENTER + inner_r, CENTER + inner_r],
                    fill=(8, 8, 15), outline=(60, 60, 80), width=2)

        # Rotation angles
        ax = cube_angle * 0.7
        ay = cube_angle
        az = cube_angle * 0.3

        # Transform vertices
        transformed = []
        for v in CUBE_VERTICES:
            x, y, z = self.rotate_point(v[0], v[1], v[2], ax, ay, az)
            transformed.append((x, y, z))

        # Calculate face depths for sorting
        face_depths = []
        for i, face in enumerate(CUBE_FACES):
            avg_z = sum(transformed[v][2] for v in face) / 4
            face_depths.append((avg_z, i, face))

        # Sort faces back to front
        face_depths.sort(key=lambda x: x[0])

        # Draw faces
        face_colors = [
            MODULES[0]['color'], MODULES[1]['color'], MODULES[2]['color'],
            MODULES[3]['color'], MODULES[4]['color'], MODULES[5]['color'],
        ]

        for depth, i, face in face_depths:
            points = [self.project_3d(*transformed[v]) for v in face]

            # Face color with depth shading
            base_color = face_colors[i % 6]
            shade = 0.4 + (depth + 1) * 0.3  # depth is -1 to 1
            shade = min(1.0, max(0.3, shade))

            fill_color = (
                int(base_color[0] * shade * (0.8 + pulse * 0.2)),
                int(base_color[1] * shade * (0.8 + pulse * 0.2)),
                int(base_color[2] * shade * (0.8 + pulse * 0.2)),
            )

            draw.polygon(points, fill=fill_color, outline=(255, 255, 255, 100))

            # Draw icon letter on front-facing faces
            if depth > 0:
                cx = sum(p[0] for p in points) // 4
                cy = sum(p[1] for p in points) // 4
                icon = MODULES[i % 6]['icon']
                draw.text((cx - 5, cy - 6), icon, fill=(255, 255, 255))

        # Draw edges
        for e in CUBE_EDGES:
            p1 = self.project_3d(*transformed[e[0]])
            p2 = self.project_3d(*transformed[e[1]])
            draw.line([p1, p2], fill=(255, 255, 255, 200), width=2)

    def _draw_labels(self, draw, pulse):
        """Draw flashy labels"""
        positions = [
            (CENTER - 20, 8),
            (445, CENTER - 60),
            (445, CENTER + 45),
            (CENTER - 20, 455),
            (5, CENTER + 45),
            (5, CENTER - 60),
        ]

        for i, m in enumerate(MODULES):
            x, y = positions[i]
            color = m['glow']
            value = int(self._values[m['name']])

            # Pulsing brightness
            bright = int(180 + pulse * 75)
            text_color = (min(255, color[0]), min(255, color[1]), min(255, color[2]))

            draw.text((x, y), m['name'], fill=text_color)
            draw.text((x, y + 14), f"{value}%", fill=(bright, bright, bright + 20))


def main():
    print("SecuBox Flashy Radar with Rotating Cube")
    radar = FlashyRadar()

    try:
        while True:
            img = radar.render()
            rgba = img.convert('RGBA')
            with open('/dev/fb0', 'wb') as fb:
                fb.write(rgba.tobytes('raw', 'BGRA'))

            time.sleep(0.033)  # 30 FPS

    except KeyboardInterrupt:
        print("\nStopped")


if __name__ == "__main__":
    main()
