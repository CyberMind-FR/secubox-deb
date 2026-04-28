#!/usr/bin/env python3
"""
SecuBox Eye Remote - First Boot Sensor Dashboard

Multi-layer, multi-color animated sensor visualization.
Detects touch noise during first boot and auto-disables touchpad if noisy.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import time
import math
import random
import colorsys
import struct
from pathlib import Path
from typing import Optional, List, Tuple
from PIL import Image, ImageDraw, ImageFilter

WIDTH = HEIGHT = 480
CENTER = 240

# Touch I2C settings
I2C_BUS = 11
I2C_ADDR = 0x15

# Noise detection settings
NOISE_SAMPLE_TIME = 5.0  # seconds to collect samples
NOISE_THRESHOLD = 50     # max samples before considered noisy
X_STABLE_RANGE = 20      # X delta must be within this range for noise

# Sensor layers with funky colors
SENSOR_LAYERS = [
    {'name': 'THERMAL', 'color': (255, 60, 30), 'r': 210, 'speed': 1.2},
    {'name': 'MAGNETIC', 'color': (30, 200, 255), 'r': 185, 'speed': -0.8},
    {'name': 'ACOUSTIC', 'color': (255, 200, 0), 'r': 160, 'speed': 1.5},
    {'name': 'PHOTONIC', 'color': (200, 50, 255), 'r': 135, 'speed': -1.0},
    {'name': 'QUANTUM', 'color': (50, 255, 150), 'r': 110, 'speed': 2.0},
    {'name': 'NEURAL', 'color': (255, 100, 200), 'r': 85, 'speed': -1.8},
]

# Marker file for touchpad state
TOUCHPAD_DISABLED_FLAG = Path("/etc/secubox/eye-remote/.touchpad_disabled")
FIRSTBOOT_DONE_FLAG = Path("/etc/secubox/eye-remote/.firstboot_done")


class FirstBootSensor:
    """Multi-layer animated sensor dashboard with noise detection."""

    def __init__(self):
        self._start_time = time.time()
        self._phase = 0
        self._layer_values = [random.random() * 0.5 + 0.3 for _ in SENSOR_LAYERS]
        self._particles: List[dict] = []
        self._noise_samples: List[Tuple[int, int]] = []
        self._touch_enabled = True
        self._noise_detected = False
        self._calibration_phase = True
        self._calibration_start = time.time()
        self._bus = None
        self._init_touch()

    def _init_touch(self):
        """Initialize I2C touch controller."""
        try:
            import smbus2
            self._bus = smbus2.SMBus(I2C_BUS)
        except Exception as e:
            print(f"Touch init failed: {e}")
            self._bus = None

    def _read_touch(self) -> Optional[Tuple[int, int]]:
        """Read raw touch coordinates."""
        if self._bus is None:
            return None
        try:
            count = self._bus.read_byte_data(I2C_ADDR, 0x02)
            if count > 0:
                data = self._bus.read_i2c_block_data(I2C_ADDR, 0x03, 6)
                data[0] &= 0x0f
                data[2] &= 0x0f
                tx, ty, _, _ = struct.unpack(">HHBB", bytes(data))
                return (tx, ty)
        except Exception:
            pass
        return None

    def _check_noise(self) -> bool:
        """Analyze collected samples for noise pattern."""
        if len(self._noise_samples) < 10:
            return False

        # Check for X-stable noise pattern (Y oscillates, X stays same)
        xs = [s[0] for s in self._noise_samples]
        x_range = max(xs) - min(xs)

        if x_range < X_STABLE_RANGE and len(self._noise_samples) > NOISE_THRESHOLD:
            return True  # Noise detected: many samples with stable X

        return False

    def _disable_touchpad(self):
        """Disable touchpad and create marker file."""
        self._touch_enabled = False
        self._noise_detected = True
        try:
            TOUCHPAD_DISABLED_FLAG.parent.mkdir(parents=True, exist_ok=True)
            TOUCHPAD_DISABLED_FLAG.write_text(f"disabled={time.time()}\nsamples={len(self._noise_samples)}")
        except Exception as e:
            print(f"Failed to create flag: {e}")

    def _spawn_particle(self, layer_idx: int):
        """Spawn a particle on a sensor layer."""
        layer = SENSOR_LAYERS[layer_idx]
        angle = random.random() * 2 * math.pi
        self._particles.append({
            'layer': layer_idx,
            'angle': angle,
            'r': layer['r'],
            'life': 1.0,
            'speed': layer['speed'] * 0.5,
            'size': random.randint(3, 8),
        })

    def update(self):
        """Update sensor values and check for noise during calibration."""
        self._phase += 0.08
        elapsed = time.time() - self._start_time

        # Update layer values with organic motion
        for i in range(len(self._layer_values)):
            noise = math.sin(elapsed * SENSOR_LAYERS[i]['speed'] + i * 0.7)
            self._layer_values[i] = 0.5 + noise * 0.35 + random.random() * 0.05
            self._layer_values[i] = max(0.1, min(0.95, self._layer_values[i]))

        # Spawn particles randomly
        if random.random() < 0.15:
            self._spawn_particle(random.randint(0, len(SENSOR_LAYERS) - 1))

        # Update particles
        for p in self._particles:
            p['angle'] += p['speed'] * 0.02
            p['life'] -= 0.02
        self._particles = [p for p in self._particles if p['life'] > 0]

        # Calibration phase: collect touch samples
        if self._calibration_phase:
            calib_elapsed = time.time() - self._calibration_start
            if calib_elapsed < NOISE_SAMPLE_TIME:
                touch = self._read_touch()
                if touch:
                    self._noise_samples.append(touch)
            else:
                # Calibration done, check for noise
                if self._check_noise():
                    self._disable_touchpad()
                self._calibration_phase = False
                # Mark first boot done
                try:
                    FIRSTBOOT_DONE_FLAG.parent.mkdir(parents=True, exist_ok=True)
                    FIRSTBOOT_DONE_FLAG.write_text(f"done={time.time()}")
                except Exception:
                    pass

    def render(self) -> Image.Image:
        """Render the multi-layer sensor dashboard."""
        self.update()
        elapsed = time.time() - self._start_time
        pulse = (math.sin(self._phase) + 1) / 2

        img = Image.new('RGBA', (WIDTH, HEIGHT), (5, 5, 15, 255))
        draw = ImageDraw.Draw(img)

        # Draw rotating background grid
        self._draw_grid(draw, elapsed)

        # Draw sensor layers
        for i, layer in enumerate(SENSOR_LAYERS):
            self._draw_sensor_layer(draw, layer, self._layer_values[i], elapsed, pulse)

        # Draw particles
        self._draw_particles(draw, elapsed)

        # Draw center core
        self._draw_core(draw, elapsed, pulse)

        # Draw status
        self._draw_status(draw, pulse)

        return img

    def _draw_grid(self, draw, elapsed):
        """Draw rotating hexagonal grid background."""
        rotation = elapsed * 0.1
        for ring in range(1, 8):
            r = ring * 35
            sides = 6
            for i in range(sides):
                angle1 = rotation + (i / sides) * 2 * math.pi
                angle2 = rotation + ((i + 1) / sides) * 2 * math.pi
                x1 = CENTER + r * math.cos(angle1)
                y1 = CENTER + r * math.sin(angle1)
                x2 = CENTER + r * math.cos(angle2)
                y2 = CENTER + r * math.sin(angle2)
                alpha = int(30 + 20 * math.sin(elapsed + ring * 0.3))
                draw.line([(x1, y1), (x2, y2)], fill=(40, 40, 60, alpha), width=1)

    def _draw_sensor_layer(self, draw, layer, value, elapsed, pulse):
        """Draw a single sensor layer ring with arc."""
        r = layer['r']
        color = layer['color']
        speed = layer['speed']

        # Rotating offset
        offset = elapsed * speed * 0.5

        # Background ring glow
        glow_alpha = int(40 + pulse * 30)
        draw.ellipse([CENTER - r - 3, CENTER - r - 3, CENTER + r + 3, CENTER + r + 3],
                    outline=(color[0]//4, color[1]//4, color[2]//4, glow_alpha), width=8)

        # Dark ring background
        draw.ellipse([CENTER - r, CENTER - r, CENTER + r, CENTER + r],
                    outline=(20, 20, 30), width=20)

        # Value arc (rotating)
        arc_extent = value * 300  # up to 300 degrees
        start = math.degrees(offset) - arc_extent / 2
        end = math.degrees(offset) + arc_extent / 2

        # Glow arc
        for glow in range(3):
            glow_color = (color[0], color[1], color[2], int(150 - glow * 40))
            draw.arc([CENTER - r - glow, CENTER - r - glow, CENTER + r + glow, CENTER + r + glow],
                    start, end, fill=glow_color, width=18 - glow * 2)

        # Main arc
        draw.arc([CENTER - r, CENTER - r, CENTER + r, CENTER + r],
                start, end, fill=color, width=16)

        # Arc head dot
        head_angle = math.radians(end)
        hx = CENTER + r * math.cos(head_angle)
        hy = CENTER + r * math.sin(head_angle)
        dot_size = 6 + pulse * 3
        draw.ellipse([hx - dot_size, hy - dot_size, hx + dot_size, hy + dot_size],
                    fill=(255, 255, 255))

    def _draw_particles(self, draw, elapsed):
        """Draw floating particles on layers."""
        for p in self._particles:
            layer = SENSOR_LAYERS[p['layer']]
            x = CENTER + p['r'] * math.cos(p['angle'])
            y = CENTER + p['r'] * math.sin(p['angle'])
            alpha = int(p['life'] * 200)
            size = p['size'] * p['life']
            color = (layer['color'][0], layer['color'][1], layer['color'][2], alpha)
            draw.ellipse([x - size, y - size, x + size, y + size], fill=color)

    def _draw_core(self, draw, elapsed, pulse):
        """Draw the animated center core."""
        # Pulsing inner circle
        inner_r = 50 + pulse * 5

        # Rainbow gradient core
        for i in range(int(inner_r), 0, -2):
            hue = (elapsed * 0.1 + i * 0.01) % 1.0
            r, g, b = colorsys.hsv_to_rgb(hue, 0.8, 0.9)
            alpha = int(150 * (i / inner_r))
            color = (int(r * 255), int(g * 255), int(b * 255), alpha)
            draw.ellipse([CENTER - i, CENTER - i, CENTER + i, CENTER + i], fill=color)

        # Center eye
        draw.ellipse([CENTER - 20, CENTER - 20, CENTER + 20, CENTER + 20],
                    fill=(10, 10, 20), outline=(100, 100, 120), width=2)

        # Pupil that follows time
        px = CENTER + math.sin(elapsed * 0.5) * 8
        py = CENTER + math.cos(elapsed * 0.7) * 8
        draw.ellipse([px - 8, py - 8, px + 8, py + 8], fill=(200, 200, 220))
        draw.ellipse([px - 4, py - 4, px + 4, py + 4], fill=(20, 20, 30))

    def _draw_status(self, draw, pulse):
        """Draw status text and calibration progress."""
        # Title
        draw.text((CENTER - 60, 15), "SENSOR MATRIX", fill=(200, 200, 220))

        # Calibration status
        if self._calibration_phase:
            calib_elapsed = time.time() - self._calibration_start
            progress = min(1.0, calib_elapsed / NOISE_SAMPLE_TIME)
            bar_width = 200
            bar_x = CENTER - bar_width // 2
            bar_y = 440

            # Progress bar background
            draw.rectangle([bar_x, bar_y, bar_x + bar_width, bar_y + 10],
                          fill=(30, 30, 40), outline=(60, 60, 80))

            # Progress bar fill
            fill_width = int(bar_width * progress)
            draw.rectangle([bar_x, bar_y, bar_x + fill_width, bar_y + 10],
                          fill=(100, 200, 255))

            # Status text
            samples_text = f"Calibrating... {len(self._noise_samples)} samples"
            draw.text((CENTER - 70, 420), samples_text, fill=(150, 150, 180))

        elif self._noise_detected:
            # Noise warning
            alpha = int(200 + pulse * 55)
            draw.text((CENTER - 70, 430), "TOUCHPAD DISABLED", fill=(255, 80, 80, alpha))
            draw.text((CENTER - 55, 450), "(noise detected)", fill=(150, 100, 100))

        else:
            # Normal status
            draw.text((CENTER - 35, 450), "SECUBOX", fill=(100, 100, 120))

        # Layer labels (around the edge)
        for i, layer in enumerate(SENSOR_LAYERS):
            angle = (i / len(SENSOR_LAYERS)) * 2 * math.pi - math.pi / 2
            lx = CENTER + 230 * math.cos(angle) - 20
            ly = CENTER + 230 * math.sin(angle) - 6
            val_pct = int(self._layer_values[i] * 100)
            draw.text((lx, ly), f"{layer['name'][:4]}", fill=layer['color'])


def run_firstboot_sensor():
    """Run the first boot sensor dashboard."""
    # Check if already done first boot
    if FIRSTBOOT_DONE_FLAG.exists():
        print("First boot already completed, skipping sensor calibration")
        return

    print("SecuBox Eye Remote - First Boot Sensor Calibration")
    print(f"Collecting touch samples for {NOISE_SAMPLE_TIME}s...")

    sensor = FirstBootSensor()

    try:
        while True:
            img = sensor.render()
            rgba = img.convert('RGBA')
            with open('/dev/fb0', 'wb') as fb:
                fb.write(rgba.tobytes('raw', 'BGRA'))
            time.sleep(0.033)  # 30 FPS

            # Exit after calibration if touch is disabled
            if not sensor._calibration_phase and sensor._noise_detected:
                time.sleep(3)  # Show message for 3 seconds
                break

            # Exit after calibration if touch is OK
            if not sensor._calibration_phase and not sensor._noise_detected:
                time.sleep(2)  # Brief pause
                break

    except KeyboardInterrupt:
        pass
    finally:
        if sensor._bus:
            sensor._bus.close()

    if sensor._noise_detected:
        print(f"Noise detected! Touchpad disabled. Samples: {len(sensor._noise_samples)}")
    else:
        print(f"Calibration OK. Samples: {len(sensor._noise_samples)}")


if __name__ == "__main__":
    run_firstboot_sensor()
