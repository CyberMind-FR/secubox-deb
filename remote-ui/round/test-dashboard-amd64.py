#!/usr/bin/env python3
"""
SecuBox Eye Remote — AMD64 Dashboard Tester
Runs the framebuffer dashboard in a window for testing on x86_64.

Uses pygame for display instead of /dev/fb0.
Connect to the gateway emulator (secubox-eye-gateway) for testing.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>

Requirements:
  pip install pygame pillow requests

Usage:
  # Start the gateway emulator first:
  secubox-eye-gateway --profile stressed --port 8765

  # Then run this test:
  python3 test-dashboard-amd64.py --api http://localhost:8765
"""
import os
import sys
import time
import math
import json
import argparse
import socket as sock_module
from datetime import datetime

try:
    import pygame
except ImportError:
    print("pygame required: pip install pygame")
    sys.exit(1)

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("pillow required: pip install pillow")
    sys.exit(1)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("requests not available, using simulation mode")

# Display config
WIDTH = 480
HEIGHT = 480

# Colors (RGB) — Neon theme
BG_COLOR = (8, 8, 12)
TEXT_COLOR = (240, 240, 250)
TEXT_MUTED = (130, 130, 150)
STATUS_OK = (0, 255, 65)
STATUS_WARN = (255, 100, 0)
STATUS_SIM = (100, 100, 120)

# Module colors — Fluorescent/Phosphorescent neon palette
MODULES = {
    'AUTH': {'color': (255, 0, 100), 'metric': 'cpu', 'unit': '%', 'r': 214},
    'WALL': {'color': (255, 100, 0), 'metric': 'mem', 'unit': '%', 'r': 201},
    'BOOT': {'color': (220, 255, 0), 'metric': 'disk', 'unit': '%', 'r': 188},
    'MIND': {'color': (0, 255, 65), 'metric': 'load', 'unit': 'x', 'r': 175},
    'ROOT': {'color': (0, 255, 255), 'metric': 'temp', 'unit': '°', 'r': 162},
    'MESH': {'color': (185, 0, 255), 'metric': 'wifi', 'unit': 'dB', 'r': 149},
}


class APIMetricsSource:
    """Fetch metrics from SecuBox API or gateway emulator."""

    def __init__(self, api_base: str):
        self.api_base = api_base.rstrip('/')
        self.mode = 'API'
        self.host = api_base
        self.device_name = ''
        self._connected = False
        self._probe()

    def _probe(self):
        """Try to connect to API."""
        if not HAS_REQUESTS:
            self.mode = 'SIM'
            return

        try:
            r = requests.get(f'{self.api_base}/api/v1/health', timeout=3)
            if r.status_code == 200:
                data = r.json()
                self.mode = data.get('mode', 'API').upper()
                self.device_name = f"emulator:{data.get('profile', 'normal')}"
                self._connected = True
                print(f'Connected to API at {self.api_base}')
                print(f'  Mode: {self.mode}, Profile: {data.get("profile")}')
                return
        except Exception as e:
            print(f'API probe failed: {e}')

        self.mode = 'SIM'
        print('Using simulation mode')

    def get_metrics(self):
        """Fetch current metrics.

        Returns:
            tuple: (metrics_dict, mode, host, device_name)
        """
        if not self._connected or not HAS_REQUESTS:
            return self._simulate(), 'SIM', '', ''

        try:
            r = requests.get(f'{self.api_base}/api/v1/system/metrics', timeout=3)
            if r.status_code == 200:
                data = r.json()
                return {
                    'cpu': data.get('cpu_percent', 0),
                    'mem': data.get('memory_percent', data.get('mem_percent', 0)),
                    'disk': data.get('disk_percent', 0),
                    'load': data.get('load_avg_1', 0),
                    'temp': data.get('cpu_temp', 0),
                    'wifi': data.get('wifi_rssi', -50),
                    'uptime': data.get('uptime_seconds', 0),
                    'hostname': data.get('hostname', 'secubox'),
                }, self.mode, self.host, self.device_name
        except Exception as e:
            print(f'API error: {e}')

        return self._simulate(), 'SIM', '', ''

    def _simulate(self):
        """Generate simulated metrics."""
        import random
        return {
            'cpu': 25 + random.uniform(-5, 5),
            'mem': 45 + random.uniform(-3, 3),
            'disk': 32 + random.uniform(-1, 1),
            'load': 0.5 + random.uniform(-0.2, 0.2),
            'temp': 42 + random.uniform(-2, 2),
            'wifi': -55 + random.randint(-5, 5),
            'uptime': int(time.time()) % 86400,
            'hostname': 'test-secubox',
        }


def format_uptime(seconds):
    """Format uptime as 'up XhYY'."""
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f'up {hours}h{minutes:02d}'


def draw_dashboard(metrics, mode='SIM', host='', device_name=''):
    """Draw the dashboard to a PIL image."""
    img = Image.new('RGBA', (WIDTH, HEIGHT), BG_COLOR + (255,))
    draw = ImageDraw.Draw(img)

    cx, cy = WIDTH // 2, HEIGHT // 2

    # Load fonts
    try:
        font_large = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 42)
        font_medium = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 18)
        font_small = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 14)
        font_tiny = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 11)
    except:
        font_large = ImageFont.load_default()
        font_medium = font_large
        font_small = font_large
        font_tiny = font_large

    # Draw circular border
    draw.ellipse([10, 10, WIDTH-10, HEIGHT-10], outline=(40, 40, 40), width=2)

    # Draw module rings
    for name, mod in MODULES.items():
        r = mod['r']
        color = mod['color']
        metric_name = mod['metric']
        value = metrics.get(metric_name, 0)

        # Calculate percentage for arc
        if metric_name == 'load':
            pct = min(100, value * 25)
        elif metric_name == 'wifi':
            pct = min(100, max(0, (value + 80) * 2))
        elif metric_name == 'temp':
            pct = min(100, max(0, (value - 30) * 2.5))
        else:
            pct = min(100, max(0, value))

        # Draw background arc
        for angle in range(0, 360, 2):
            rad = math.radians(angle - 90)
            x = cx + r * math.cos(rad)
            y = cy + r * math.sin(rad)
            draw.ellipse([x-2, y-2, x+2, y+2], fill=(30, 30, 30))

        # Draw value arc
        arc_end = int(pct * 3.6)
        for angle in range(0, arc_end, 2):
            rad = math.radians(angle - 90)
            x = cx + r * math.cos(rad)
            y = cy + r * math.sin(rad)
            draw.ellipse([x-3, y-3, x+3, y+3], fill=color)

        # Draw head dot
        if arc_end > 0:
            rad = math.radians(arc_end - 90)
            x = cx + r * math.cos(rad)
            y = cy + r * math.sin(rad)
            draw.ellipse([x-5, y-5, x+5, y+5], fill=(255, 255, 255))

    # Center info
    now = datetime.now()
    time_str = now.strftime('%H:%M:%S')
    date_str = now.strftime('%a %d %b')

    # Time
    bbox = draw.textbbox((0, 0), time_str, font=font_large)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, cy - 50), time_str, fill=TEXT_COLOR, font=font_large)

    # Date
    bbox = draw.textbbox((0, 0), date_str, font=font_medium)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, cy), date_str, fill=TEXT_MUTED, font=font_medium)

    # Hostname
    hostname = metrics.get('hostname', 'secubox')
    bbox = draw.textbbox((0, 0), hostname, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, cy + 25), hostname, fill=TEXT_MUTED, font=font_small)

    # Uptime
    uptime_str = format_uptime(metrics.get('uptime', 0))
    bbox = draw.textbbox((0, 0), uptime_str, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, cy + 45), uptime_str, fill=TEXT_MUTED, font=font_small)

    # Draw pods with values
    pod_positions = [
        ('AUTH', cx, cy - 115),
        ('WALL', cx + 100, cy - 60),
        ('BOOT', cx + 100, cy + 60),
        ('MESH', cx, cy + 115),
        ('ROOT', cx - 100, cy + 60),
        ('MIND', cx - 100, cy - 60),
    ]

    for name, px, py in pod_positions:
        mod = MODULES[name]
        metric_name = mod['metric']
        value = metrics.get(metric_name, 0)
        unit = mod['unit']
        color = mod['color']

        # Format value
        if metric_name in ['cpu', 'mem', 'disk']:
            val_str = f'{int(value)}'
        elif metric_name == 'load':
            val_str = f'{value:.1f}'
        elif metric_name == 'temp':
            val_str = f'{int(value)}'
        else:
            val_str = f'{int(value)}'

        # Value
        bbox = draw.textbbox((0, 0), val_str, font=font_medium)
        tw = bbox[2] - bbox[0]
        draw.text((px - tw//2, py - 10), val_str, fill=color, font=font_medium)

        # Unit and name
        label = f'{unit} {name}'
        bbox = draw.textbbox((0, 0), label, font=font_small)
        tw = bbox[2] - bbox[0]
        draw.text((px - tw//2, py + 10), label, fill=TEXT_MUTED, font=font_small)

    # Top: SecuBox branding + device name
    brand = 'SECUBOX EYE'
    bbox = draw.textbbox((0, 0), brand, font=font_tiny)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, 20), brand, fill=(201, 168, 76), font=font_tiny)

    # Device name/host at top
    if device_name or host:
        device_text = device_name if device_name else host
        if len(device_text) > 20:
            device_text = device_text[:18] + '..'
        bbox = draw.textbbox((0, 0), device_text, font=font_tiny)
        tw = bbox[2] - bbox[0]
        draw.text((cx - tw//2, 35), device_text, fill=TEXT_MUTED, font=font_tiny)

    # Status bar at bottom
    if mode in ['OTG', 'API', 'EMULATOR']:
        status = f'● {mode} CONNECTED'
        status_color = STATUS_OK
    elif mode == 'WiFi':
        status = '● WiFi CONNECTED'
        status_color = (0, 191, 255)
    else:
        status = '○ SIMULATION'
        status_color = STATUS_SIM

    bbox = draw.textbbox((0, 0), status, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, HEIGHT - 55), status, fill=status_color, font=font_small)

    # Host address at bottom
    if host and mode != 'SIM':
        bbox = draw.textbbox((0, 0), host, font=font_tiny)
        tw = bbox[2] - bbox[0]
        draw.text((cx - tw//2, HEIGHT - 35), host, fill=TEXT_MUTED, font=font_tiny)

    return img


def pil_to_pygame(img):
    """Convert PIL image to pygame surface."""
    raw = img.convert('RGB').tobytes()
    return pygame.image.fromstring(raw, (WIDTH, HEIGHT), 'RGB')


def main():
    parser = argparse.ArgumentParser(
        description='SecuBox Eye Remote - AMD64 Dashboard Tester'
    )
    parser.add_argument(
        '--api', '-a',
        default='http://localhost:8765',
        help='API base URL (default: http://localhost:8765)'
    )
    parser.add_argument(
        '--fullscreen', '-f',
        action='store_true',
        help='Run in fullscreen mode'
    )
    args = parser.parse_args()

    print('SecuBox Eye Remote - AMD64 Test Dashboard')
    print(f'API: {args.api}')
    print('Press Q or ESC to exit')
    print()

    pygame.init()
    pygame.display.set_caption('SecuBox Eye Remote - Test Dashboard')

    if args.fullscreen:
        screen = pygame.display.set_mode((WIDTH, HEIGHT), pygame.FULLSCREEN)
    else:
        screen = pygame.display.set_mode((WIDTH, HEIGHT))

    clock = pygame.time.Clock()
    source = APIMetricsSource(args.api)

    running = True
    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            elif event.type == pygame.KEYDOWN:
                if event.key in (pygame.K_q, pygame.K_ESCAPE):
                    running = False

        # Get metrics and draw
        metrics, mode, host, device_name = source.get_metrics()
        img = draw_dashboard(metrics, mode, host, device_name)
        surface = pil_to_pygame(img)
        screen.blit(surface, (0, 0))
        pygame.display.flip()

        clock.tick(2)  # 2 FPS

    pygame.quit()
    print('Done.')


if __name__ == '__main__':
    main()
