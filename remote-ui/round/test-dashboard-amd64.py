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
                # Emulator simulates OTG connection
                if data.get('emulated'):
                    self.mode = 'OTG'
                    self.device_name = data.get('device_name', 'secubox-emulated')
                else:
                    self.mode = 'OTG'
                    self.device_name = data.get('device_name', 'secubox')
                self._connected = True
                print(f'Connected to SecuBox at {self.api_base}')
                print(f'  Mode: {self.mode} ({"emulated" if data.get("emulated") else "real"})')
                print(f'  Device: {self.device_name}')
                if data.get('profile'):
                    print(f'  Profile: {data.get("profile")}')
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
                # Get transport mode from API (otg, wifi, or default to current mode)
                transport = data.get('transport', '').upper()
                if transport in ['OTG', 'WIFI']:
                    self.mode = transport
                # Update device name if provided
                if data.get('hostname'):
                    self.device_name = data.get('hostname')
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

    # Center info - OTG mode display (no clock/date)
    # OTG/WiFi/SIM status - large and central
    if mode == 'OTG':
        mode_text = 'USB OTG'
        mode_color = STATUS_OK  # Neon green
    elif mode == 'WIFI':
        mode_text = 'WiFi'
        mode_color = (0, 191, 255)  # Cyan
    else:
        mode_text = 'SIM'
        mode_color = STATUS_SIM

    # Large mode indicator
    bbox = draw.textbbox((0, 0), mode_text, font=font_large)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, cy - 30), mode_text, fill=mode_color, font=font_large)

    # Connection status
    if mode in ['OTG', 'WIFI']:
        status_text = 'CONNECTED'
        bbox = draw.textbbox((0, 0), status_text, font=font_medium)
        tw = bbox[2] - bbox[0]
        draw.text((cx - tw//2, cy + 10), status_text, fill=mode_color, font=font_medium)

    # Hostname below
    hostname = metrics.get('hostname', 'secubox')
    bbox = draw.textbbox((0, 0), hostname, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, cy + 40), hostname, fill=TEXT_MUTED, font=font_small)

    # Rings only - no text labels on circles (clean design)

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

    # Host address at bottom (minimal)
    if host and mode != 'SIM':
        host_display = host.replace('http://', '').replace('https://', '').split(':')[0]
        bbox = draw.textbbox((0, 0), host_display, font=font_tiny)
        tw = bbox[2] - bbox[0]
        draw.text((cx - tw//2, HEIGHT - 30), host_display, fill=TEXT_MUTED, font=font_tiny)

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
