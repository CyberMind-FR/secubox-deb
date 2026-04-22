#!/usr/bin/env python3
"""
SecuBox Eye Remote - Framebuffer Dashboard
Renders directly to /dev/fb0 for Pi Zero W (ARMv6, no NEON/Chromium)

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
import os
import sys
import time
import math
import struct
import random
import socket
import socket as sock_module
import json

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print('Installing pillow...')
    os.system('pip3 install pillow')
    from PIL import Image, ImageDraw, ImageFont

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Display config
WIDTH = 480
HEIGHT = 480
FB_DEV = '/dev/fb0'

# API config
API_OTG = 'http://10.55.0.1:8000'
API_WIFI = 'http://secubox.local:8000'
API_TIMEOUT = 3

# Colors (RGB) — Neon theme
BG_COLOR = (8, 8, 12)            # Deep space black
TEXT_COLOR = (240, 240, 250)     # Bright white
TEXT_MUTED = (130, 130, 150)     # Soft gray-blue
STATUS_OK = (0, 255, 65)         # Neon green
STATUS_WARN = (255, 100, 0)      # Neon orange
STATUS_SIM = (100, 100, 120)     # Dim gray

# Module colors — Arc-en-ciel Laser (Neon Rainbow)
MODULES = {
    'AUTH': {'color': (255, 0, 100), 'metric': 'cpu', 'unit': '%', 'r': 214},     # Neon Magenta
    'WALL': {'color': (255, 100, 0), 'metric': 'mem', 'unit': '%', 'r': 201},     # Neon Orange
    'BOOT': {'color': (220, 255, 0), 'metric': 'disk', 'unit': '%', 'r': 188},    # Neon Yellow
    'MIND': {'color': (0, 255, 65), 'metric': 'load', 'unit': 'x', 'r': 175},     # Matrix Green
    'ROOT': {'color': (0, 255, 255), 'metric': 'temp', 'unit': '°', 'r': 162},    # Cyber Cyan
    'MESH': {'color': (185, 0, 255), 'metric': 'wifi', 'unit': 'dB', 'r': 149},   # Laser Purple
}

# Eye Agent Unix socket
AGENT_SOCKET = '/run/secubox-eye/metrics.sock'


class AgentMetricsSource:
    """Fetch metrics from Eye Agent via Unix socket."""

    def __init__(self):
        self.mode = 'SIM'
        self.host = ''
        self.device_name = ''
        self.sim = SimulatedMetrics()
        self._last_data = None

    def _read_from_socket(self) -> dict | None:
        """Read metrics from agent Unix socket."""
        try:
            s = sock_module.socket(sock_module.AF_UNIX, sock_module.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect(AGENT_SOCKET)
            data = s.recv(8192)
            s.close()
            return json.loads(data.decode())
        except Exception:
            return None

    def get_metrics(self):
        """Get current metrics from agent or simulation.

        Returns:
            tuple: (metrics_dict, mode, host, device_name)
        """
        data = self._read_from_socket()

        if data and 'metrics' in data:
            self._last_data = data
            secubox_info = data.get('secubox', {})
            transport = secubox_info.get('transport', 'SIM')
            mode = transport.upper() if transport in ('otg', 'wifi') else 'SIM'
            self.mode = mode
            self.host = secubox_info.get('host', '')
            self.device_name = secubox_info.get('name', '')

            metrics = data['metrics']
            # Map API fields to dashboard fields
            return {
                'cpu': metrics.get('cpu_percent', 0),
                'mem': metrics.get('mem_percent', 0),
                'disk': metrics.get('disk_percent', 0),
                'load': metrics.get('load_avg_1', 0),
                'temp': metrics.get('cpu_temp', 0),
                'wifi': metrics.get('wifi_rssi', -80),
                'uptime': metrics.get('uptime_seconds', 0),
                'hostname': metrics.get('hostname', 'secubox'),
            }, mode, self.host, self.device_name

        # Fallback to simulation
        self.mode = 'SIM'
        self.host = ''
        self.device_name = ''
        return self.sim.update(), 'SIM', '', ''


class MetricsSource:
    """Fetch metrics from SecuBox API or simulate"""

    def __init__(self):
        self.mode = 'SIM'  # OTG, WiFi, or SIM
        self.api_base = None
        self.host = ''
        self.device_name = ''
        self.jwt_token = None
        self.sim = SimulatedMetrics()
        self._probe_api()

    def _probe_api(self):
        """Try to connect to SecuBox API"""
        if not HAS_REQUESTS:
            return

        for base, mode in [(API_OTG, 'OTG'), (API_WIFI, 'WiFi')]:
            try:
                r = requests.get(f'{base}/api/v1/health', timeout=API_TIMEOUT)
                if r.status_code == 200:
                    self.api_base = base
                    self.mode = mode
                    self.host = base.replace('http://', '').split(':')[0]
                    print(f'Connected to SecuBox via {mode} at {self.host}')
                    return
            except:
                pass

        print('No SecuBox API found, using simulation mode')

    def get_metrics(self):
        """Get current metrics.

        Returns:
            tuple: (metrics_dict, mode, host, device_name)
        """
        if self.mode == 'SIM' or not self.api_base:
            return self.sim.update(), 'SIM', '', ''

        try:
            headers = {}
            if self.jwt_token:
                headers['Authorization'] = f'Bearer {self.jwt_token}'

            r = requests.get(
                f'{self.api_base}/api/v1/system/metrics',
                headers=headers,
                timeout=API_TIMEOUT
            )

            if r.status_code == 200:
                data = r.json()
                hostname = data.get('hostname', 'secubox')
                self.device_name = hostname
                return {
                    'cpu': data.get('cpu_percent', 0),
                    'mem': data.get('mem_percent', 0),
                    'disk': data.get('disk_percent', 0),
                    'load': data.get('load_avg_1', 0),
                    'temp': data.get('cpu_temp', 0),
                    'wifi': data.get('wifi_rssi', -80),
                    'uptime': data.get('uptime_seconds', 0),
                    'hostname': hostname,
                }, self.mode, self.host, self.device_name
        except Exception as e:
            print(f'API error: {e}')

        # Fallback to simulation
        return self.sim.update(), 'SIM', '', ''


class SimulatedMetrics:
    """Simulate metrics when no API available"""

    def __init__(self):
        self.cpu = 25.0
        self.mem = 45.0
        self.disk = 32.0
        self.load = 0.5
        self.temp = 42.0
        self.wifi = -55
        self.uptime = 0
        self.start = time.time()

    def update(self):
        # Add realistic drift
        self.cpu = max(5, min(95, self.cpu + random.uniform(-3, 3)))
        self.mem = max(20, min(85, self.mem + random.uniform(-1, 1)))
        self.disk = max(10, min(90, self.disk + random.uniform(-0.1, 0.1)))
        self.load = max(0.1, min(4.0, self.load + random.uniform(-0.1, 0.1)))
        self.temp = max(35, min(70, self.temp + random.uniform(-0.5, 0.5)))
        self.wifi = max(-80, min(-30, self.wifi + random.randint(-2, 2)))
        self.uptime = int(time.time() - self.start)

        return {
            'cpu': self.cpu,
            'mem': self.mem,
            'disk': self.disk,
            'load': self.load,
            'temp': self.temp,
            'wifi': self.wifi,
            'uptime': self.uptime,
            'hostname': 'secubox-eye'
        }


def format_uptime(seconds):
    """Format uptime as 'up XhYY'"""
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f'up {hours}h{minutes:02d}'


def draw_dashboard(metrics, mode='SIM', host='', device_name=''):
    """Draw the dashboard to an image

    Args:
        metrics: Dict with cpu, mem, disk, load, temp, wifi, uptime, hostname
        mode: Transport mode - 'OTG', 'WiFi', or 'SIM'
        host: SecuBox host IP/address
        device_name: Name of connected SecuBox device
    """
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
    for _, mod in MODULES.items():
        r = mod['r']
        color = mod['color']
        metric_name = mod['metric']
        value = metrics.get(metric_name, 0)

        # Calculate percentage for arc
        if metric_name == 'load':
            pct = min(100, value * 25)  # 4.0 = 100%
        elif metric_name == 'wifi':
            pct = min(100, max(0, (value + 80) * 2))  # -80 to -30 dBm
        elif metric_name == 'temp':
            pct = min(100, max(0, (value - 30) * 2.5))  # 30-70°C
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
    draw.text((cx - tw//2, 20), brand, fill=(201, 168, 76), font=font_tiny)  # gold-hermetic

    # Device name/host at top (if connected)
    if device_name or host:
        device_text = device_name if device_name else host
        # Truncate if too long
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


def write_to_fb(img):
    """Write image to framebuffer (BGRA format)"""
    pixels = img.convert('RGBA')
    data = bytearray()

    for y in range(HEIGHT):
        for x in range(WIDTH):
            r, g, b, a = pixels.getpixel((x, y))
            data.extend([b, g, r, a])  # BGRA

    with open(FB_DEV, 'wb') as fb:
        fb.write(data)


def main():
    print('SecuBox Eye Remote - Framebuffer Dashboard')
    print(f'Display: {WIDTH}x{HEIGHT}')
    print('Press Ctrl+C to exit')

    # Try agent first, fall back to simulation
    if os.path.exists(AGENT_SOCKET):
        print('Using Eye Agent for metrics')
    else:
        print('Agent not running, will use simulation mode')

    source = AgentMetricsSource()

    while True:
        try:
            metrics, mode, host, device_name = source.get_metrics()
            img = draw_dashboard(metrics, mode, host, device_name)
            write_to_fb(img)

            # Log connection changes
            if mode != 'SIM' and host:
                pass  # Connected to real device
            time.sleep(1)
        except KeyboardInterrupt:
            print('\nExiting...')
            break
        except Exception as e:
            print(f'Error: {e}')
            time.sleep(1)


if __name__ == '__main__':
    main()
