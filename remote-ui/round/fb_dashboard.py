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

# Module icons directory (relative to script location)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ICONS_DIR = os.path.join(SCRIPT_DIR, 'assets', 'icons')

# Icon cache
_icon_cache = {}

# Framebuffer info (cached)
_fb_info = None


def load_module_icon(module_name: str, size: int = 48) -> Image.Image | None:
    """Load a module icon from assets.

    Args:
        module_name: Module name (AUTH, WALL, BOOT, MIND, ROOT, MESH)
        size: Icon size (22, 48, 96, 128)

    Returns:
        PIL Image or None if not found
    """
    cache_key = f"{module_name}_{size}"
    if cache_key in _icon_cache:
        return _icon_cache[cache_key]

    icon_path = os.path.join(ICONS_DIR, f"{module_name.lower()}-{size}.png")
    try:
        if os.path.exists(icon_path):
            icon = Image.open(icon_path).convert('RGBA')
            _icon_cache[cache_key] = icon
            return icon
    except Exception as e:
        print(f"Failed to load icon {icon_path}: {e}")

    return None


def get_critical_module(metrics: dict) -> tuple[str, float]:
    """Determine which module has the most critical metric.

    Returns:
        tuple: (module_name, criticality_score 0-100)
    """
    scores = {}

    # CPU (AUTH) - direct percentage
    cpu = metrics.get('cpu', 0)
    scores['AUTH'] = cpu

    # Memory (WALL) - direct percentage
    mem = metrics.get('mem', 0)
    scores['WALL'] = mem

    # Disk (BOOT) - direct percentage
    disk = metrics.get('disk', 0)
    scores['BOOT'] = disk

    # Load (MIND) - scale 0-4 to 0-100
    load = metrics.get('load', 0)
    scores['MIND'] = min(100, load * 25)

    # Temp (ROOT) - scale 30-80°C to 0-100
    temp = metrics.get('temp', 0)
    scores['ROOT'] = min(100, max(0, (temp - 30) * 2))

    # WiFi (MESH) - scale -80 to -30 dBm to 0-100 (inverted - weaker = more critical)
    wifi = metrics.get('wifi', -80)
    # Invert: -80 dBm = 100% critical, -30 dBm = 0% critical
    scores['MESH'] = min(100, max(0, (-wifi - 30) * 2))

    # Find most critical
    critical_module = max(scores, key=scores.get)
    return critical_module, scores[critical_module]


def detect_otg_interface() -> bool:
    """Check if USB OTG network interface (usb0) is UP."""
    try:
        with open('/sys/class/net/usb0/operstate', 'r') as f:
            state = f.read().strip()
            return state == 'up'
    except:
        return False


def get_usb0_ip() -> str:
    """Get IP address of usb0 interface."""
    try:
        import subprocess
        result = subprocess.run(
            ['ip', '-4', 'addr', 'show', 'usb0'],
            capture_output=True, text=True, timeout=2
        )
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                return line.split()[1].split('/')[0]
    except:
        pass
    return '10.55.0.2'


class AgentMetricsSource:
    """Fetch metrics from Eye Agent via Unix socket."""

    def __init__(self):
        self.mode = 'SIM'
        self.host = ''
        self.device_name = ''
        self.sim = SimulatedMetrics()
        self._last_data = None
        self._otg_up = False

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

        # Check OTG interface status for mode detection
        self._otg_up = detect_otg_interface()

        if self._otg_up:
            # OTG network is up - show OTG mode with simulated metrics
            self.mode = 'OTG'
            self.host = '10.55.0.1'
            self.device_name = 'SecuBox (waiting)'
            return self.sim.update(), 'OTG', self.host, self.device_name

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

    # Center info - Contextual icon + mode display
    # Get the most critical module for contextual icon
    critical_module, criticality = get_critical_module(metrics)
    module_color = MODULES[critical_module]['color']

    # Draw contextual icon (48px) centered above mode text
    icon = load_module_icon(critical_module, 48)
    if icon:
        icon_x = cx - 24  # Center 48px icon
        icon_y = cy - 75  # Above mode text
        img.paste(icon, (icon_x, icon_y), icon)  # Use alpha mask

    # OTG/WiFi/SIM status
    if mode == 'OTG':
        mode_text = 'USB OTG'
        mode_color = STATUS_OK  # Neon green
    elif mode == 'WIFI':
        mode_text = 'WiFi'
        mode_color = (0, 191, 255)  # Cyan
    else:
        mode_text = 'SIM'
        mode_color = STATUS_SIM

    # Mode indicator (smaller, below icon)
    bbox = draw.textbbox((0, 0), mode_text, font=font_medium)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, cy - 20), mode_text, fill=mode_color, font=font_medium)

    # Critical module indicator with value
    metric_name = MODULES[critical_module]['metric']
    metric_value = metrics.get(metric_name, 0)
    metric_unit = MODULES[critical_module]['unit']
    if metric_name == 'wifi':
        value_text = f"{critical_module} {int(metric_value)}{metric_unit}"
    elif metric_name == 'load':
        value_text = f"{critical_module} {metric_value:.1f}{metric_unit}"
    else:
        value_text = f"{critical_module} {int(metric_value)}{metric_unit}"
    bbox = draw.textbbox((0, 0), value_text, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, cy + 5), value_text, fill=module_color, font=font_small)

    # Connection status
    if mode in ['OTG', 'WIFI']:
        status_text = 'CONNECTED'
        bbox = draw.textbbox((0, 0), status_text, font=font_tiny)
        tw = bbox[2] - bbox[0]
        draw.text((cx - tw//2, cy + 25), status_text, fill=mode_color, font=font_tiny)

    # Hostname below
    hostname = metrics.get('hostname', 'secubox')
    bbox = draw.textbbox((0, 0), hostname, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, cy + 42), hostname, fill=TEXT_MUTED, font=font_small)

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


def get_fb_info():
    """Get framebuffer info from sysfs (cached).

    Returns:
        tuple: (bits_per_pixel, stride)
    """
    global _fb_info
    if _fb_info is not None:
        return _fb_info

    try:
        with open('/sys/class/graphics/fb0/bits_per_pixel', 'r') as f:
            bpp = int(f.read().strip())
    except:
        bpp = 32  # Default to 32-bit

    # Line length (stride) - bytes per row
    try:
        with open('/sys/class/graphics/fb0/stride', 'r') as f:
            stride = int(f.read().strip())
    except:
        stride = WIDTH * (bpp // 8)

    # Virtual size for buffer info
    try:
        with open('/sys/class/graphics/fb0/virtual_size', 'r') as f:
            vsize = f.read().strip()
    except:
        vsize = f'{WIDTH},{HEIGHT}'

    print(f'Framebuffer: {bpp}bpp, stride={stride}, vsize={vsize}')
    _fb_info = (bpp, stride)
    return _fb_info


def write_to_fb(img):
    """Write image to framebuffer with auto-format detection."""
    bpp, stride = get_fb_info()

    if bpp == 32:
        # 32-bit BGRA (most common for DPI displays)
        pixels = img.convert('RGBA')
        raw = pixels.tobytes('raw', 'BGRA')
    elif bpp == 24:
        # 24-bit BGR
        pixels = img.convert('RGB')
        raw = pixels.tobytes('raw', 'BGR')
    elif bpp == 16:
        # 16-bit RGB565
        pixels = img.convert('RGB')
        data = bytearray(WIDTH * HEIGHT * 2)
        idx = 0
        for y in range(HEIGHT):
            for x in range(WIDTH):
                r, g, b = pixels.getpixel((x, y))
                # RGB565: RRRRRGGG GGGBBBBB
                pixel = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
                data[idx] = pixel & 0xFF
                data[idx + 1] = (pixel >> 8) & 0xFF
                idx += 2
        raw = bytes(data)
    else:
        print(f'Unsupported framebuffer depth: {bpp}bpp')
        return

    try:
        with open(FB_DEV, 'wb') as fb:
            fb.write(raw)
    except Exception as e:
        print(f'Framebuffer write error: {e}')


def main():
    print('SecuBox Eye Remote - Framebuffer Dashboard')
    print(f'Display: {WIDTH}x{HEIGHT}')
    print('Press Ctrl+C to exit')

    # Check framebuffer device
    if os.path.exists(FB_DEV):
        print(f'Framebuffer device: {FB_DEV} found')
        # Pre-fetch FB info
        bpp, stride = get_fb_info()
    else:
        print(f'WARNING: {FB_DEV} not found!')

    # Try agent first, fall back to simulation
    if os.path.exists(AGENT_SOCKET):
        print(f'Eye Agent socket found: {AGENT_SOCKET}')
    else:
        print('Agent not running, will use simulation mode')

    source = AgentMetricsSource()

    # Draw initial frame immediately
    print('Drawing initial frame...')
    try:
        metrics, mode, host, device_name = source.get_metrics()
        img = draw_dashboard(metrics, mode, host, device_name)
        write_to_fb(img)
        print(f'Initial frame drawn, mode={mode}')
    except Exception as e:
        print(f'Initial frame error: {e}')

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
