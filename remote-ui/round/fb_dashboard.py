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

# Gadget mode configuration
MODE_FILE = '/etc/secubox/gadget-mode'
SERIAL_DEV = '/dev/ttyGS0'
SERIAL_BAUD = 115200

# Terminal display settings
TERM_FONT_SIZE = 12
TERM_LINES = 28  # Lines visible in round display
TERM_COLS = 45   # Chars per line (fits 480px with 12px mono font)

# Flash mode settings
FLASH_IMAGE_FILE = '/var/lib/secubox-flash.img'
FLASH_STATS_FILE = '/sys/kernel/config/usb_gadget/secubox/functions/mass_storage.0/lun.0/file'
FLASH_PROGRESS_FILE = '/run/secubox-flash-progress'

# Auth mode settings
AUTH_STATE_FILE = '/run/secubox-auth-state.json'
AUTH_QR_SIZE = 200  # QR code size in pixels

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


def get_gadget_mode() -> str:
    """Read current USB gadget mode.

    Returns:
        Mode string: 'normal', 'flash', 'debug', 'tty', 'auth', or 'normal' as default
    """
    try:
        if os.path.exists(MODE_FILE):
            with open(MODE_FILE, 'r') as f:
                mode = f.read().strip().lower()
                if mode in ('normal', 'flash', 'debug', 'tty', 'auth'):
                    return mode
    except:
        pass
    return 'normal'


class SerialTerminal:
    """Read and buffer serial console output for TTY mode display."""

    def __init__(self, device=SERIAL_DEV, baud=SERIAL_BAUD, max_lines=100):
        self.device = device
        self.baud = baud
        self.max_lines = max_lines
        self.lines: list[str] = []
        self.serial = None
        self._buffer = ''

    def open(self) -> bool:
        """Open serial port for reading."""
        try:
            import serial
            self.serial = serial.Serial(
                self.device,
                self.baud,
                timeout=0.1,
                rtscts=False,
                dsrdtr=False
            )
            return True
        except ImportError:
            print('pyserial not installed')
            return False
        except Exception as e:
            print(f'Serial open error: {e}')
            return False

    def close(self):
        """Close serial port."""
        if self.serial:
            try:
                self.serial.close()
            except:
                pass
            self.serial = None

    def read(self) -> bool:
        """Read available data from serial port.

        Returns:
            True if new data was read
        """
        if not self.serial:
            return False

        try:
            if self.serial.in_waiting > 0:
                data = self.serial.read(self.serial.in_waiting)
                text = data.decode('utf-8', errors='replace')
                self._buffer += text

                # Process buffer into lines
                while '\n' in self._buffer:
                    line, self._buffer = self._buffer.split('\n', 1)
                    # Strip CR and clean control chars (keep basic ASCII)
                    line = line.rstrip('\r')
                    line = ''.join(c if 32 <= ord(c) < 127 else ' ' for c in line)
                    self.lines.append(line)

                # Trim old lines
                if len(self.lines) > self.max_lines:
                    self.lines = self.lines[-self.max_lines:]

                return True
        except Exception as e:
            print(f'Serial read error: {e}')

        return False

    def get_display_lines(self, count=TERM_LINES) -> list[str]:
        """Get last N lines for display.

        Args:
            count: Number of lines to return

        Returns:
            List of strings, each truncated to TERM_COLS
        """
        display = self.lines[-count:] if self.lines else []
        # Pad to fill display
        while len(display) < count:
            display.insert(0, '')
        # Truncate long lines
        return [line[:TERM_COLS] for line in display]

    def add_simulated_line(self, text: str):
        """Add a line to the buffer (for testing without serial)."""
        self.lines.append(text[:TERM_COLS])
        if len(self.lines) > self.max_lines:
            self.lines = self.lines[-self.max_lines:]


def draw_terminal(term: SerialTerminal, mode: str = 'tty') -> Image.Image:
    """Draw a terminal display for TTY/serial mode.

    Args:
        term: SerialTerminal instance with buffered output
        mode: Current gadget mode (tty, debug, etc.)

    Returns:
        PIL Image ready for framebuffer
    """
    img = Image.new('RGBA', (WIDTH, HEIGHT), BG_COLOR + (255,))
    draw = ImageDraw.Draw(img)
    cx, cy = WIDTH // 2, HEIGHT // 2

    # Load monospace font
    try:
        font_mono = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf', TERM_FONT_SIZE)
        font_small = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 10)
    except:
        font_mono = ImageFont.load_default()
        font_small = font_mono

    # Draw circular mask/border
    draw.ellipse([5, 5, WIDTH-5, HEIGHT-5], outline=(40, 40, 50), width=2)

    # Header bar
    header = f'TTY MODE — {mode.upper()}'
    bbox = draw.textbbox((0, 0), header, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.rectangle([cx-tw//2-10, 8, cx+tw//2+10, 24], fill=(30, 80, 50))
    draw.text((cx - tw//2, 10), header, fill=(0, 255, 100), font=font_small)

    # Terminal area - calculate visible region (centered circle)
    # For round display, we need to shrink text area toward center
    term_top = 30
    term_left = 25
    term_right = WIDTH - 25
    line_height = TERM_FONT_SIZE + 2

    # Get display lines
    lines = term.get_display_lines(TERM_LINES)

    # Draw lines with subtle alternating background
    y = term_top
    for i, line in enumerate(lines):
        # Skip lines outside visible circle area
        # Simple approximation: reduce width near top/bottom
        dist_from_center = abs(y + line_height//2 - cy)
        if dist_from_center > 220:  # Outside circle
            y += line_height
            continue

        # Calculate available width at this y position
        if dist_from_center < 200:
            # Use Pythagorean theorem for circle
            half_width = int(math.sqrt(220**2 - dist_from_center**2))
        else:
            half_width = 50

        line_x = max(term_left, cx - half_width)
        max_chars = (half_width * 2) // (TERM_FONT_SIZE // 2)  # Approximate chars
        display_line = line[:max_chars]

        # Alternate background for readability
        if i % 2 == 0 and display_line.strip():
            draw.rectangle([line_x, y, cx + half_width, y + line_height], fill=(15, 15, 20))

        # Draw text
        if display_line.strip():
            draw.text((line_x, y), display_line, fill=(0, 255, 100), font=font_mono)

        y += line_height

    # Footer with status
    footer = f'● SERIAL @ {SERIAL_BAUD}'
    bbox = draw.textbbox((0, 0), footer, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, HEIGHT - 22), footer, fill=(100, 100, 120), font=font_small)

    return img


class FlashProgress:
    """Track flash/mass storage transfer progress."""

    def __init__(self, image_file=FLASH_IMAGE_FILE):
        self.image_file = image_file
        self.total_size = 0
        self.bytes_read = 0
        self.start_time = time.time()
        self._last_bytes = 0
        self._last_time = time.time()
        self.speed_mbps = 0.0
        self.active = False

        # Get image size
        try:
            if os.path.exists(image_file):
                self.total_size = os.path.getsize(image_file)
                print(f'Flash image: {image_file} ({self.total_size / (1024*1024):.1f} MB)')
        except:
            pass

    def update(self) -> bool:
        """Update progress by reading from /proc/diskstats or similar.

        Returns:
            True if progress changed
        """
        # Try to read progress from a status file written by gadget driver
        try:
            if os.path.exists(FLASH_PROGRESS_FILE):
                with open(FLASH_PROGRESS_FILE, 'r') as f:
                    data = json.load(f)
                    self.bytes_read = data.get('bytes_read', 0)
                    self.active = data.get('active', False)

                    now = time.time()
                    if now > self._last_time:
                        elapsed = now - self._last_time
                        bytes_diff = self.bytes_read - self._last_bytes
                        if elapsed > 0 and bytes_diff > 0:
                            self.speed_mbps = (bytes_diff / elapsed) / (1024 * 1024)
                        self._last_bytes = self.bytes_read
                        self._last_time = now
                    return True
        except:
            pass

        # Fallback: check if backing file is being read via /proc
        try:
            # Use stat to detect access time changes
            stat = os.stat(self.image_file)
            # This is a rough heuristic - actual bytes read would need eBPF/tracing
            self.active = (time.time() - stat.st_atime) < 5
        except:
            self.active = False

        return False

    @property
    def percent(self) -> float:
        """Get completion percentage."""
        if self.total_size <= 0:
            return 0.0
        return min(100.0, (self.bytes_read / self.total_size) * 100)

    @property
    def eta_seconds(self) -> int:
        """Estimate time remaining."""
        if self.speed_mbps <= 0 or self.total_size <= 0:
            return -1
        remaining_bytes = self.total_size - self.bytes_read
        return int(remaining_bytes / (self.speed_mbps * 1024 * 1024))

    def format_size(self, bytes_val: int) -> str:
        """Format bytes as human-readable string."""
        if bytes_val >= 1024 * 1024 * 1024:
            return f'{bytes_val / (1024*1024*1024):.1f} GB'
        elif bytes_val >= 1024 * 1024:
            return f'{bytes_val / (1024*1024):.1f} MB'
        elif bytes_val >= 1024:
            return f'{bytes_val / 1024:.1f} KB'
        return f'{bytes_val} B'


def draw_flash_progress(progress: FlashProgress) -> Image.Image:
    """Draw flash mode progress screen.

    Args:
        progress: FlashProgress instance

    Returns:
        PIL Image ready for framebuffer
    """
    img = Image.new('RGBA', (WIDTH, HEIGHT), BG_COLOR + (255,))
    draw = ImageDraw.Draw(img)
    cx, cy = WIDTH // 2, HEIGHT // 2

    # Load fonts
    try:
        font_large = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 36)
        font_medium = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 16)
        font_small = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 12)
    except:
        font_large = ImageFont.load_default()
        font_medium = font_large
        font_small = font_large

    # Draw circular border
    draw.ellipse([10, 10, WIDTH-10, HEIGHT-10], outline=(40, 40, 50), width=2)

    # Header
    header = 'FLASH MODE'
    bbox = draw.textbbox((0, 0), header, font=font_medium)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, 25), header, fill=(255, 100, 0), font=font_medium)

    # Flash icon (simplified USB icon)
    icon = load_module_icon('BOOT', 96)
    if icon:
        img.paste(icon, (cx - 48, 55), icon)

    # Status text
    if progress.active:
        status = 'TRANSFERRING...'
        status_color = (0, 255, 100)
    elif progress.percent > 0:
        status = 'TRANSFER COMPLETE'
        status_color = (0, 200, 255)
    else:
        status = 'WAITING FOR HOST'
        status_color = (255, 200, 0)

    bbox = draw.textbbox((0, 0), status, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, 160), status, fill=status_color, font=font_small)

    # Progress bar (circular arc style)
    bar_y = 190
    bar_width = 280
    bar_height = 20
    bar_x = cx - bar_width // 2

    # Background
    draw.rounded_rectangle(
        [bar_x, bar_y, bar_x + bar_width, bar_y + bar_height],
        radius=10,
        fill=(30, 30, 40)
    )

    # Progress fill
    fill_width = int(bar_width * (progress.percent / 100))
    if fill_width > 0:
        # Gradient-like effect with orange to yellow
        draw.rounded_rectangle(
            [bar_x, bar_y, bar_x + fill_width, bar_y + bar_height],
            radius=10,
            fill=(255, 150, 0)
        )

    # Percentage text
    pct_text = f'{progress.percent:.0f}%'
    bbox = draw.textbbox((0, 0), pct_text, font=font_large)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, 220), pct_text, fill=(255, 255, 255), font=font_large)

    # Size info
    size_text = f'{progress.format_size(progress.bytes_read)} / {progress.format_size(progress.total_size)}'
    bbox = draw.textbbox((0, 0), size_text, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, 270), size_text, fill=TEXT_MUTED, font=font_small)

    # Speed and ETA
    if progress.speed_mbps > 0:
        speed_text = f'{progress.speed_mbps:.1f} MB/s'
        bbox = draw.textbbox((0, 0), speed_text, font=font_small)
        tw = bbox[2] - bbox[0]
        draw.text((cx - tw//2, 290), speed_text, fill=(100, 200, 100), font=font_small)

    if progress.eta_seconds > 0:
        eta_min = progress.eta_seconds // 60
        eta_sec = progress.eta_seconds % 60
        eta_text = f'ETA: {eta_min}:{eta_sec:02d}'
        bbox = draw.textbbox((0, 0), eta_text, font=font_small)
        tw = bbox[2] - bbox[0]
        draw.text((cx - tw//2, 310), eta_text, fill=TEXT_MUTED, font=font_small)

    # Footer with instructions
    footer = 'Boot from USB to flash SecuBox'
    bbox = draw.textbbox((0, 0), footer, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, HEIGHT - 50), footer, fill=(100, 100, 120), font=font_small)

    # CyberMind branding
    brand = 'SECUBOX EYE'
    bbox = draw.textbbox((0, 0), brand, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, HEIGHT - 30), brand, fill=(201, 168, 76), font=font_small)

    return img


class AuthState:
    """Manage authentication state for AUTH mode (FIDO2 security key)."""

    def __init__(self):
        self.device_id = ''
        self.challenge = ''
        self.qr_url = ''
        self.state = 'idle'  # idle, pending, approved, denied
        self.last_update = 0
        self._qr_image = None

        # Try to load device ID
        try:
            import uuid
            machine_id_path = '/etc/machine-id'
            if os.path.exists(machine_id_path):
                with open(machine_id_path, 'r') as f:
                    self.device_id = f.read().strip()[:12]
            else:
                self.device_id = uuid.uuid4().hex[:12]
        except:
            self.device_id = 'eye-remote'

    def update(self) -> bool:
        """Update auth state from status file.

        Returns:
            True if state changed
        """
        try:
            if os.path.exists(AUTH_STATE_FILE):
                with open(AUTH_STATE_FILE, 'r') as f:
                    data = json.load(f)
                    old_state = self.state
                    self.state = data.get('state', 'idle')
                    self.challenge = data.get('challenge', '')
                    self.qr_url = data.get('qr_url', '')
                    self.last_update = data.get('timestamp', 0)

                    # Regenerate QR if URL changed
                    if self.qr_url and self.qr_url != getattr(self, '_last_qr_url', ''):
                        self._generate_qr()
                        self._last_qr_url = self.qr_url

                    return self.state != old_state
        except:
            pass
        return False

    def _generate_qr(self):
        """Generate QR code image from URL."""
        try:
            import qrcode
            # Create QR code with medium error correction
            qr = qrcode.QRCode(
                version=1,
                error_correction=1,  # ERROR_CORRECT_M = 1
                box_size=6,
                border=2,
            )
            qr.add_data(self.qr_url)
            qr.make(fit=True)

            # Create image with PIL
            qr_img = qr.make_image(fill_color='white', back_color='black')

            # Convert to PIL Image - handle different qrcode versions
            try:
                # Try PIL image factory (qrcode >= 7.0)
                if hasattr(qr_img, '_img'):
                    pil_img = qr_img._img
                elif hasattr(qr_img, 'get_image'):
                    pil_img = qr_img.get_image()
                else:
                    # Fallback: convert via tobytes/frombytes
                    pil_img = qr_img
            except Exception:
                pil_img = qr_img

            # Ensure it's an RGBA image at the right size
            if hasattr(pil_img, 'convert'):
                self._qr_image = pil_img.convert('RGBA').resize(
                    (AUTH_QR_SIZE, AUTH_QR_SIZE),
                    Image.Resampling.NEAREST if hasattr(Image, 'Resampling') else Image.NEAREST
                )
            else:
                # Last resort: create blank image
                self._qr_image = Image.new('RGBA', (AUTH_QR_SIZE, AUTH_QR_SIZE), (255, 255, 255, 255))

        except ImportError:
            print('qrcode library not installed')
            self._qr_image = None
        except Exception as e:
            print(f'QR generation error: {e}')
            self._qr_image = None

    def get_qr_image(self):
        """Get the QR code image.

        Returns:
            PIL Image or None if not generated
        """
        return self._qr_image

    def generate_backup_code(self) -> str:
        """Generate a backup authentication URL for QR code.

        Uses device ID and a timestamp-based challenge.
        """
        import hashlib
        ts = int(time.time())
        data = f'{self.device_id}:{ts}'
        challenge = hashlib.sha256(data.encode()).hexdigest()[:16]
        self.challenge = challenge
        # Format: secubox-auth://device_id/challenge
        self.qr_url = f'secubox-auth://{self.device_id}/{challenge}'
        self._generate_qr()
        return self.qr_url


def draw_auth_mode(auth: AuthState) -> Image.Image:
    """Draw auth mode screen with QR code.

    Args:
        auth: AuthState instance

    Returns:
        PIL Image ready for framebuffer
    """
    img = Image.new('RGBA', (WIDTH, HEIGHT), BG_COLOR + (255,))
    draw = ImageDraw.Draw(img)
    cx, cy = WIDTH // 2, HEIGHT // 2

    # Load fonts
    try:
        font_large = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf', 24)
        font_medium = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 14)
        font_small = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 11)
    except:
        font_large = ImageFont.load_default()
        font_medium = font_large
        font_small = font_large

    # Draw circular border
    draw.ellipse([10, 10, WIDTH-10, HEIGHT-10], outline=(40, 40, 50), width=2)

    # Header
    header = 'AUTH MODE'
    bbox = draw.textbbox((0, 0), header, font=font_medium)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, 20), header, fill=(192, 78, 36), font=font_medium)

    # Auth icon
    icon = load_module_icon('AUTH', 48)
    if icon:
        img.paste(icon, (cx - 24, 45), icon)

    # State indicator
    state_colors = {
        'idle': (100, 100, 120),
        'pending': (255, 200, 0),
        'approved': (0, 255, 100),
        'denied': (255, 50, 50),
    }
    state_texts = {
        'idle': 'READY TO AUTHENTICATE',
        'pending': 'TOUCH TO APPROVE',
        'approved': 'AUTHENTICATED',
        'denied': 'ACCESS DENIED',
    }

    state_color = state_colors.get(auth.state, state_colors['idle'])
    state_text = state_texts.get(auth.state, 'UNKNOWN')

    bbox = draw.textbbox((0, 0), state_text, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, 100), state_text, fill=state_color, font=font_small)

    # QR code (centered, below status)
    qr_img = auth.get_qr_image()
    if qr_img:
        qr_x = cx - AUTH_QR_SIZE // 2
        qr_y = 125
        img.paste(qr_img, (qr_x, qr_y), qr_img)

        # QR label
        qr_label = 'BACKUP CODE'
        bbox = draw.textbbox((0, 0), qr_label, font=font_small)
        tw = bbox[2] - bbox[0]
        draw.text((cx - tw//2, qr_y + AUTH_QR_SIZE + 5), qr_label, fill=TEXT_MUTED, font=font_small)
    else:
        # No QR - show placeholder
        draw.rectangle(
            [cx - AUTH_QR_SIZE//2, 125, cx + AUTH_QR_SIZE//2, 125 + AUTH_QR_SIZE],
            outline=(50, 50, 60),
            width=2
        )
        placeholder = 'QR CODE'
        bbox = draw.textbbox((0, 0), placeholder, font=font_medium)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
        draw.text((cx - tw//2, 125 + AUTH_QR_SIZE//2 - th//2), placeholder, fill=(60, 60, 70), font=font_medium)

    # Device ID
    device_text = f'Device: {auth.device_id}'
    bbox = draw.textbbox((0, 0), device_text, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, HEIGHT - 80), device_text, fill=TEXT_MUTED, font=font_small)

    # Instructions
    if auth.state == 'pending':
        instr = 'Touch the display to approve'
    else:
        instr = 'Connect USB for FIDO2 auth'

    bbox = draw.textbbox((0, 0), instr, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, HEIGHT - 55), instr, fill=(100, 100, 120), font=font_small)

    # Branding
    brand = 'SECUBOX EYE'
    bbox = draw.textbbox((0, 0), brand, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((cx - tw//2, HEIGHT - 30), brand, fill=(201, 168, 76), font=font_small)

    return img


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

    # Check initial gadget mode
    gadget_mode = get_gadget_mode()
    print(f'Gadget mode: {gadget_mode}')

    # Try agent first, fall back to simulation
    if os.path.exists(AGENT_SOCKET):
        print(f'Eye Agent socket found: {AGENT_SOCKET}')
    else:
        print('Agent not running, will use simulation mode')

    source = AgentMetricsSource()
    terminal = None
    flash_progress = None

    # Initialize serial terminal for TTY mode
    if gadget_mode == 'tty':
        terminal = SerialTerminal()
        if terminal.open():
            print(f'Serial terminal opened: {SERIAL_DEV}')
        else:
            print('Serial terminal failed to open, using simulation')
            # Add some simulated lines for testing
            terminal.add_simulated_line('U-Boot 2024.01 (Apr 15 2026)')
            terminal.add_simulated_line('')
            terminal.add_simulated_line('Marvell ARMADA 3720 ESPRESSOBIN Board')
            terminal.add_simulated_line('')
            terminal.add_simulated_line('DRAM:  1 GiB')
            terminal.add_simulated_line('SF: Detected w25q32dw with page size 256 Bytes')
            terminal.add_simulated_line('Net:   eth0: mvpp2-0, eth1: mvpp2-1')
            terminal.add_simulated_line('')
            terminal.add_simulated_line('Hit any key to stop autoboot: 0')
            terminal.add_simulated_line('=> ')

    # Initialize flash progress for FLASH mode
    if gadget_mode == 'flash':
        flash_progress = FlashProgress()
        print(f'Flash mode initialized, image size: {flash_progress.format_size(flash_progress.total_size)}')

    # Initialize auth state for AUTH mode
    auth_state = None
    if gadget_mode == 'auth':
        auth_state = AuthState()
        auth_state.generate_backup_code()
        print(f'Auth mode initialized, device: {auth_state.device_id}')

    # Draw initial frame immediately
    print('Drawing initial frame...')
    try:
        if gadget_mode == 'tty' and terminal:
            img = draw_terminal(terminal, gadget_mode)
        elif gadget_mode == 'flash' and flash_progress:
            img = draw_flash_progress(flash_progress)
        elif gadget_mode == 'auth':
            if not auth_state:
                auth_state = AuthState()
                auth_state.generate_backup_code()
            img = draw_auth_mode(auth_state)
        else:
            metrics, mode, host, device_name = source.get_metrics()
            img = draw_dashboard(metrics, mode, host, device_name)
        write_to_fb(img)
        print(f'Initial frame drawn, gadget_mode={gadget_mode}')
    except Exception as e:
        print(f'Initial frame error: {e}')

    last_gadget_mode = gadget_mode

    while True:
        try:
            # Check for mode changes
            gadget_mode = get_gadget_mode()
            if gadget_mode != last_gadget_mode:
                print(f'Mode changed: {last_gadget_mode} -> {gadget_mode}')
                last_gadget_mode = gadget_mode

                # Handle terminal lifecycle
                if gadget_mode == 'tty':
                    if not terminal:
                        terminal = SerialTerminal()
                    if not terminal.serial:
                        terminal.open()
                elif terminal and terminal.serial:
                    terminal.close()

                # Handle flash progress lifecycle
                if gadget_mode == 'flash':
                    if not flash_progress:
                        flash_progress = FlashProgress()
                        print(f'Flash mode initialized')

                # Handle auth state lifecycle
                if gadget_mode == 'auth':
                    if not auth_state:
                        auth_state = AuthState()
                        auth_state.generate_backup_code()
                        print(f'Auth mode initialized')

            # Render based on current mode
            if gadget_mode == 'tty' and terminal:
                # Read any new serial data
                terminal.read()
                img = draw_terminal(terminal, gadget_mode)
                write_to_fb(img)
                time.sleep(0.1)  # Faster refresh for serial data
            elif gadget_mode == 'flash':
                # Flash mode with progress
                if not flash_progress:
                    flash_progress = FlashProgress()
                flash_progress.update()
                img = draw_flash_progress(flash_progress)
                write_to_fb(img)
                time.sleep(0.5)  # Medium refresh for progress updates
            elif gadget_mode == 'auth':
                # Auth mode with QR code
                if not auth_state:
                    auth_state = AuthState()
                    auth_state.generate_backup_code()
                auth_state.update()
                img = draw_auth_mode(auth_state)
                write_to_fb(img)
                time.sleep(0.5)  # Medium refresh for auth updates
            else:
                # Standard dashboard mode
                metrics, mode, host, device_name = source.get_metrics()
                img = draw_dashboard(metrics, mode, host, device_name)
                write_to_fb(img)
                time.sleep(1)

        except KeyboardInterrupt:
            print('\nExiting...')
            break
        except Exception as e:
            print(f'Error: {e}')
            time.sleep(1)

    # Cleanup
    if terminal:
        terminal.close()


if __name__ == '__main__':
    main()
