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
import sys
import time
import math
import random
import colorsys
import subprocess
import json
import asyncio
import threading
import urllib.request
import urllib.error
import ssl
from pathlib import Path
from enum import Enum
from typing import Optional, Tuple, List, Dict, Any
from PIL import Image, ImageDraw, ImageFilter, ImageEnhance

# Import metrics fetcher (with fallback if not available)
try:
    from ..api.metrics_fetcher import (
        MetricsFetcher, SecuBoxMetrics, ConnectionState,
        get_fetcher, fetch_metrics
    )
    HAS_METRICS_FETCHER = True
except ImportError:
    HAS_METRICS_FETCHER = False
    ConnectionState = None

# Import gadget status renderer
try:
    from ..gadget_status import render_gadget_status_bar, render_gadget_indicator
    HAS_GADGET_STATUS = True
except ImportError:
    HAS_GADGET_STATUS = False

WIDTH = HEIGHT = 480
CENTER = 240


class FallbackMode(Enum):
    OFFLINE = "offline"           # No connection - local metrics
    CONNECTING = "connecting"     # Trying to connect - dice animation
    ONLINE = "online"             # Connected - full dashboard
    COMMUNICATING = "comm"        # Active transfer - fast dice


# Flashy module colors - thinner rings, larger center
MODULES = [
    {'name': 'BOOT', 'color': (255, 60, 40),   'r': 220, 'glow': (255, 100, 80)},   # rouge (outer)
    {'name': 'AUTH', 'color': (255, 160, 40),  'r': 200, 'glow': (255, 200, 80)},   # orange
    {'name': 'WALL', 'color': (255, 220, 0),   'r': 180, 'glow': (255, 240, 80)},   # jaune
    {'name': 'ROOT', 'color': (0, 255, 120),   'r': 160, 'glow': (80, 255, 160)},   # vert
    {'name': 'MESH', 'color': (0, 180, 255),   'r': 140, 'glow': (80, 220, 255)},   # bleu
    {'name': 'MIND', 'color': (120, 80, 255),  'r': 120, 'glow': (160, 120, 255)},  # violet (inner)
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

# API endpoints - HTTPS via nginx reverse proxy (port 8000 not exposed)
# OTG network: Pi Zero W (10.55.0.2) ← USB → ESPRESSObin (10.55.0.1)
# Main network: ESPRESSObin at 192.168.255.250
API_BASE_OTG = "https://10.55.0.1"           # ESPRESSObin via OTG USB
API_BASE_OTG_ALT = "https://192.168.255.250" # ESPRESSObin via main network
API_BASE_WIFI = "https://secubox.local"      # mDNS fallback
# Try multiple paths (depends on nginx/reverse proxy config)
API_METRICS_PATHS = [
    "/api/v1/eye-remote/api/system/info",  # Via nginx reverse proxy
    "/api/v1/hub/metrics",                  # Hub metrics fallback
    "/api/v1/system/metrics",               # Legacy path
]
API_TIMEOUT = 3

# Module-specific metrics mapping
MODULE_METRICS = {
    'AUTH': {
        'primary': 'cpu_percent',
        'details': ['processes', 'threads', 'ctx_switches'],
        'unit': '%',
        'label': 'CPU',
        'symbol': 'cpu',  # CPU chip symbol
    },
    'WALL': {
        'primary': 'mem_percent',
        'details': ['mem_used_mb', 'mem_total_mb', 'swap_percent'],
        'unit': '%',
        'label': 'MEM',
        'symbol': 'mem',  # RAM stick symbol
    },
    'BOOT': {
        'primary': 'disk_percent',
        'details': ['disk_used_gb', 'disk_total_gb', 'iops'],
        'unit': '%',
        'label': 'DISK',
        'symbol': 'disk',  # Hard drive symbol
    },
    'MIND': {
        'primary': 'load_avg_1',
        'details': ['load_avg_5', 'load_avg_15', 'uptime_hours'],
        'unit': '',
        'label': 'LOAD',
        'symbol': 'load',  # Gauge/meter symbol
    },
    'ROOT': {
        'primary': 'cpu_temp',
        'details': ['gpu_temp', 'throttled', 'voltage'],
        'unit': '°C',
        'label': 'TEMP',
        'symbol': 'temp',  # Thermometer symbol
    },
    'MESH': {
        'primary': 'wifi_rssi',
        'details': ['rx_bytes_mb', 'tx_bytes_mb', 'connections'],
        'unit': 'dBm',
        'label': 'NET',
        'symbol': 'wifi',  # WiFi signal symbol
    },
}


class FallbackManager:
    """Manages fallback display modes based on connection state."""

    def __init__(self):
        self._start_time = time.time()
        self._mode = FallbackMode.OFFLINE
        self._values: Dict[str, float] = {m['name']: 50.0 for m in MODULES}
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
        self._api_metrics: Dict[str, Any] = {}  # Metrics from gateway API
        self._last_api_fetch = 0
        self._api_fetch_interval = 2.0  # Fetch every 2s
        self._api_base = API_BASE_OTG
        self._targeted_module = 0  # Index of module targeted by radar

        # Double buffer for async API fetch - prevents display freeze
        self._metrics_buffer_a: Dict[str, Any] = {}
        self._metrics_buffer_b: Dict[str, Any] = {}
        self._active_buffer = 'a'  # Which buffer is being read by display
        self._fetch_thread: Optional[threading.Thread] = None
        self._fetch_lock = threading.Lock()
        self._fetching = False

        # Real metrics fetcher (async)
        self._metrics_fetcher: Optional['MetricsFetcher'] = None
        self._secubox_metrics: Optional['SecuBoxMetrics'] = None
        self._module_details: Dict[str, Dict[str, Any]] = {}
        self._using_real_metrics = False
        self._async_loop: Optional[asyncio.AbstractEventLoop] = None

        # Initialize metrics fetcher if available
        if HAS_METRICS_FETCHER:
            try:
                self._metrics_fetcher = get_fetcher()
                print("Real metrics fetcher initialized")
            except Exception as e:
                print(f"Metrics fetcher init failed: {e}")

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

    def _fetch_api_worker(self):
        """Background worker to fetch API metrics without blocking display."""
        # Determine which buffer to write to (opposite of active)
        write_buffer = self._metrics_buffer_b if self._active_buffer == 'a' else self._metrics_buffer_a

        success = False

        # SSL context for self-signed certificates
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        # Try each API path
        for api_path in API_METRICS_PATHS:
            try:
                url = f"{self._api_base}{api_path}"
                req = urllib.request.Request(url, headers={'Accept': 'application/json'})
                with urllib.request.urlopen(req, timeout=API_TIMEOUT, context=ssl_ctx) as resp:
                    data = json.loads(resp.read().decode())

                    # Write to inactive buffer
                    new_values: Dict[str, float] = {}

                    # CPU percent - standard field
                    if 'cpu_percent' in data:
                        new_values['AUTH'] = float(max(5, min(95, data['cpu_percent'])))

                    # Memory - ESPRESSObin uses memory_used_percent, standard uses mem_percent
                    if 'memory_used_percent' in data or 'mem_percent' in data:
                        mem_val = data.get('memory_used_percent', data.get('mem_percent', 50))
                        new_values['WALL'] = float(max(5, min(95, mem_val)))

                    # Disk - ESPRESSObin uses disk_used_percent, standard uses disk_percent
                    if 'disk_used_percent' in data or 'disk_percent' in data:
                        disk_val = data.get('disk_used_percent', data.get('disk_percent', 50))
                        new_values['BOOT'] = float(max(5, min(95, disk_val)))

                    # Load average - logarithmic scale
                    if 'load_avg_1' in data:
                        load = data['load_avg_1']
                        load_pct = 50 + 20 * math.log10(max(0.1, min(10, load))) if load > 0 else 5
                        new_values['MIND'] = float(max(5, min(95, load_pct)))

                    # CPU temperature - check multiple field names
                    temp_val = data.get('cpu_temp', data.get('temperature', None))
                    if temp_val is not None:
                        temp_pct = max(0, min(100, (temp_val - 30) / 55 * 100))
                        new_values['ROOT'] = float(max(5, min(95, temp_pct)))

                    # WiFi RSSI
                    if 'wifi_rssi' in data:
                        rssi = data['wifi_rssi']
                        rssi_pct = max(0, min(100, (rssi + 90) / 60 * 100))
                        new_values['MESH'] = float(max(5, min(95, rssi_pct)))

                    # Atomic swap to new buffer
                    with self._fetch_lock:
                        write_buffer.clear()
                        write_buffer.update(data)
                        for k, v in new_values.items():
                            self._values[k] = v
                        self._api_metrics = data
                        # Swap buffers
                        self._active_buffer = 'b' if self._active_buffer == 'a' else 'a'

                    success = True
                    break  # Success, exit loop

            except urllib.error.URLError:
                continue
            except Exception:
                continue

        # If all paths failed, try switching base URL for next attempt
        if not success:
            # Rotate through: OTG → OTG_ALT → WIFI → OTG
            if self._api_base == API_BASE_OTG:
                self._api_base = API_BASE_OTG_ALT
            elif self._api_base == API_BASE_OTG_ALT:
                self._api_base = API_BASE_WIFI
            else:
                self._api_base = API_BASE_OTG

        self._fetching = False

    def fetch_api_metrics(self):
        """Start async fetch of metrics - non-blocking, uses double buffer."""
        now = time.time()
        if now - self._last_api_fetch < self._api_fetch_interval:
            return

        # Don't start new fetch if one is already running
        if self._fetching:
            return

        self._last_api_fetch = now
        self._fetching = True

        # Use new metrics fetcher if available
        if self._metrics_fetcher is not None:
            self._fetch_thread = threading.Thread(
                target=self._fetch_real_metrics_worker, daemon=True
            )
        else:
            # Fallback to legacy worker
            self._fetch_thread = threading.Thread(
                target=self._fetch_api_worker, daemon=True
            )
        self._fetch_thread.start()

    def _fetch_real_metrics_worker(self):
        """Background worker using MetricsFetcher for real SecuBox metrics."""
        if self._metrics_fetcher is None:
            self._fetching = False
            return

        try:
            # Create event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                # Fetch all metrics from SecuBox
                metrics = loop.run_until_complete(self._metrics_fetcher.fetch_all())

                # Check connection state (with proper type guard)
                if ConnectionState is not None and metrics.connection != ConnectionState.DISCONNECTED:
                    # Get ring values and module details
                    ring_values = self._metrics_fetcher.get_ring_values()
                    module_details = self._metrics_fetcher.get_module_details()

                    with self._fetch_lock:
                        # Update ring values
                        for name, value in ring_values.items():
                            self._values[name] = float(value)

                        # Store full metrics and details
                        self._secubox_metrics = metrics
                        self._module_details = module_details
                        self._using_real_metrics = True

                        # Update API metrics dict for compatibility
                        self._api_metrics = {
                            'cpu_percent': metrics.cpu_percent,
                            'mem_percent': metrics.mem_percent,
                            'disk_percent': metrics.disk_percent,
                            'load_avg_1': metrics.load_avg_1,
                            'cpu_temp': metrics.cpu_temp,
                            'wifi_rssi': metrics.wifi_rssi,
                            'hostname': metrics.hostname,
                            'uptime_seconds': metrics.uptime_seconds,
                            'connection': metrics.connection.value,
                            'latency_ms': metrics.api_latency_ms,
                        }

                        # Update mode based on connection
                        if ConnectionState is not None:
                            if metrics.connection == ConnectionState.OTG:
                                self._mode = FallbackMode.ONLINE
                                self._api_base = API_BASE_OTG
                            elif metrics.connection == ConnectionState.WIFI:
                                self._mode = FallbackMode.ONLINE
                                self._api_base = API_BASE_WIFI
                else:
                    self._using_real_metrics = False

            finally:
                loop.close()

        except Exception as e:
            print(f"Real metrics fetch error: {e}")
            self._using_real_metrics = False

        self._fetching = False

    def get_module_detail(self, module_name: str) -> Dict[str, Any]:
        """Get detailed metrics for a specific module."""
        if self._module_details and module_name in self._module_details:
            return self._module_details[module_name]

        # Fallback to basic info from values
        value = self._values.get(module_name, 0)
        metrics_info = MODULE_METRICS.get(module_name, {})
        return {
            'primary': f"{value:.1f}",
            'label': metrics_info.get('label', module_name),
            'details': [],
            'real_data': False,
        }

    @property
    def using_real_metrics(self) -> bool:
        """Check if currently using real metrics from SecuBox."""
        return self._using_real_metrics

    @property
    def connection_type(self) -> str:
        """Get current connection type string."""
        if self._secubox_metrics:
            return self._secubox_metrics.connection.value
        return "disconnected"

    def get_targeted_module_index(self) -> int:
        """Get index of module currently targeted by radar sweep.

        Rainbow: BOOT(rouge), AUTH(orange), WALL(jaune), ROOT(vert), MESH(bleu), MIND(violet)
        New indices: BOOT=0, AUTH=1, WALL=2, ROOT=3, MESH=4, MIND=5
        Icons start at 3 o'clock (angle=0), clockwise.
        """
        sweep = self.sweep_angle
        # Direct sync
        adjusted = sweep
        position = int(adjusted / (math.pi / 3)) % 6
        # Rainbow order = module order now
        return position

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

    def _check_api_available(self, base_url: str) -> bool:
        """Check if API is actually responding - quick check with 1s timeout."""
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        try:
            url = f"{base_url}{API_METRICS_PATHS[0]}"
            req = urllib.request.Request(url, headers={'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=1.0, context=ssl_ctx) as resp:
                return resp.status == 200
        except Exception:
            return False

    def _sync_fetch_initial(self):
        """Synchronous initial fetch when transitioning to ONLINE.

        This ensures we have remote metrics before first render in ONLINE mode,
        avoiding the race condition where local metrics are shown briefly.
        """
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        for api_path in API_METRICS_PATHS:
            try:
                url = f"{self._api_base}{api_path}"
                req = urllib.request.Request(url, headers={'Accept': 'application/json'})
                with urllib.request.urlopen(req, timeout=API_TIMEOUT, context=ssl_ctx) as resp:
                    data = json.loads(resp.read().decode())

                    # Update values directly (synchronous, no threading)
                    if 'cpu_percent' in data:
                        self._values['AUTH'] = float(max(5, min(95, data['cpu_percent'])))
                    if 'memory_used_percent' in data or 'mem_percent' in data:
                        mem_val = data.get('memory_used_percent', data.get('mem_percent', 50))
                        self._values['WALL'] = float(max(5, min(95, mem_val)))
                    if 'disk_used_percent' in data or 'disk_percent' in data:
                        disk_val = data.get('disk_used_percent', data.get('disk_percent', 50))
                        self._values['BOOT'] = float(max(5, min(95, disk_val)))
                    if 'load_avg_1' in data:
                        load = data['load_avg_1']
                        load_pct = 50 + 20 * math.log10(max(0.1, min(10, load))) if load > 0 else 5
                        self._values['MIND'] = float(max(5, min(95, load_pct)))
                    temp_val = data.get('cpu_temp', data.get('temperature', None))
                    if temp_val is not None:
                        temp_pct = max(0, min(100, (temp_val - 30) / 55 * 100))
                        self._values['ROOT'] = float(max(5, min(95, temp_pct)))
                    if 'wifi_rssi' in data:
                        rssi = data['wifi_rssi']
                        rssi_pct = max(0, min(100, (rssi + 90) / 60 * 100))
                        self._values['MESH'] = float(max(5, min(95, rssi_pct)))

                    self._api_metrics = data
                    print(f"Initial sync fetch success: {data.get('hostname', 'unknown')}")
                    return True

            except Exception as e:
                continue

        return False

    def check_connection(self) -> FallbackMode:
        """Check OTG/WiFi connection - ONLINE if connected, uses local metrics if no API."""
        now = time.time()
        if now - self._last_check < self._check_interval:
            return self._mode

        self._last_check = now
        was_offline = (self._mode == FallbackMode.OFFLINE)

        # Check OTG first (10.55.0.1 - ESPRESSObin USB interface)
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', '10.55.0.1'],
                capture_output=True, timeout=2
            )
            if result.returncode == 0:
                # Connected via OTG - ONLINE mode
                self._api_base = API_BASE_OTG
                self._mode = FallbackMode.ONLINE
                # Sync fetch on transition to get initial remote metrics
                if was_offline:
                    self._sync_fetch_initial()
                return self._mode
        except Exception:
            pass

        # Check ESPRESSObin main network IP (192.168.255.250)
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', '192.168.255.250'],
                capture_output=True, timeout=2
            )
            if result.returncode == 0:
                # Connected via main network - ONLINE mode
                self._api_base = API_BASE_OTG_ALT
                self._mode = FallbackMode.ONLINE
                if was_offline:
                    self._sync_fetch_initial()
                return self._mode
        except Exception:
            pass

        # Check WiFi mDNS (secubox.local)
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', 'secubox.local'],
                capture_output=True, timeout=2
            )
            if result.returncode == 0:
                # Connected via WiFi - ONLINE mode
                self._api_base = API_BASE_WIFI
                self._mode = FallbackMode.ONLINE
                # Sync fetch on transition to get initial remote metrics
                if was_offline:
                    self._sync_fetch_initial()
                return self._mode
        except Exception:
            pass

        # No connection at all
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
                        cpu_pct = 100.0 * (1 - diff_idle / diff_total)
                        self._values['AUTH'] = float(max(5, min(95, cpu_pct)))

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
                mem_pct = 100.0 * (1 - avail / total)
                self._values['WALL'] = float(max(5, min(95, mem_pct)))

            # Disk from os.statvfs
            st = os.statvfs('/')
            disk_pct = 100.0 * (1 - st.f_bavail / st.f_blocks)
            self._values['BOOT'] = float(max(5, min(95, disk_pct)))

            # Load average - logarithmic scale for spikes
            load1, _, _ = os.getloadavg()
            # Pi Zero has 1 core: load 0.1=10%, 1.0=50%, 10.0=90% (log scale)
            if load1 > 0:
                load_pct = 50.0 + 20.0 * math.log10(max(0.1, min(10, load1)))
            else:
                load_pct = 5.0
            self._values['MIND'] = float(max(5, min(95, load_pct)))

            # CPU temperature
            try:
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                    temp_c = int(f.read().strip()) / 1000.0
                    # Scale: 30°C=0%, 85°C=100%
                    temp_pct = max(0.0, min(100.0, (temp_c - 30) / 55 * 100))
                    self._values['ROOT'] = float(max(5, min(95, temp_pct)))
            except Exception:
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
                                net_pct = 10.0 * math.log10(max(1, total_bytes / 100))
                                net_pct = float(max(5, min(95, net_pct)))
                            else:
                                net_pct = 5.0
                            self._values['MESH'] = net_pct
                            break
            except Exception:
                pass

        except Exception:
            # Fallback to small random drift if metrics fail
            for m in MODULES:
                name = m['name']
                delta = (random.random() - 0.5) * 2
                self._values[name] = float(max(20, min(95, self._values[name] + delta)))

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
        self.check_connection()

        # Update metrics based on mode
        if self._mode in (FallbackMode.ONLINE, FallbackMode.COMMUNICATING):
            # Online: use API metrics (fetch async), only use local as fallback
            self.fetch_api_metrics()
            # Only update local if we have no API data yet
            if not self._api_metrics:
                self.update_local_metrics()
        else:
            # Offline: always use local metrics
            self.update_local_metrics()

        # Track which module is targeted by radar
        self._targeted_module = self.get_targeted_module_index()

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

        # Gadget status bar (bottom of screen) - only when online via OTG
        if HAS_GADGET_STATUS and self._mode in (FallbackMode.ONLINE, FallbackMode.COMMUNICATING):
            try:
                render_gadget_status_bar(draw, y=455)
            except Exception:
                pass  # Silently ignore rendering errors

        # Gadget indicator (corner badge) - show when any gadget mode is active
        elif HAS_GADGET_STATUS:
            try:
                render_gadget_indicator(draw, x=WIDTH - 30, y=HEIGHT - 25)
            except Exception:
                pass

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

    def _draw_metric_symbol(self, draw, cx, cy, symbol, color, size=18):
        """Draw a metric symbol (CPU, MEM, DISK, etc.) centered in targeting circle.

        All symbols fit within a 24px radius circle (the targeting glow is 30px).
        """
        bright = (min(255, color[0] + 100), min(255, color[1] + 100), min(255, color[2] + 100))
        dark = (color[0] // 2, color[1] // 2, color[2] // 2)

        if symbol == 'cpu':
            # CPU chip: square with pins - fits in 24px
            s = 10
            draw.rectangle([cx - s, cy - s, cx + s, cy + s], outline=bright, width=2)
            draw.rectangle([cx - s + 3, cy - s + 3, cx + s - 3, cy + s - 3], fill=color)
            # Pins (shorter)
            for i in range(-1, 2):
                draw.line([(cx + i * 5, cy - s - 3), (cx + i * 5, cy - s)], fill=bright, width=2)
                draw.line([(cx + i * 5, cy + s), (cx + i * 5, cy + s + 3)], fill=bright, width=2)
                draw.line([(cx - s - 3, cy + i * 5), (cx - s, cy + i * 5)], fill=bright, width=2)
                draw.line([(cx + s, cy + i * 5), (cx + s + 3, cy + i * 5)], fill=bright, width=2)

        elif symbol == 'mem':
            # RAM stick: compact rectangle - fits in 24px
            w, h = 18, 8
            draw.rectangle([cx - w, cy - h, cx + w, cy + h], outline=bright, width=2)
            # Chips on RAM
            for i in range(-3, 4):
                draw.rectangle([cx + i * 5 - 1, cy - h + 2, cx + i * 5 + 1, cy + h - 2], fill=color)

        elif symbol == 'disk':
            # Floppy disk: classic 3.5" diskette icon - fits in 24px
            s = 11  # half-size
            # Main body (square with slight rounding)
            draw.rectangle([cx - s, cy - s, cx + s, cy + s], fill=dark, outline=bright, width=2)
            # Metal slider at top
            draw.rectangle([cx - 4, cy - s, cx + 4, cy - s + 5], fill=bright)
            # Notch in slider
            draw.rectangle([cx - 1, cy - s, cx + 1, cy - s + 3], fill=dark)
            # Label area (center rectangle)
            draw.rectangle([cx - 7, cy + 1, cx + 7, cy + s - 2], fill=color, outline=bright, width=1)

        elif symbol == 'load':
            # Gauge/meter: semicircle with needle - fits in 24px
            r = 14
            draw.arc([cx - r, cy - r + 4, cx + r, cy + r + 4], 180, 0, fill=bright, width=3)
            # Needle pointing based on load value
            value = self._values.get('MIND', 50) / 100
            needle_angle = math.pi * (1 - value)
            nx = cx + int((r - 2) * math.cos(needle_angle))
            ny = cy + 4 - int((r - 2) * math.sin(needle_angle))
            draw.line([(cx, cy + 4), (nx, ny)], fill=color, width=2)
            draw.ellipse([cx - 3, cy + 1, cx + 3, cy + 7], fill=bright)

        elif symbol == 'temp':
            # Thermometer: compact - fits in 24px
            # Bulb at bottom
            draw.ellipse([cx - 5, cy + 6, cx + 5, cy + 16], fill=color, outline=bright, width=1)
            # Tube
            draw.rectangle([cx - 3, cy - 14, cx + 3, cy + 8], fill=dark, outline=bright, width=1)
            # Mercury level based on temp
            value = self._values.get('ROOT', 50) / 100
            level = int(18 * value)
            draw.rectangle([cx - 2, cy + 6 - level, cx + 2, cy + 6], fill=color)

        elif symbol == 'wifi':
            # WiFi signal: compact arcs - fits in 24px
            for i in range(3):
                arc_r = 5 + i * 6
                alpha = 255 if i < int(3 * self._values.get('MESH', 50) / 100) + 1 else 80
                c = (bright[0], bright[1], bright[2]) if alpha > 100 else dark
                draw.arc([cx - arc_r, cy - arc_r + 6, cx + arc_r, cy + arc_r + 6],
                        225, 315, fill=c, width=2)
            draw.ellipse([cx - 2, cy + 10, cx + 2, cy + 14], fill=bright)

    def _draw_center_icons(self, draw, sweep, pulse, single_mode=False):
        """Draw 6 module icons in circle, color ordered.

        Circle order (clockwise from top): red, orange, yellow, green, blue, purple
        Maps to: AUTH, WALL, BOOT, ROOT, MESH, MIND

        If single_mode=True, show one centered cycling icon only.
        When radar targets a module, show metric symbol instead of module icon.
        """
        icon_r = 62  # Radius for icon placement

        # Rainbow: rouge, orange, jaune, vert, bleu, violet
        # New indices: BOOT=0, AUTH=1, WALL=2, ROOT=3, MESH=4, MIND=5
        icon_order = [
            ('boot', 0),   # pos 0: rouge
            ('auth', 1),   # pos 1: orange
            ('wall', 2),   # pos 2: jaune
            ('root', 3),   # pos 3: vert
            ('mesh', 4),   # pos 4: bleu
            ('mind', 5),   # pos 5: violet
        ]

        # Determine which icon to show in single mode (cycle every 2 seconds)
        if single_mode:
            cycle_index = int(time.time() / 2) % 6
        else:
            cycle_index = -1  # Show all

        for pos_idx, (name, module_idx) in enumerate(icon_order):
            m = MODULES[module_idx]

            # In single mode, only draw the current cycling icon - CENTERED
            if single_mode and pos_idx != cycle_index:
                continue

            if single_mode:
                # Center the single icon (no metric text below)
                ix, iy = CENTER, CENTER - 10
            else:
                # Position in circle, shifted one step back
                angle = (pos_idx / 6) * 2 * math.pi - math.pi/3
                ix = int(CENTER + icon_r * math.cos(angle))
                iy = int(CENTER + icon_r * math.sin(angle))

            # Highlight if targeted by radar (online mode only)
            is_targeted = (not single_mode and module_idx == self._targeted_module)

            if is_targeted:
                # Glow ring around targeted icon
                glow_color = m['color']
                draw.ellipse([ix - 30, iy - 30, ix + 30, iy + 30],
                            outline=glow_color, width=3)

                # Draw metric symbol instead of module icon when targeted
                # Symbol fits inside the 30px glow circle
                metrics_info = MODULE_METRICS.get(m['name'], {})
                symbol = metrics_info.get('symbol', 'cpu')
                self._draw_metric_symbol(draw, ix, iy, symbol, m['color'])

            elif name in self._icons:
                # Draw 48px PNG icon (centered) - normal state
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

        # Tube-style arcs - each arc centered at its icon direction
        # New order: BOOT=0, AUTH=1, WALL=2, ROOT=3, MESH=4, MIND=5
        # Each module index = its icon position (rainbow order matches)
        module_to_pos = [0, 1, 2, 3, 4, 5]

        for idx, m in enumerate(MODULES):
            r = m['r']
            color = m['color']
            value = self._values[m['name']]

            # PIL degrees: swap red↔yellow and green↔purple
            # pos: 0=red, 1=orange, 2=yellow, 3=green, 4=blue, 5=purple
            pil_angles = [300, 0, 60, 120, 180, 240]
            icon_pos = module_to_pos[idx]
            center_deg = pil_angles[icon_pos]

            arc_extent = (value / 100) * 360
            half = arc_extent / 2
            start = center_deg + half
            end = center_deg - half

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

        # Center is left clean for icons (metrics shown via _draw_targeted_metrics)

    def _draw_targeted_metrics(self, draw):
        """Draw detailed metrics for the radar-targeted module."""
        idx = self._targeted_module
        m = MODULES[idx]
        name = m['name']
        color = m['color']

        # Get module details (real or fallback)
        details = self.get_module_detail(name)

        primary = details.get('primary', '?')
        label = details.get('label', name)
        extra_details = details.get('details', [])
        has_real = details.get('real_data', False)

        # Draw in center - below icons area
        # Module label with real data indicator
        label_color = color if has_real else (color[0]//2, color[1]//2, color[2]//2)
        draw.text((CENTER - 15, CENTER + 35), label, fill=label_color)

        # Primary value
        draw.text((CENTER - 25, CENTER + 50), str(primary), fill=(200, 200, 210))

        # Show first extra detail if available (small text)
        if extra_details and len(extra_details) > 0:
            detail_text = extra_details[0][:20]  # Truncate
            draw.text((CENTER - 40, CENTER + 65), detail_text, fill=(120, 120, 130))

    def _draw_single_metric(self, draw, idx):
        """Draw metric for single cycling icon (offline mode)."""
        m = MODULES[idx]
        name = m['name']
        color = m['color']
        metrics_info = MODULE_METRICS.get(name, {})

        label = metrics_info.get('label', name)
        unit = metrics_info.get('unit', '')
        value = self._values.get(name, 0)

        # Format value
        if isinstance(value, float):
            value_str = f"{value:.1f}"
        else:
            value_str = str(value)

        # Draw below centered icon
        draw.text((CENTER - 15, CENTER + 35), label, fill=color)
        val_text = f"{value_str}{unit}"
        draw.text((CENTER - 20, CENTER + 50), val_text, fill=(180, 180, 190))

    def _draw_mode_indicator(self, draw, pulse):
        """Draw connection mode indicator with real/local data source."""
        mode_colors = {
            FallbackMode.OFFLINE: (255, 80, 80),
            FallbackMode.CONNECTING: (255, 200, 0),
            FallbackMode.ONLINE: (0, 255, 100),
            FallbackMode.COMMUNICATING: (0, 200, 255),
        }

        color = mode_colors.get(self._mode, (100, 100, 100))

        # Build label with connection type and data source
        if self._mode == FallbackMode.ONLINE:
            conn_type = self.connection_type.upper()
            if self._using_real_metrics:
                label = f"{conn_type}"
                # Add latency if available
                if self._secubox_metrics and self._secubox_metrics.api_latency_ms > 0:
                    label += f" {self._secubox_metrics.api_latency_ms:.0f}ms"
            else:
                label = f"{conn_type} LOCAL"
        elif self._mode == FallbackMode.OFFLINE:
            label = "LOCAL"
        elif self._mode == FallbackMode.CONNECTING:
            label = "CONNECTING"
        else:
            label = "SYNC"

        # Pulsing dot - different color if using real data
        if self._using_real_metrics:
            # Cyan dot for real metrics
            dot_color = (0, 220, 255)
        else:
            dot_color = color

        size = int(5 + pulse * 3)
        draw.ellipse([15 - size, 15 - size, 15 + size, 15 + size], fill=dot_color)
        draw.text((25, 10), label, fill=color)

        # Show hostname if connected
        if self._mode == FallbackMode.ONLINE and self._secubox_metrics:
            hostname = self._secubox_metrics.hostname[:12]  # Truncate
            draw.text((WIDTH - 100, 10), hostname, fill=(150, 150, 160))


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
