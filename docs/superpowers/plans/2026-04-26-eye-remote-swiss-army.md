# Eye Remote Swiss Army Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform Eye Remote into a multi-mode Swiss Army dashboard with 4 operating modes, web-based control, and intelligent failover.

**Architecture:** Unified Python Agent extending existing `fb_dashboard.py` and `agent/` code. Single async process handles framebuffer rendering, FastAPI web server, mode state machine, and system controls. Communication with SecuBox via existing `secubox_client.py`.

**Tech Stack:** Python 3.11+, FastAPI, Uvicorn, Pillow, httpx, nmcli, bluetoothctl

**Spec:** `docs/superpowers/specs/2026-04-26-eye-remote-swiss-army-design.md`

---

## Phase 1: Core Infrastructure

### Task 1: Create Mode Enum and State Machine

**Files:**
- Create: `remote-ui/round/agent/mode_manager.py`
- Test: `remote-ui/round/tests/test_mode_manager.py`

- [ ] **Step 1: Write the failing test for Mode enum**

```python
# remote-ui/round/tests/test_mode_manager.py
"""Tests for mode manager state machine."""
import pytest
from agent.mode_manager import Mode, ModeManager

def test_mode_enum_values():
    """Mode enum should have 4 modes."""
    assert Mode.DASHBOARD.value == "dashboard"
    assert Mode.LOCAL.value == "local"
    assert Mode.FLASH.value == "flash"
    assert Mode.GATEWAY.value == "gateway"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd remote-ui/round && python -m pytest tests/test_mode_manager.py::test_mode_enum_values -v`
Expected: FAIL with "No module named 'agent.mode_manager'"

- [ ] **Step 3: Create mode_manager.py with Mode enum**

```python
# remote-ui/round/agent/mode_manager.py
"""
SecuBox Eye Remote — Mode Manager
State machine for 4 operating modes: Dashboard, Local, Flash, Gateway.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import logging
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger(__name__)


class Mode(Enum):
    """Operating modes for Eye Remote."""
    DASHBOARD = "dashboard"
    LOCAL = "local"
    FLASH = "flash"
    GATEWAY = "gateway"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd remote-ui/round && python -m pytest tests/test_mode_manager.py::test_mode_enum_values -v`
Expected: PASS

- [ ] **Step 5: Write failing test for ModeManager initialization**

```python
# Append to remote-ui/round/tests/test_mode_manager.py
def test_mode_manager_init():
    """ModeManager should start in LOCAL mode by default."""
    mm = ModeManager()
    assert mm.current_mode == Mode.LOCAL
    assert mm.previous_mode is None

def test_mode_manager_init_with_mode():
    """ModeManager can be initialized with specific mode."""
    mm = ModeManager(initial_mode=Mode.DASHBOARD)
    assert mm.current_mode == Mode.DASHBOARD
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cd remote-ui/round && python -m pytest tests/test_mode_manager.py::test_mode_manager_init -v`
Expected: FAIL with "ModeManager not defined"

- [ ] **Step 7: Implement ModeManager class**

```python
# Append to remote-ui/round/agent/mode_manager.py

# Flag file paths (on USB storage partition)
FLAG_FILE_FLASH = Path("/var/lib/secubox/eye-remote/storage/FORCE_FLASH")
FLAG_FILE_GATEWAY = Path("/var/lib/secubox/eye-remote/storage/FORCE_GATEWAY")


class ModeManager:
    """
    State machine for Eye Remote operating modes.

    Modes:
    - DASHBOARD: Real-time SecuBox metrics (when API available)
    - LOCAL: Pi Zero self-monitoring (API unavailable)
    - FLASH: USB storage mode for ESPRESSObin recovery
    - GATEWAY: Multi-SecuBox fleet management

    Mode selection:
    1. Check flag files (FORCE_FLASH, FORCE_GATEWAY)
    2. Auto-detect based on SecuBox API availability
    """

    def __init__(self, initial_mode: Mode = Mode.LOCAL):
        self._current_mode = initial_mode
        self._previous_mode: Optional[Mode] = None
        self._listeners: list[Callable[[Mode, Mode], None]] = []
        self._lock = asyncio.Lock()

    @property
    def current_mode(self) -> Mode:
        """Current operating mode."""
        return self._current_mode

    @property
    def previous_mode(self) -> Optional[Mode]:
        """Previous operating mode (before last transition)."""
        return self._previous_mode

    def add_listener(self, callback: Callable[[Mode, Mode], None]) -> None:
        """Add a mode change listener. Callback receives (old_mode, new_mode)."""
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[Mode, Mode], None]) -> None:
        """Remove a mode change listener."""
        if callback in self._listeners:
            self._listeners.remove(callback)

    async def set_mode(self, new_mode: Mode) -> bool:
        """
        Transition to a new mode.

        Args:
            new_mode: Target mode

        Returns:
            True if mode changed, False if already in that mode
        """
        async with self._lock:
            if new_mode == self._current_mode:
                return False

            old_mode = self._current_mode
            self._previous_mode = old_mode
            self._current_mode = new_mode

            log.info(f"Mode transition: {old_mode.value} -> {new_mode.value}")

            # Notify listeners
            for listener in self._listeners:
                try:
                    listener(old_mode, new_mode)
                except Exception as e:
                    log.error(f"Mode listener error: {e}")

            return True

    def check_flag_files(self) -> Optional[Mode]:
        """
        Check for flag files that force a specific mode.

        Returns:
            Forced mode or None if no flag files present
        """
        if FLAG_FILE_FLASH.exists():
            log.info(f"Found {FLAG_FILE_FLASH}, forcing FLASH mode")
            return Mode.FLASH

        if FLAG_FILE_GATEWAY.exists():
            log.info(f"Found {FLAG_FILE_GATEWAY}, forcing GATEWAY mode")
            return Mode.GATEWAY

        return None

    async def determine_initial_mode(self, api_available: bool) -> Mode:
        """
        Determine initial mode based on flag files and API availability.

        Args:
            api_available: Whether SecuBox API is reachable

        Returns:
            Appropriate initial mode
        """
        # Check flag files first (highest priority)
        forced_mode = self.check_flag_files()
        if forced_mode:
            await self.set_mode(forced_mode)
            return forced_mode

        # Auto-detect based on API
        if api_available:
            await self.set_mode(Mode.DASHBOARD)
            return Mode.DASHBOARD
        else:
            await self.set_mode(Mode.LOCAL)
            return Mode.LOCAL
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd remote-ui/round && python -m pytest tests/test_mode_manager.py -v`
Expected: All PASS

- [ ] **Step 9: Commit**

```bash
git add remote-ui/round/agent/mode_manager.py remote-ui/round/tests/test_mode_manager.py
git commit -m "feat(eye-remote): Add Mode enum and ModeManager state machine"
```

---

### Task 2: Add Mode Transition Tests

**Files:**
- Modify: `remote-ui/round/tests/test_mode_manager.py`

- [ ] **Step 1: Write failing tests for mode transitions**

```python
# Append to remote-ui/round/tests/test_mode_manager.py
import asyncio

@pytest.mark.asyncio
async def test_set_mode_changes_mode():
    """set_mode should change current mode."""
    mm = ModeManager(initial_mode=Mode.LOCAL)
    result = await mm.set_mode(Mode.DASHBOARD)
    assert result is True
    assert mm.current_mode == Mode.DASHBOARD
    assert mm.previous_mode == Mode.LOCAL

@pytest.mark.asyncio
async def test_set_mode_same_mode_returns_false():
    """set_mode with same mode should return False."""
    mm = ModeManager(initial_mode=Mode.LOCAL)
    result = await mm.set_mode(Mode.LOCAL)
    assert result is False
    assert mm.current_mode == Mode.LOCAL

@pytest.mark.asyncio
async def test_mode_listener_called():
    """Mode change should notify listeners."""
    mm = ModeManager(initial_mode=Mode.LOCAL)
    calls = []

    def listener(old_mode, new_mode):
        calls.append((old_mode, new_mode))

    mm.add_listener(listener)
    await mm.set_mode(Mode.DASHBOARD)

    assert len(calls) == 1
    assert calls[0] == (Mode.LOCAL, Mode.DASHBOARD)

@pytest.mark.asyncio
async def test_determine_initial_mode_with_api():
    """Should select DASHBOARD when API available."""
    mm = ModeManager()
    mode = await mm.determine_initial_mode(api_available=True)
    assert mode == Mode.DASHBOARD

@pytest.mark.asyncio
async def test_determine_initial_mode_without_api():
    """Should select LOCAL when API unavailable."""
    mm = ModeManager()
    mode = await mm.determine_initial_mode(api_available=False)
    assert mode == Mode.LOCAL
```

- [ ] **Step 2: Run tests**

Run: `cd remote-ui/round && python -m pytest tests/test_mode_manager.py -v`
Expected: All PASS (implementation already supports this)

- [ ] **Step 3: Commit**

```bash
git add remote-ui/round/tests/test_mode_manager.py
git commit -m "test(eye-remote): Add mode transition tests"
```

---

### Task 3: Create Failover Monitor

**Files:**
- Create: `remote-ui/round/agent/failover.py`
- Test: `remote-ui/round/tests/test_failover.py`

- [ ] **Step 1: Write failing test for FailoverState**

```python
# remote-ui/round/tests/test_failover.py
"""Tests for failover monitoring."""
import pytest
from agent.failover import FailoverState, FailoverMonitor

def test_failover_state_enum():
    """FailoverState should have correct states."""
    assert FailoverState.CONNECTED.value == "connected"
    assert FailoverState.STALE.value == "stale"
    assert FailoverState.DEGRADED.value == "degraded"
    assert FailoverState.DISCONNECTED.value == "disconnected"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd remote-ui/round && python -m pytest tests/test_failover.py::test_failover_state_enum -v`
Expected: FAIL with "No module named 'agent.failover'"

- [ ] **Step 3: Create failover.py**

```python
# remote-ui/round/agent/failover.py
"""
SecuBox Eye Remote — Failover Monitor
Monitors SecuBox API connection and manages graceful degradation.

Staged failover:
- 0s: Stale data + pulsing OFFLINE badge
- 15s: Rings fade to gray
- 60s: Full transition to Local mode

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import logging
import time
from enum import Enum
from typing import Callable, Optional

log = logging.getLogger(__name__)


class FailoverState(Enum):
    """Connection state for failover logic."""
    CONNECTED = "connected"      # API responding normally
    STALE = "stale"              # Data stale, showing OFFLINE badge (0-15s)
    DEGRADED = "degraded"        # Rings grayed out (15-60s)
    DISCONNECTED = "disconnected"  # Full transition to Local mode (60s+)


# Failover timing constants (seconds)
STALE_THRESHOLD = 0      # Immediate on disconnect
DEGRADED_THRESHOLD = 15  # Gray out rings
DISCONNECT_THRESHOLD = 60  # Switch to Local mode
RECONNECT_INTERVAL = 10  # Check API every N seconds


class FailoverMonitor:
    """
    Monitors SecuBox API connection and manages failover states.

    Provides staged degradation with visual feedback:
    1. CONNECTED: Normal operation
    2. STALE: Show offline badge, data getting old
    3. DEGRADED: Visual degradation (gray rings)
    4. DISCONNECTED: Full switch to Local mode
    """

    def __init__(
        self,
        stale_threshold: float = STALE_THRESHOLD,
        degraded_threshold: float = DEGRADED_THRESHOLD,
        disconnect_threshold: float = DISCONNECT_THRESHOLD,
        reconnect_interval: float = RECONNECT_INTERVAL,
    ):
        self._state = FailoverState.DISCONNECTED
        self._last_success: Optional[float] = None
        self._listeners: list[Callable[[FailoverState, FailoverState], None]] = []

        self._stale_threshold = stale_threshold
        self._degraded_threshold = degraded_threshold
        self._disconnect_threshold = disconnect_threshold
        self._reconnect_interval = reconnect_interval

        self._check_task: Optional[asyncio.Task] = None
        self._api_check_fn: Optional[Callable[[], bool]] = None

    @property
    def state(self) -> FailoverState:
        """Current failover state."""
        return self._state

    @property
    def seconds_since_success(self) -> float:
        """Seconds since last successful API response."""
        if self._last_success is None:
            return float('inf')
        return time.time() - self._last_success

    def add_listener(self, callback: Callable[[FailoverState, FailoverState], None]) -> None:
        """Add a state change listener."""
        self._listeners.append(callback)

    def _notify_listeners(self, old_state: FailoverState, new_state: FailoverState) -> None:
        """Notify all listeners of state change."""
        for listener in self._listeners:
            try:
                listener(old_state, new_state)
            except Exception as e:
                log.error(f"Failover listener error: {e}")

    def record_success(self) -> None:
        """Record a successful API response."""
        self._last_success = time.time()
        if self._state != FailoverState.CONNECTED:
            old_state = self._state
            self._state = FailoverState.CONNECTED
            log.info("API connection restored")
            self._notify_listeners(old_state, self._state)

    def update_state(self) -> FailoverState:
        """
        Update failover state based on time since last success.

        Returns:
            Current failover state
        """
        elapsed = self.seconds_since_success
        old_state = self._state

        if elapsed <= self._stale_threshold:
            self._state = FailoverState.CONNECTED
        elif elapsed <= self._degraded_threshold:
            self._state = FailoverState.STALE
        elif elapsed <= self._disconnect_threshold:
            self._state = FailoverState.DEGRADED
        else:
            self._state = FailoverState.DISCONNECTED

        if self._state != old_state:
            log.info(f"Failover state: {old_state.value} -> {self._state.value}")
            self._notify_listeners(old_state, self._state)

        return self._state

    async def start_monitoring(self, api_check_fn: Callable[[], bool]) -> None:
        """
        Start background monitoring task.

        Args:
            api_check_fn: Async function that returns True if API is reachable
        """
        self._api_check_fn = api_check_fn
        self._check_task = asyncio.create_task(self._monitor_loop())

    async def stop_monitoring(self) -> None:
        """Stop background monitoring task."""
        if self._check_task:
            self._check_task.cancel()
            try:
                await self._check_task
            except asyncio.CancelledError:
                pass

    async def _monitor_loop(self) -> None:
        """Background loop that checks API and updates state."""
        while True:
            try:
                # Update state based on elapsed time
                self.update_state()

                # If disconnected, try to reconnect
                if self._state == FailoverState.DISCONNECTED and self._api_check_fn:
                    try:
                        if await asyncio.wait_for(
                            asyncio.to_thread(self._api_check_fn),
                            timeout=3.0
                        ):
                            self.record_success()
                    except (asyncio.TimeoutError, Exception) as e:
                        log.debug(f"API check failed: {e}")

                await asyncio.sleep(self._reconnect_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Failover monitor error: {e}")
                await asyncio.sleep(self._reconnect_interval)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd remote-ui/round && python -m pytest tests/test_failover.py::test_failover_state_enum -v`
Expected: PASS

- [ ] **Step 5: Write more failover tests**

```python
# Append to remote-ui/round/tests/test_failover.py
import time

def test_failover_monitor_init():
    """FailoverMonitor should start DISCONNECTED."""
    fm = FailoverMonitor()
    assert fm.state == FailoverState.DISCONNECTED
    assert fm.seconds_since_success == float('inf')

def test_record_success_changes_state():
    """record_success should transition to CONNECTED."""
    fm = FailoverMonitor()
    fm.record_success()
    assert fm.state == FailoverState.CONNECTED
    assert fm.seconds_since_success < 1.0

def test_update_state_progression():
    """State should progress through stages based on time."""
    fm = FailoverMonitor(
        stale_threshold=0,
        degraded_threshold=0.1,
        disconnect_threshold=0.2,
    )

    # Start connected
    fm.record_success()
    assert fm.state == FailoverState.CONNECTED

    # Wait for stale
    time.sleep(0.05)
    fm.update_state()
    assert fm.state == FailoverState.STALE

    # Wait for degraded
    time.sleep(0.1)
    fm.update_state()
    assert fm.state == FailoverState.DEGRADED

    # Wait for disconnected
    time.sleep(0.15)
    fm.update_state()
    assert fm.state == FailoverState.DISCONNECTED

def test_failover_listener_called():
    """State change should notify listeners."""
    fm = FailoverMonitor()
    calls = []

    def listener(old_state, new_state):
        calls.append((old_state, new_state))

    fm.add_listener(listener)
    fm.record_success()

    assert len(calls) == 1
    assert calls[0] == (FailoverState.DISCONNECTED, FailoverState.CONNECTED)
```

- [ ] **Step 6: Run all failover tests**

Run: `cd remote-ui/round && python -m pytest tests/test_failover.py -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add remote-ui/round/agent/failover.py remote-ui/round/tests/test_failover.py
git commit -m "feat(eye-remote): Add FailoverMonitor with staged degradation"
```

---

### Task 4: Create Display Renderer Base Class

**Files:**
- Create: `remote-ui/round/agent/display/__init__.py`
- Create: `remote-ui/round/agent/display/renderer.py`
- Test: `remote-ui/round/tests/test_display_renderer.py`

- [ ] **Step 1: Create display package init**

```python
# remote-ui/round/agent/display/__init__.py
"""Display rendering modules for Eye Remote."""
from .renderer import DisplayRenderer, RenderContext

__all__ = ['DisplayRenderer', 'RenderContext']
```

- [ ] **Step 2: Write failing test for DisplayRenderer**

```python
# remote-ui/round/tests/test_display_renderer.py
"""Tests for display renderer."""
import pytest
from PIL import Image
from agent.display.renderer import DisplayRenderer, RenderContext

def test_render_context_creation():
    """RenderContext should hold display state."""
    ctx = RenderContext(
        width=480,
        height=480,
        mode="dashboard",
        connection_state="connected",
    )
    assert ctx.width == 480
    assert ctx.height == 480
    assert ctx.mode == "dashboard"

def test_display_renderer_creates_image():
    """DisplayRenderer should create PIL Image."""
    renderer = DisplayRenderer(width=480, height=480)
    img = renderer.create_frame()
    assert isinstance(img, Image.Image)
    assert img.size == (480, 480)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd remote-ui/round && python -m pytest tests/test_display_renderer.py -v`
Expected: FAIL with "No module named 'agent.display'"

- [ ] **Step 4: Create renderer.py**

```python
# remote-ui/round/agent/display/renderer.py
"""
SecuBox Eye Remote — Display Renderer Base
Base class for framebuffer rendering on HyperPixel 2.1 Round (480x480).

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple

from PIL import Image, ImageDraw, ImageFont

log = logging.getLogger(__name__)

# Display constants
WIDTH = 480
HEIGHT = 480
FB_DEV = '/dev/fb0'

# Colors (RGB)
BG_COLOR = (8, 8, 12)           # Deep space black
TEXT_COLOR = (240, 240, 250)    # Bright white
TEXT_MUTED = (130, 130, 150)    # Soft gray-blue
STATUS_OK = (0, 255, 65)        # Neon green
STATUS_WARN = (255, 100, 0)     # Neon orange
STATUS_ERROR = (255, 0, 80)     # Neon red
STATUS_OFFLINE = (100, 100, 120)  # Dim gray

# Module colors (Neon Rainbow)
MODULE_COLORS = {
    'AUTH': (255, 0, 100),    # Neon Magenta
    'WALL': (255, 100, 0),    # Neon Orange
    'BOOT': (220, 255, 0),    # Neon Yellow
    'MIND': (0, 255, 65),     # Matrix Green
    'ROOT': (0, 255, 255),    # Cyber Cyan
    'MESH': (185, 0, 255),    # Laser Purple
}


@dataclass
class RenderContext:
    """Context passed to render methods."""
    width: int = WIDTH
    height: int = HEIGHT
    mode: str = "local"
    connection_state: str = "disconnected"
    metrics: dict = field(default_factory=dict)
    hostname: str = "eye-remote"
    uptime_seconds: int = 0
    secubox_name: str = ""
    alert_count: int = 0
    flash_progress: float = 0.0
    devices: list = field(default_factory=list)


class DisplayRenderer:
    """
    Base display renderer for Eye Remote.

    Handles:
    - PIL Image creation and management
    - Framebuffer output
    - Common drawing utilities
    - Font loading
    """

    def __init__(self, width: int = WIDTH, height: int = HEIGHT):
        self.width = width
        self.height = height
        self.center = (width // 2, height // 2)

        # Font cache
        self._fonts: dict[str, ImageFont.FreeTypeFont] = {}
        self._load_fonts()

        # Current frame
        self._frame: Optional[Image.Image] = None

        # Framebuffer info
        self._fb_info: Optional[dict] = None

    def _load_fonts(self) -> None:
        """Load system fonts."""
        font_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
            "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
        ]

        sizes = {'small': 12, 'medium': 16, 'large': 24, 'xlarge': 32, 'time': 48}

        for name, size in sizes.items():
            for path in font_paths:
                if os.path.exists(path):
                    try:
                        self._fonts[name] = ImageFont.truetype(path, size)
                        break
                    except Exception:
                        pass

            # Fallback to default
            if name not in self._fonts:
                self._fonts[name] = ImageFont.load_default()

    def get_font(self, name: str = 'medium') -> ImageFont.FreeTypeFont:
        """Get a named font."""
        return self._fonts.get(name, self._fonts.get('medium'))

    def create_frame(self) -> Image.Image:
        """Create a new frame with background color."""
        self._frame = Image.new('RGB', (self.width, self.height), BG_COLOR)
        return self._frame

    def get_draw(self) -> ImageDraw.ImageDraw:
        """Get ImageDraw for current frame."""
        if self._frame is None:
            self.create_frame()
        return ImageDraw.Draw(self._frame)

    def draw_text_centered(
        self,
        draw: ImageDraw.ImageDraw,
        text: str,
        y: int,
        font_name: str = 'medium',
        color: Tuple[int, int, int] = TEXT_COLOR,
    ) -> None:
        """Draw text centered horizontally."""
        font = self.get_font(font_name)
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        x = (self.width - text_width) // 2
        draw.text((x, y), text, font=font, fill=color)

    def draw_circle_mask(self, draw: ImageDraw.ImageDraw) -> None:
        """Apply circular mask for round display."""
        # Create mask for corners
        mask = Image.new('L', (self.width, self.height), 0)
        mask_draw = ImageDraw.Draw(mask)
        mask_draw.ellipse([0, 0, self.width - 1, self.height - 1], fill=255)

        # Apply mask
        if self._frame:
            bg = Image.new('RGB', (self.width, self.height), (0, 0, 0))
            self._frame = Image.composite(self._frame, bg, mask)

    def write_to_framebuffer(self) -> bool:
        """
        Write current frame to /dev/fb0.

        Returns:
            True if successful
        """
        if self._frame is None:
            return False

        try:
            # Get framebuffer info if not cached
            if self._fb_info is None:
                self._fb_info = self._get_fb_info()

            # Convert to RGB565 for framebuffer
            rgb565 = self._convert_to_rgb565(self._frame)

            with open(FB_DEV, 'wb') as fb:
                fb.write(rgb565)

            return True

        except Exception as e:
            log.error(f"Failed to write framebuffer: {e}")
            return False

    def _get_fb_info(self) -> dict:
        """Get framebuffer info from FBIOGET_VSCREENINFO."""
        import fcntl

        FBIOGET_VSCREENINFO = 0x4600

        try:
            with open(FB_DEV, 'rb') as fb:
                info = fcntl.ioctl(fb.fileno(), FBIOGET_VSCREENINFO, b'\x00' * 160)
                xres, yres = struct.unpack('II', info[:8])
                bits_per_pixel = struct.unpack('I', info[24:28])[0]
                return {
                    'xres': xres,
                    'yres': yres,
                    'bpp': bits_per_pixel,
                }
        except Exception:
            return {'xres': self.width, 'yres': self.height, 'bpp': 16}

    def _convert_to_rgb565(self, img: Image.Image) -> bytes:
        """Convert PIL Image to RGB565 bytes for framebuffer."""
        rgb = img.convert('RGB')
        pixels = list(rgb.getdata())

        result = bytearray(len(pixels) * 2)
        for i, (r, g, b) in enumerate(pixels):
            # RGB565: RRRRRGGGGGGBBBBB
            rgb565 = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            result[i * 2] = rgb565 & 0xFF
            result[i * 2 + 1] = (rgb565 >> 8) & 0xFF

        return bytes(result)
```

- [ ] **Step 5: Run tests**

Run: `cd remote-ui/round && python -m pytest tests/test_display_renderer.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add remote-ui/round/agent/display/
git add remote-ui/round/tests/test_display_renderer.py
git commit -m "feat(eye-remote): Add DisplayRenderer base class with framebuffer support"
```

---

### Task 5: Extend Config for New Settings

**Files:**
- Modify: `remote-ui/round/agent/config.py`
- Create: `remote-ui/round/files/etc/secubox/eye-remote/eye-remote.toml`
- Test: `remote-ui/round/tests/test_config.py` (extend)

- [ ] **Step 1: Write failing test for new config fields**

```python
# Append to remote-ui/round/tests/test_config.py (or create if missing)
import pytest
from pathlib import Path
from agent.config import load_config, Config, DisplayConfig, ModeConfig, WebConfig

def test_display_config_defaults():
    """DisplayConfig should have default values."""
    dc = DisplayConfig()
    assert dc.brightness == 80
    assert dc.timeout_seconds == 300
    assert dc.theme == "neon"

def test_mode_config_defaults():
    """ModeConfig should have default values."""
    mc = ModeConfig()
    assert mc.default == "auto"
    assert mc.auto_fallback_seconds == 60
    assert mc.reconnect_interval_seconds == 10

def test_web_config_defaults():
    """WebConfig should have default values."""
    wc = WebConfig()
    assert wc.enabled is True
    assert wc.port == 8080
    assert wc.bind == "0.0.0.0"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd remote-ui/round && python -m pytest tests/test_config.py -v`
Expected: FAIL with "cannot import name 'DisplayConfig'"

- [ ] **Step 3: Update config.py with new dataclasses**

```python
# remote-ui/round/agent/config.py
"""
SecuBox Eye Remote — Configuration loader
Loads device and SecuBox connection config from TOML file.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List

DEFAULT_CONFIG_PATH = Path("/etc/secubox/eye-remote/eye-remote.toml")


@dataclass
class DeviceConfig:
    """Eye Remote device configuration."""
    id: str = "eye-remote-001"
    name: str = "Eye Remote"


@dataclass
class DisplayConfig:
    """Display settings."""
    brightness: int = 80
    timeout_seconds: int = 300
    theme: str = "neon"  # neon | classic | minimal


@dataclass
class ModeConfig:
    """Mode switching settings."""
    default: str = "auto"  # auto | dashboard | local | flash | gateway
    auto_fallback_seconds: int = 60
    reconnect_interval_seconds: int = 10


@dataclass
class WebConfig:
    """Web Remote server settings."""
    enabled: bool = True
    port: int = 8080
    bind: str = "0.0.0.0"


@dataclass
class SecuBoxConfig:
    """Configuration for one SecuBox connection."""
    id: str = ""
    name: str = "SecuBox"
    host: str = "10.55.0.1"
    port: int = 8000
    token: str = ""
    transport: str = "otg"  # otg | wifi | manual
    active: bool = False


@dataclass
class SecuBoxesConfig:
    """SecuBox fleet configuration."""
    primary: str = ""
    devices: List[SecuBoxConfig] = field(default_factory=list)


@dataclass
class Config:
    """Full agent configuration."""
    device: DeviceConfig = field(default_factory=DeviceConfig)
    display: DisplayConfig = field(default_factory=DisplayConfig)
    mode: ModeConfig = field(default_factory=ModeConfig)
    web: WebConfig = field(default_factory=WebConfig)
    secuboxes: SecuBoxesConfig = field(default_factory=SecuBoxesConfig)


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    """
    Load configuration from TOML file.

    Args:
        path: Path to config file

    Returns:
        Parsed Config object
    """
    if not path.exists():
        return Config()

    with open(path, "rb") as f:
        data = tomllib.load(f)

    # Device
    device_data = data.get("device", {})
    device = DeviceConfig(
        id=device_data.get("id", "eye-remote-001"),
        name=device_data.get("name", "Eye Remote"),
    )

    # Display
    display_data = data.get("display", {})
    display = DisplayConfig(
        brightness=display_data.get("brightness", 80),
        timeout_seconds=display_data.get("timeout_seconds", 300),
        theme=display_data.get("theme", "neon"),
    )

    # Mode
    mode_data = data.get("mode", {})
    mode = ModeConfig(
        default=mode_data.get("default", "auto"),
        auto_fallback_seconds=mode_data.get("auto_fallback_seconds", 60),
        reconnect_interval_seconds=mode_data.get("reconnect_interval_seconds", 10),
    )

    # Web
    web_data = data.get("web", {})
    web = WebConfig(
        enabled=web_data.get("enabled", True),
        port=web_data.get("port", 8080),
        bind=web_data.get("bind", "0.0.0.0"),
    )

    # SecuBoxes
    secuboxes_data = data.get("secuboxes", {})
    devices = []
    for sb_data in secuboxes_data.get("devices", []):
        devices.append(SecuBoxConfig(
            id=sb_data.get("id", ""),
            name=sb_data.get("name", "SecuBox"),
            host=sb_data.get("host", "10.55.0.1"),
            port=sb_data.get("port", 8000),
            token=sb_data.get("token", ""),
            transport=sb_data.get("transport", "otg"),
            active=sb_data.get("active", False),
        ))

    secuboxes = SecuBoxesConfig(
        primary=secuboxes_data.get("primary", ""),
        devices=devices,
    )

    return Config(
        device=device,
        display=display,
        mode=mode,
        web=web,
        secuboxes=secuboxes,
    )


def get_active_secubox(config: Config) -> Optional[SecuBoxConfig]:
    """Get the currently active SecuBox config."""
    # First check for explicitly active
    for sb in config.secuboxes.devices:
        if sb.active:
            return sb

    # Then check for primary
    for sb in config.secuboxes.devices:
        if sb.id == config.secuboxes.primary:
            return sb

    # Return first device
    return config.secuboxes.devices[0] if config.secuboxes.devices else None
```

- [ ] **Step 4: Run tests**

Run: `cd remote-ui/round && python -m pytest tests/test_config.py -v`
Expected: All PASS

- [ ] **Step 5: Create default config file**

```toml
# remote-ui/round/files/etc/secubox/eye-remote/eye-remote.toml
# SecuBox Eye Remote Configuration
# CyberMind — https://cybermind.fr

[device]
id = "eye-remote-001"
name = "Eye Remote"

[display]
brightness = 80
timeout_seconds = 300
theme = "neon"  # neon | classic | minimal

[mode]
default = "auto"  # auto | dashboard | local | flash | gateway
auto_fallback_seconds = 60
reconnect_interval_seconds = 10

[web]
enabled = true
port = 8080
bind = "0.0.0.0"

[secuboxes]
primary = "secubox-main"

[[secuboxes.devices]]
id = "secubox-main"
name = "SecuBox Main"
host = "10.55.0.1"
port = 8000
transport = "otg"
```

- [ ] **Step 6: Commit**

```bash
git add remote-ui/round/agent/config.py
git add remote-ui/round/files/etc/secubox/eye-remote/eye-remote.toml
git add remote-ui/round/tests/test_config.py
git commit -m "feat(eye-remote): Extend config with display, mode, and web settings"
```

---

## Phase 2: Display Modes

### Task 6: Create Dashboard Mode Display

**Files:**
- Create: `remote-ui/round/agent/display/mode_dashboard.py`
- Test: `remote-ui/round/tests/test_mode_dashboard.py`

- [ ] **Step 1: Write failing test**

```python
# remote-ui/round/tests/test_mode_dashboard.py
"""Tests for Dashboard mode display."""
import pytest
from PIL import Image
from agent.display.mode_dashboard import DashboardRenderer
from agent.display.renderer import RenderContext

def test_dashboard_renderer_creates_frame():
    """DashboardRenderer should create a frame."""
    renderer = DashboardRenderer()
    ctx = RenderContext(
        mode="dashboard",
        connection_state="connected",
        metrics={'cpu': 45, 'mem': 60, 'disk': 30, 'load': 1.5, 'temp': 42, 'wifi': -55},
        hostname="secubox-main",
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd remote-ui/round && python -m pytest tests/test_mode_dashboard.py -v`
Expected: FAIL

- [ ] **Step 3: Create mode_dashboard.py**

```python
# remote-ui/round/agent/display/mode_dashboard.py
"""
SecuBox Eye Remote — Dashboard Mode Display
Renders 6 metric rings with real-time SecuBox data.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import math
import time
from typing import Tuple

from PIL import Image, ImageDraw

from .renderer import (
    DisplayRenderer, RenderContext,
    MODULE_COLORS, TEXT_COLOR, TEXT_MUTED, STATUS_OK, STATUS_WARN, STATUS_OFFLINE,
)

# Ring configuration
RINGS = [
    {'name': 'AUTH', 'metric': 'cpu', 'unit': '%', 'radius': 214, 'width': 10},
    {'name': 'WALL', 'metric': 'mem', 'unit': '%', 'radius': 201, 'width': 10},
    {'name': 'BOOT', 'metric': 'disk', 'unit': '%', 'radius': 188, 'width': 10},
    {'name': 'MIND', 'metric': 'load', 'unit': 'x', 'radius': 175, 'width': 10},
    {'name': 'ROOT', 'metric': 'temp', 'unit': '°', 'radius': 162, 'width': 10},
    {'name': 'MESH', 'metric': 'wifi', 'unit': 'dB', 'radius': 149, 'width': 10},
]


class DashboardRenderer(DisplayRenderer):
    """
    Renders Dashboard mode with 6 metric rings.

    Display elements:
    - Connection badge (top): OTG | WiFi | OFFLINE
    - 6 concentric rings: AUTH/WALL/BOOT/MIND/ROOT/MESH
    - Center: Time, hostname, uptime
    - Status indicator (bottom): NOMINAL | WARNING | CRITICAL
    """

    def __init__(self):
        super().__init__()
        self._animation_offset = 0.0

    def render(self, ctx: RenderContext) -> Image.Image:
        """Render Dashboard mode frame."""
        self.create_frame()
        draw = self.get_draw()

        # Draw rings
        self._draw_rings(draw, ctx)

        # Draw connection badge
        self._draw_connection_badge(draw, ctx)

        # Draw center content
        self._draw_center(draw, ctx)

        # Draw status indicator
        self._draw_status(draw, ctx)

        # Apply circular mask
        self.draw_circle_mask(draw)

        # Update animation
        self._animation_offset += 0.02

        return self._frame

    def _draw_rings(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw the 6 metric rings."""
        cx, cy = self.center
        metrics = ctx.metrics

        for ring in RINGS:
            name = ring['name']
            radius = ring['radius']
            width = ring['width']
            color = MODULE_COLORS.get(name, (128, 128, 128))

            # Get metric value and normalize to 0-1
            value = metrics.get(ring['metric'], 0)
            if ring['metric'] == 'load':
                # Load: 0-4 scale
                normalized = min(1.0, value / 4.0)
            elif ring['metric'] == 'wifi':
                # WiFi: -80 to -30 dBm, inverted
                normalized = min(1.0, max(0.0, (value + 80) / 50))
            elif ring['metric'] == 'temp':
                # Temp: 30-80°C
                normalized = min(1.0, max(0.0, (value - 30) / 50))
            else:
                # Percentage: 0-100
                normalized = min(1.0, value / 100.0)

            # Apply fading if degraded
            if ctx.connection_state == "degraded":
                color = tuple(c // 2 for c in color)
            elif ctx.connection_state == "stale":
                # Pulse effect
                pulse = (math.sin(self._animation_offset * 4) + 1) / 2
                color = tuple(int(c * (0.5 + 0.5 * pulse)) for c in color)

            # Draw background arc (dim)
            self._draw_arc(draw, cx, cy, radius, width, 0, 360,
                          tuple(c // 8 for c in color))

            # Draw value arc
            end_angle = int(normalized * 360)
            if end_angle > 0:
                self._draw_arc(draw, cx, cy, radius, width, -90, -90 + end_angle, color)

    def _draw_arc(
        self,
        draw: ImageDraw.ImageDraw,
        cx: int, cy: int,
        radius: int, width: int,
        start_angle: int, end_angle: int,
        color: Tuple[int, int, int],
    ) -> None:
        """Draw an arc segment."""
        bbox = [cx - radius, cy - radius, cx + radius, cy + radius]
        draw.arc(bbox, start_angle, end_angle, fill=color, width=width)

    def _draw_connection_badge(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw connection status badge at top."""
        if ctx.connection_state == "connected":
            text = "● OTG"
            color = STATUS_OK
        elif ctx.connection_state in ("stale", "degraded"):
            text = "● OFFLINE"
            color = STATUS_WARN
        else:
            text = "○ DISCONNECTED"
            color = STATUS_OFFLINE

        self.draw_text_centered(draw, text, 30, 'small', color)

    def _draw_center(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw center content: time, hostname, uptime."""
        cy = self.height // 2

        # Time
        current_time = time.strftime("%H:%M:%S")
        self.draw_text_centered(draw, current_time, cy - 40, 'time', TEXT_COLOR)

        # Hostname
        hostname = ctx.hostname or "secubox"
        self.draw_text_centered(draw, hostname, cy + 20, 'medium', TEXT_MUTED)

        # Uptime
        uptime = self._format_uptime(ctx.uptime_seconds)
        self.draw_text_centered(draw, f"up {uptime}", cy + 45, 'small', TEXT_MUTED)

    def _draw_status(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw status indicator at bottom."""
        # Determine status based on metrics
        metrics = ctx.metrics
        critical = False
        warning = False

        if metrics.get('cpu', 0) > 85 or metrics.get('mem', 0) > 90:
            critical = True
        elif metrics.get('cpu', 0) > 70 or metrics.get('mem', 0) > 75:
            warning = True

        if critical:
            text = "▲ CRITICAL"
            color = (255, 0, 80)
        elif warning:
            text = "▲ WARNING"
            color = STATUS_WARN
        else:
            text = "● NOMINAL"
            color = STATUS_OK

        self.draw_text_centered(draw, text, self.height - 50, 'medium', color)

    def _format_uptime(self, seconds: int) -> str:
        """Format uptime in human-readable form."""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m"
        elif seconds < 86400:
            h = seconds // 3600
            m = (seconds % 3600) // 60
            return f"{h}h{m:02d}m"
        else:
            d = seconds // 86400
            h = (seconds % 86400) // 3600
            return f"{d}d{h}h"
```

- [ ] **Step 4: Run test**

Run: `cd remote-ui/round && python -m pytest tests/test_mode_dashboard.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/display/mode_dashboard.py
git add remote-ui/round/tests/test_mode_dashboard.py
git commit -m "feat(eye-remote): Add Dashboard mode renderer with metric rings"
```

---

### Task 7: Create Local Mode Display

**Files:**
- Create: `remote-ui/round/agent/display/mode_local.py`
- Test: `remote-ui/round/tests/test_mode_local.py`

- [ ] **Step 1: Write failing test**

```python
# remote-ui/round/tests/test_mode_local.py
"""Tests for Local mode display."""
import pytest
from PIL import Image
from agent.display.mode_local import LocalRenderer
from agent.display.renderer import RenderContext

def test_local_renderer_creates_frame():
    """LocalRenderer should create a frame."""
    renderer = LocalRenderer()
    ctx = RenderContext(
        mode="local",
        connection_state="disconnected",
        metrics={'cpu': 20, 'mem': 45, 'disk': 30},
        hostname="eye-remote",
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd remote-ui/round && python -m pytest tests/test_mode_local.py -v`
Expected: FAIL

- [ ] **Step 3: Create mode_local.py**

```python
# remote-ui/round/agent/display/mode_local.py
"""
SecuBox Eye Remote — Local Mode Display
Renders Pi Zero self-monitoring with icon grid.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from PIL import Image, ImageDraw

from .renderer import (
    DisplayRenderer, RenderContext,
    TEXT_COLOR, TEXT_MUTED, STATUS_OK,
)

# Icon grid layout
ICONS = [
    {'name': 'Network', 'symbol': '📡', 'metric': 'network'},
    {'name': 'Power', 'symbol': '🔋', 'metric': 'power'},
    {'name': 'Storage', 'symbol': '💾', 'metric': 'disk'},
    {'name': 'WiFi', 'symbol': '📶', 'metric': 'wifi'},
    {'name': 'Settings', 'symbol': '⚙️', 'metric': None},
    {'name': 'Refresh', 'symbol': '🔄', 'metric': None},
]


class LocalRenderer(DisplayRenderer):
    """
    Renders Local mode with Pi Zero self-monitoring.

    Display elements:
    - Mode badge (top): LOCAL MODE
    - Icon grid (center): 3x2 grid of status icons
    - Device info: Pi Zero W, uptime
    - Web Remote hint (bottom): URL
    """

    def render(self, ctx: RenderContext) -> Image.Image:
        """Render Local mode frame."""
        self.create_frame()
        draw = self.get_draw()

        # Draw mode badge
        self._draw_mode_badge(draw)

        # Draw icon grid
        self._draw_icon_grid(draw, ctx)

        # Draw device info
        self._draw_device_info(draw, ctx)

        # Draw web remote hint
        self._draw_web_hint(draw)

        # Apply circular mask
        self.draw_circle_mask(draw)

        return self._frame

    def _draw_mode_badge(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw LOCAL MODE badge at top."""
        self.draw_text_centered(draw, "● LOCAL MODE", 35, 'medium', (0, 170, 255))

    def _draw_icon_grid(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw 3x2 icon grid."""
        cx, cy = self.center
        metrics = ctx.metrics

        # Grid parameters
        cols, rows = 3, 2
        icon_size = 60
        spacing_x = 90
        spacing_y = 80
        start_x = cx - spacing_x
        start_y = cy - 60

        for i, icon_data in enumerate(ICONS):
            col = i % cols
            row = i // cols
            x = start_x + col * spacing_x
            y = start_y + row * spacing_y

            # Draw icon (using text emoji for now)
            symbol = icon_data['symbol']
            font = self.get_font('xlarge')
            draw.text((x - 15, y - 20), symbol, font=font, fill=TEXT_COLOR)

            # Draw label below
            label = icon_data['name']
            self.draw_text_centered(draw, label, y + 35, 'small', TEXT_MUTED)

    def _draw_device_info(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw device info below icons."""
        cy = self.center[1]

        # Device name
        device_name = "Pi Zero W"
        uptime = self._format_uptime(ctx.uptime_seconds)
        info_text = f"{device_name} • up {uptime}"

        self.draw_text_centered(draw, info_text, cy + 100, 'medium', TEXT_MUTED)

    def _draw_web_hint(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw web remote URL hint at bottom."""
        text = "Web: eye-remote.local:8080"
        self.draw_text_centered(draw, text, self.height - 50, 'small', (100, 150, 200))

    def _format_uptime(self, seconds: int) -> str:
        """Format uptime in human-readable form."""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m"
        elif seconds < 86400:
            h = seconds // 3600
            m = (seconds % 3600) // 60
            return f"{h}h{m:02d}m"
        else:
            d = seconds // 86400
            h = (seconds % 86400) // 3600
            return f"{d}d{h}h"
```

- [ ] **Step 4: Run test**

Run: `cd remote-ui/round && python -m pytest tests/test_mode_local.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/display/mode_local.py
git add remote-ui/round/tests/test_mode_local.py
git commit -m "feat(eye-remote): Add Local mode renderer with icon grid"
```

---

### Task 8: Create Flash Mode Display

**Files:**
- Create: `remote-ui/round/agent/display/mode_flash.py`
- Test: `remote-ui/round/tests/test_mode_flash.py`

- [ ] **Step 1: Write failing test**

```python
# remote-ui/round/tests/test_mode_flash.py
"""Tests for Flash mode display."""
import pytest
from PIL import Image
from agent.display.mode_flash import FlashRenderer
from agent.display.renderer import RenderContext

def test_flash_renderer_creates_frame():
    """FlashRenderer should create a frame."""
    renderer = FlashRenderer()
    ctx = RenderContext(
        mode="flash",
        flash_progress=0.75,
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)
```

- [ ] **Step 2: Create mode_flash.py**

```python
# remote-ui/round/agent/display/mode_flash.py
"""
SecuBox Eye Remote — Flash Mode Display
Renders USB storage status and flash progress for ESPRESSObin recovery.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import os
from pathlib import Path

from PIL import Image, ImageDraw

from .renderer import (
    DisplayRenderer, RenderContext,
    TEXT_COLOR, TEXT_MUTED, STATUS_OK, STATUS_WARN,
)

STORAGE_PATH = Path("/var/lib/secubox/eye-remote/storage.img")


class FlashRenderer(DisplayRenderer):
    """
    Renders Flash mode for ESPRESSObin recovery.

    Display elements:
    - Mode badge (top): ⚡ FLASH MODE
    - Storage icon (center)
    - Storage info: Size, format
    - Progress bar (if flashing)
    - U-Boot status (bottom)
    """

    def render(self, ctx: RenderContext) -> Image.Image:
        """Render Flash mode frame."""
        self.create_frame()
        draw = self.get_draw()

        # Draw mode badge
        self._draw_mode_badge(draw)

        # Draw storage icon
        self._draw_storage_icon(draw)

        # Draw storage info
        self._draw_storage_info(draw)

        # Draw progress bar if flashing
        if ctx.flash_progress > 0:
            self._draw_progress_bar(draw, ctx.flash_progress)

        # Draw U-Boot status
        self._draw_uboot_status(draw)

        # Apply circular mask
        self.draw_circle_mask(draw)

        return self._frame

    def _draw_mode_badge(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw FLASH MODE badge at top."""
        self.draw_text_centered(draw, "⚡ FLASH MODE", 35, 'medium', (255, 136, 0))

    def _draw_storage_icon(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw storage icon."""
        cx, cy = self.center
        font = self.get_font('xlarge')
        draw.text((cx - 20, cy - 80), "💾", font=font, fill=TEXT_COLOR)

    def _draw_storage_info(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw storage info."""
        cy = self.center[1]

        # Storage status
        self.draw_text_centered(draw, "USB STORAGE", cy - 20, 'large', TEXT_COLOR)

        # Get storage size
        if STORAGE_PATH.exists():
            size_bytes = STORAGE_PATH.stat().st_size
            size_gb = size_bytes / (1024 ** 3)
            size_text = f"{size_gb:.1f} GB • FAT32"
        else:
            size_text = "Not mounted"

        self.draw_text_centered(draw, size_text, cy + 15, 'medium', TEXT_MUTED)

    def _draw_progress_bar(self, draw: ImageDraw.ImageDraw, progress: float) -> None:
        """Draw flash progress bar."""
        cx, cy = self.center

        bar_width = 200
        bar_height = 16
        bar_x = cx - bar_width // 2
        bar_y = cy + 50

        # Background
        draw.rectangle(
            [bar_x, bar_y, bar_x + bar_width, bar_y + bar_height],
            fill=(40, 40, 50),
            outline=(80, 80, 90),
        )

        # Progress fill
        fill_width = int(bar_width * progress)
        if fill_width > 0:
            # Gradient from orange to yellow
            draw.rectangle(
                [bar_x + 1, bar_y + 1, bar_x + fill_width - 1, bar_y + bar_height - 1],
                fill=(255, 136, 0),
            )

        # Percentage text
        percent_text = f"{int(progress * 100)}%"
        self.draw_text_centered(draw, percent_text, bar_y + bar_height + 10, 'medium', TEXT_MUTED)

        # Status text
        if progress < 1.0:
            status = "Flashing image..."
        else:
            status = "Flash complete!"
        self.draw_text_centered(draw, status, bar_y + bar_height + 35, 'small', TEXT_MUTED)

    def _draw_uboot_status(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw U-Boot status at bottom."""
        self.draw_text_centered(draw, "U-Boot ready", self.height - 50, 'medium', STATUS_OK)
```

- [ ] **Step 3: Run test**

Run: `cd remote-ui/round && python -m pytest tests/test_mode_flash.py -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add remote-ui/round/agent/display/mode_flash.py
git add remote-ui/round/tests/test_mode_flash.py
git commit -m "feat(eye-remote): Add Flash mode renderer with progress bar"
```

---

### Task 9: Create Gateway Mode Display

**Files:**
- Create: `remote-ui/round/agent/display/mode_gateway.py`
- Test: `remote-ui/round/tests/test_mode_gateway.py`

- [ ] **Step 1: Write failing test**

```python
# remote-ui/round/tests/test_mode_gateway.py
"""Tests for Gateway mode display."""
import pytest
from PIL import Image
from agent.display.mode_gateway import GatewayRenderer
from agent.display.renderer import RenderContext

def test_gateway_renderer_creates_frame():
    """GatewayRenderer should create a frame."""
    renderer = GatewayRenderer()
    ctx = RenderContext(
        mode="gateway",
        devices=[
            {'name': 'secubox-main', 'online': True},
            {'name': 'secubox-lab', 'online': True},
            {'name': 'secubox-remote', 'online': False},
        ],
        alert_count=1,
    )
    frame = renderer.render(ctx)
    assert isinstance(frame, Image.Image)
    assert frame.size == (480, 480)
```

- [ ] **Step 2: Create mode_gateway.py**

```python
# remote-ui/round/agent/display/mode_gateway.py
"""
SecuBox Eye Remote — Gateway Mode Display
Renders multi-SecuBox fleet management view.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from PIL import Image, ImageDraw

from .renderer import (
    DisplayRenderer, RenderContext,
    TEXT_COLOR, TEXT_MUTED, STATUS_OK, STATUS_WARN,
)


class GatewayRenderer(DisplayRenderer):
    """
    Renders Gateway mode for multi-SecuBox fleet.

    Display elements:
    - Mode badge (top): 🌐 GATEWAY MODE
    - Fleet icon (center)
    - Device list with status dots
    - Fleet summary: X/Y online
    - Alert count (bottom)
    """

    def render(self, ctx: RenderContext) -> Image.Image:
        """Render Gateway mode frame."""
        self.create_frame()
        draw = self.get_draw()

        # Draw mode badge
        self._draw_mode_badge(draw)

        # Draw fleet icon
        self._draw_fleet_icon(draw)

        # Draw device list
        self._draw_device_list(draw, ctx)

        # Draw fleet summary
        self._draw_fleet_summary(draw, ctx)

        # Draw alert count
        self._draw_alerts(draw, ctx)

        # Apply circular mask
        self.draw_circle_mask(draw)

        return self._frame

    def _draw_mode_badge(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw GATEWAY MODE badge at top."""
        self.draw_text_centered(draw, "🌐 GATEWAY MODE", 35, 'medium', (160, 0, 255))

    def _draw_fleet_icon(self, draw: ImageDraw.ImageDraw) -> None:
        """Draw fleet icon."""
        cx, cy = self.center
        font = self.get_font('xlarge')
        draw.text((cx - 20, cy - 100), "🖥️", font=font, fill=TEXT_COLOR)

    def _draw_device_list(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw list of SecuBox devices with status."""
        cx, cy = self.center
        devices = ctx.devices or []

        y_start = cy - 40
        y_spacing = 28

        for i, device in enumerate(devices[:5]):  # Max 5 devices
            y = y_start + i * y_spacing

            name = device.get('name', f'device-{i}')
            online = device.get('online', False)

            # Status dot
            dot = "●" if online else "○"
            dot_color = STATUS_OK if online else (100, 100, 120)

            # Device text
            text = f"{dot} {name}"
            if not online:
                text += " (down)"

            font = self.get_font('medium')
            # Center the list
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            x = cx - text_width // 2

            draw.text((x, y), text, font=font, fill=dot_color if not online else TEXT_COLOR)

    def _draw_fleet_summary(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw fleet summary."""
        devices = ctx.devices or []
        online_count = sum(1 for d in devices if d.get('online', False))
        total_count = len(devices)

        summary = f"Fleet: {online_count}/{total_count} online"
        self.draw_text_centered(draw, summary, self.height - 80, 'medium', TEXT_MUTED)

    def _draw_alerts(self, draw: ImageDraw.ImageDraw, ctx: RenderContext) -> None:
        """Draw alert count at bottom."""
        alert_count = ctx.alert_count

        if alert_count > 0:
            text = f"▲ {alert_count} alert{'s' if alert_count > 1 else ''}"
            color = STATUS_WARN
        else:
            text = "● No alerts"
            color = STATUS_OK

        self.draw_text_centered(draw, text, self.height - 50, 'medium', color)
```

- [ ] **Step 3: Run test**

Run: `cd remote-ui/round && python -m pytest tests/test_mode_gateway.py -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add remote-ui/round/agent/display/mode_gateway.py
git add remote-ui/round/tests/test_mode_gateway.py
git commit -m "feat(eye-remote): Add Gateway mode renderer with fleet view"
```

---

## Phase 3: Web Remote Server

### Task 10: Create FastAPI Server Foundation

**Files:**
- Create: `remote-ui/round/agent/web/__init__.py`
- Create: `remote-ui/round/agent/web/server.py`
- Test: `remote-ui/round/tests/test_web_server.py`

- [ ] **Step 1: Create web package init**

```python
# remote-ui/round/agent/web/__init__.py
"""Web Remote server for Eye Remote."""
from .server import create_app, WebServer

__all__ = ['create_app', 'WebServer']
```

- [ ] **Step 2: Write failing test**

```python
# remote-ui/round/tests/test_web_server.py
"""Tests for Web Remote server."""
import pytest
from fastapi.testclient import TestClient
from agent.web.server import create_app

def test_create_app():
    """create_app should return FastAPI app."""
    app = create_app()
    assert app is not None

def test_health_endpoint():
    """Health endpoint should return OK."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_static_control_page():
    """Control page should be served."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/control")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
```

- [ ] **Step 3: Create server.py**

```python
# remote-ui/round/agent/web/server.py
"""
SecuBox Eye Remote — Web Remote Server
FastAPI server for touchless control.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

log = logging.getLogger(__name__)

# Static files directory
STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    mode_manager=None,
    failover_monitor=None,
    config=None,
) -> FastAPI:
    """
    Create FastAPI application for Web Remote.

    Args:
        mode_manager: ModeManager instance
        failover_monitor: FailoverMonitor instance
        config: Config instance

    Returns:
        Configured FastAPI app
    """
    app = FastAPI(
        title="Eye Remote Web Control",
        description="SecuBox Eye Remote touchless control interface",
        version="1.0.0",
    )

    # Store references in app state
    app.state.mode_manager = mode_manager
    app.state.failover_monitor = failover_monitor
    app.state.config = config

    # Health check
    @app.get("/api/health")
    async def health():
        return {"status": "ok", "service": "eye-remote-web"}

    # Serve control page
    @app.get("/control", response_class=HTMLResponse)
    async def control_page():
        html_path = STATIC_DIR / "control.html"
        if html_path.exists():
            return HTMLResponse(content=html_path.read_text())
        return HTMLResponse(content=_default_control_html())

    # Serve static files
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # Import and include routers
    from .routes import mode, wifi, bluetooth, display, devices, system, secubox

    app.include_router(mode.router, prefix="/api", tags=["mode"])
    app.include_router(wifi.router, prefix="/api/wifi", tags=["wifi"])
    app.include_router(bluetooth.router, prefix="/api/bluetooth", tags=["bluetooth"])
    app.include_router(display.router, prefix="/api/display", tags=["display"])
    app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
    app.include_router(system.router, prefix="/api/system", tags=["system"])
    app.include_router(secubox.router, prefix="/api/secubox", tags=["secubox"])

    return app


def _default_control_html() -> str:
    """Return default control page HTML if static file missing."""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Eye Remote Control</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0a0a0f;
            color: #fff;
            min-height: 100vh;
            padding: 16px;
        }
        h1 { font-size: 20px; margin-bottom: 16px; }
        .status { color: #0f0; font-size: 12px; }
        .card {
            background: #1a1a1a;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
        }
        .btn {
            display: inline-block;
            background: #1a3a1a;
            border: 1px solid #0f0;
            color: #0f0;
            padding: 12px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            margin: 4px;
        }
        .btn:hover { background: #2a4a2a; }
    </style>
</head>
<body>
    <h1>Eye Remote Control</h1>
    <p class="status">● Connected</p>

    <div class="card">
        <h3>Mode</h3>
        <button class="btn" onclick="setMode('dashboard')">Dashboard</button>
        <button class="btn" onclick="setMode('local')">Local</button>
        <button class="btn" onclick="setMode('flash')">Flash</button>
        <button class="btn" onclick="setMode('gateway')">Gateway</button>
    </div>

    <div class="card">
        <h3>System</h3>
        <button class="btn" onclick="reboot()">Reboot</button>
    </div>

    <script>
        async function setMode(mode) {
            await fetch('/api/mode', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({mode})
            });
            location.reload();
        }
        async function reboot() {
            if (confirm('Reboot Eye Remote?')) {
                await fetch('/api/system/reboot', {method: 'POST'});
            }
        }
    </script>
</body>
</html>
"""


class WebServer:
    """
    Manages the FastAPI server lifecycle.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        mode_manager=None,
        failover_monitor=None,
        config=None,
    ):
        self.host = host
        self.port = port
        self.app = create_app(mode_manager, failover_monitor, config)
        self._server_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the web server."""
        import uvicorn

        config = uvicorn.Config(
            self.app,
            host=self.host,
            port=self.port,
            log_level="warning",
        )
        server = uvicorn.Server(config)
        self._server_task = asyncio.create_task(server.serve())
        log.info(f"Web server started on http://{self.host}:{self.port}")

    async def stop(self) -> None:
        """Stop the web server."""
        if self._server_task:
            self._server_task.cancel()
            try:
                await self._server_task
            except asyncio.CancelledError:
                pass
```

- [ ] **Step 4: Create routes package and mode router**

```python
# remote-ui/round/agent/web/routes/__init__.py
"""API route modules."""

# remote-ui/round/agent/web/routes/mode.py
"""Mode switching API routes."""
from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter()


class ModeRequest(BaseModel):
    mode: str


class ModeResponse(BaseModel):
    mode: str
    previous: str | None = None


@router.get("/mode")
async def get_mode(request: Request) -> ModeResponse:
    """Get current operating mode."""
    mm = request.app.state.mode_manager
    if mm:
        return ModeResponse(
            mode=mm.current_mode.value,
            previous=mm.previous_mode.value if mm.previous_mode else None,
        )
    return ModeResponse(mode="local")


@router.post("/mode")
async def set_mode(request: Request, data: ModeRequest) -> ModeResponse:
    """Set operating mode."""
    from agent.mode_manager import Mode

    mm = request.app.state.mode_manager
    if mm:
        mode_map = {
            "dashboard": Mode.DASHBOARD,
            "local": Mode.LOCAL,
            "flash": Mode.FLASH,
            "gateway": Mode.GATEWAY,
        }
        if data.mode in mode_map:
            await mm.set_mode(mode_map[data.mode])

    return await get_mode(request)
```

- [ ] **Step 5: Create stub routers for other routes**

```python
# remote-ui/round/agent/web/routes/wifi.py
"""WiFi configuration API routes."""
from fastapi import APIRouter
router = APIRouter()

@router.get("/status")
async def wifi_status():
    return {"connected": False, "ssid": None}

@router.get("/scan")
async def wifi_scan():
    return {"networks": []}

@router.post("/connect")
async def wifi_connect():
    return {"success": False, "error": "Not implemented"}


# remote-ui/round/agent/web/routes/bluetooth.py
"""Bluetooth management API routes."""
from fastapi import APIRouter
router = APIRouter()

@router.get("/status")
async def bt_status():
    return {"enabled": False}

@router.get("/devices")
async def bt_devices():
    return {"devices": []}

@router.post("/enable")
async def bt_enable():
    return {"enabled": False}

@router.post("/pair")
async def bt_pair():
    return {"success": False}


# remote-ui/round/agent/web/routes/display.py
"""Display settings API routes."""
from fastapi import APIRouter
router = APIRouter()

@router.get("/settings")
async def display_settings():
    return {"brightness": 80, "timeout": 300, "theme": "neon"}

@router.post("/brightness")
async def set_brightness():
    return {"brightness": 80}

@router.post("/timeout")
async def set_timeout():
    return {"timeout": 300}


# remote-ui/round/agent/web/routes/devices.py
"""SecuBox device manager API routes."""
from fastapi import APIRouter
router = APIRouter()

@router.get("")
async def list_devices():
    return {"devices": []}

@router.post("")
async def add_device():
    return {"success": False}

@router.delete("/{device_id}")
async def remove_device(device_id: str):
    return {"success": False}


# remote-ui/round/agent/web/routes/system.py
"""System actions API routes."""
from fastapi import APIRouter
router = APIRouter()

@router.post("/reboot")
async def system_reboot():
    return {"success": False, "message": "Not implemented"}

@router.post("/shutdown")
async def system_shutdown():
    return {"success": False, "message": "Not implemented"}

@router.get("/logs")
async def system_logs():
    return {"logs": []}


# remote-ui/round/agent/web/routes/secubox.py
"""SecuBox remote control API routes."""
from fastapi import APIRouter
router = APIRouter()

@router.get("/{device_id}/status")
async def secubox_status(device_id: str):
    return {"device_id": device_id, "online": False}

@router.post("/{device_id}/restart")
async def secubox_restart(device_id: str):
    return {"success": False}

@router.post("/{device_id}/lockdown")
async def secubox_lockdown(device_id: str):
    return {"success": False}
```

- [ ] **Step 6: Create static directory**

```bash
mkdir -p remote-ui/round/agent/web/static
mkdir -p remote-ui/round/agent/web/routes
touch remote-ui/round/agent/web/routes/__init__.py
```

- [ ] **Step 7: Run tests**

Run: `cd remote-ui/round && python -m pytest tests/test_web_server.py -v`
Expected: All PASS

- [ ] **Step 8: Commit**

```bash
git add remote-ui/round/agent/web/
git add remote-ui/round/tests/test_web_server.py
git commit -m "feat(eye-remote): Add FastAPI Web Remote server with route stubs"
```

---

## Remaining Phases (Summary)

The full plan continues with:

### Phase 4: System Controls (Tasks 11-14)
- Task 11: WiFi Manager (nmcli wrapper)
- Task 12: Bluetooth Manager (bluetoothctl wrapper)
- Task 13: Display Controller (brightness, timeout)
- Task 14: Integrate system controls into API routes

### Phase 5: Advanced Features (Tasks 15-17)
- Task 15: SecuBox Device Manager
- Task 16: SecuBox Remote Control
- Task 17: Gateway Fleet Aggregation

### Phase 6: Integration & Polish (Tasks 18-21)
- Task 18: Update main.py entry point
- Task 19: Create control.html Web UI
- Task 20: Add WebSocket real-time updates
- Task 21: Final integration testing

---

## Quick Reference

**Run all tests:**
```bash
cd remote-ui/round && python -m pytest tests/ -v
```

**Start dev server:**
```bash
cd remote-ui/round && python -m uvicorn agent.web.server:create_app --factory --reload --port 8080
```

**Test on hardware:**
```bash
scp -r remote-ui/round/ pi@eye-remote.local:/opt/secubox/eye-remote/
ssh pi@eye-remote.local "sudo systemctl restart secubox-eye-agent"
```
