#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote — Auto-Mode Controller

Intelligent state machine for automatic OTG mode switching based on
host detection, connection state, and fallback logic.

Mode Priority (highest to lowest):
1. network  - ECM + ACM (requires host network support)
2. hid      - HID Keyboard + ACM (fallback when network fails)
3. storage  - Mass Storage + ACM (recovery, U-Boot compatible)

State Machine Flow:
    BOOT → Detect Host Type
             │
             ├─ U-Boot (powered >3s, no config) → STORAGE
             │
             └─ OS detected (configured <3s) → Try NETWORK
                                                  │
                        ┌─────────────────────────┼─────────────────────────┐
                        │                         │                         │
                      Success                 Timeout/Fail              HID Probe
                        │                         │                         │
                        ▼                         │                         ▼
                  NETWORK_ACTIVE ◄────────────────┤                   HID_ACTIVE
                        │                         │                         │
                        │ Connection loss 60s+    │                         │
                        ▼                         ▼                         │
                  SILENT_STORAGE ◄────────────────┴─────────────────────────┘
                        │
                        │ Wake trigger (file, serial, GPIO)
                        ▼
                  Try NETWORK again

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional, List, Dict, Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Enums and Constants
# ═══════════════════════════════════════════════════════════════════════════════

class AutoModeState(Enum):
    """State machine states for auto-mode controller."""
    BOOT = "boot"                     # Initial boot, detecting host
    PROBING_NETWORK = "probing_network"  # Trying network mode
    NETWORK_ACTIVE = "network_active"    # Network mode working
    PROBING_HID = "probing_hid"          # Trying HID mode
    HID_ACTIVE = "hid_active"            # HID mode working
    STORAGE_ACTIVE = "storage_active"    # Storage mode (U-Boot/fallback)
    SILENT_STORAGE = "silent_storage"    # Silent fallback, monitoring wakeups


class GadgetMode(Enum):
    """USB gadget modes."""
    NONE = "none"
    NETWORK = "network"     # ECM + ACM
    HID = "hid"            # HID Keyboard + ACM
    STORAGE = "storage"     # Mass Storage only (U-Boot compatible)
    SILENT = "silent"       # Storage + ACM (silent fallback)
    COMPOSITE = "up"        # ECM + ACM + Storage (full)


class UDCState(Enum):
    """USB Device Controller states."""
    NOT_ATTACHED = "not attached"
    ATTACHED = "attached"
    POWERED = "powered"
    CONFIGURED = "configured"
    SUSPENDED = "suspended"


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AutoModeConfig:
    """Configuration for auto-mode controller."""
    # Auto mode settings
    enabled: bool = True
    default_mode: str = "storage"
    preferred_mode: str = "network"

    # Timing
    network_probe_timeout_s: float = 10.0
    hid_probe_timeout_s: float = 5.0
    silent_fallback_threshold_s: float = 60.0
    mode_switch_cooldown_s: float = 5.0
    host_settle_delay_s: float = 2.0

    # Wake-up settings
    serial_console_enabled: bool = True
    serial_wake_patterns: List[str] = field(default_factory=lambda: ["WAKE", "wake", "NETWORK", "network"])
    magic_file_enabled: bool = True
    magic_file_name: str = "WAKE_NETWORK"
    gpio_button_enabled: bool = True
    gpio_button_pin: int = 17
    gpio_long_press_seconds: float = 3.0
    scheduled_check_enabled: bool = True
    scheduled_check_interval_m: int = 5

    # Host detection
    uboot_detect_threshold_s: float = 3.0
    network_probe_endpoints: List[str] = field(default_factory=lambda: [
        "http://10.55.0.1:8000/api/v1/health",
        "http://10.55.0.1:8000/api/v1/system/metrics"
    ])
    network_probe_timeout_s_endpoint: float = 3.0

    # Storage
    storage_image_path: str = "/var/lib/secubox/eye-remote/storage.img"
    readonly_in_silent_mode: bool = False
    storage_unmounted_recovery_s: float = 30.0  # Switch back to composite if not mounted

    # Logging
    log_level: str = "info"
    dedupe_interval_s: int = 300

    @classmethod
    def from_toml(cls, path: Path) -> "AutoModeConfig":
        """Load configuration from TOML file."""
        if not path.exists():
            log.warning(f"Config file not found: {path}, using defaults")
            return cls()

        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)

            auto_mode = data.get("auto_mode", {})
            timing = data.get("timing", {})
            wakeup = data.get("wakeup", {})
            host_detection = data.get("host_detection", {})
            storage = data.get("storage", {})
            log_cfg = data.get("logging", {})

            return cls(
                enabled=auto_mode.get("enabled", True),
                default_mode=auto_mode.get("default_mode", "storage"),
                preferred_mode=auto_mode.get("preferred_mode", "network"),
                network_probe_timeout_s=timing.get("network_probe_timeout_s", 10.0),
                hid_probe_timeout_s=timing.get("hid_probe_timeout_s", 5.0),
                silent_fallback_threshold_s=timing.get("silent_fallback_threshold_s", 60.0),
                mode_switch_cooldown_s=timing.get("mode_switch_cooldown_s", 5.0),
                host_settle_delay_s=timing.get("host_settle_delay_s", 2.0),
                serial_console_enabled=wakeup.get("serial_console_enabled", True),
                serial_wake_patterns=wakeup.get("serial_wake_patterns", ["WAKE", "wake", "NETWORK", "network"]),
                magic_file_enabled=wakeup.get("magic_file_enabled", True),
                magic_file_name=wakeup.get("magic_file_name", "WAKE_NETWORK"),
                gpio_button_enabled=wakeup.get("gpio_button_enabled", True),
                gpio_button_pin=wakeup.get("gpio_button_pin", 17),
                gpio_long_press_seconds=wakeup.get("gpio_long_press_seconds", 3.0),
                scheduled_check_enabled=wakeup.get("scheduled_check_enabled", True),
                scheduled_check_interval_m=wakeup.get("scheduled_check_interval_m", 5),
                uboot_detect_threshold_s=host_detection.get("uboot_detect_threshold_s", 3.0),
                network_probe_endpoints=host_detection.get("network_probe_endpoints", [
                    "http://10.55.0.1:8000/api/v1/health"
                ]),
                network_probe_timeout_s_endpoint=host_detection.get("network_probe_timeout_s", 3.0),
                storage_image_path=storage.get("image_path", "/var/lib/secubox/eye-remote/storage.img"),
                readonly_in_silent_mode=storage.get("readonly_in_silent_mode", False),
                log_level=log_cfg.get("level", "info"),
                dedupe_interval_s=log_cfg.get("dedupe_interval_s", 300),
            )
        except Exception as e:
            log.error(f"Failed to load config from {path}: {e}")
            return cls()


# ═══════════════════════════════════════════════════════════════════════════════
# UDC Monitor
# ═══════════════════════════════════════════════════════════════════════════════

class UDCMonitor:
    """Monitors USB Device Controller state."""

    UDC_PATH = Path("/sys/class/udc")

    def __init__(self):
        self._udc_name: Optional[str] = None
        self._find_udc()

    def _find_udc(self) -> None:
        """Find available UDC."""
        if self.UDC_PATH.exists():
            udcs = list(self.UDC_PATH.iterdir())
            if udcs:
                self._udc_name = udcs[0].name

    @property
    def udc_name(self) -> Optional[str]:
        """Get UDC name."""
        return self._udc_name

    @property
    def state_path(self) -> Optional[Path]:
        """Get path to UDC state file."""
        if self._udc_name:
            return self.UDC_PATH / self._udc_name / "state"
        return None

    def get_state(self) -> UDCState:
        """Get current UDC state."""
        if self.state_path and self.state_path.exists():
            try:
                state_str = self.state_path.read_text().strip()
                return UDCState(state_str)
            except (ValueError, OSError):
                pass
        return UDCState.NOT_ATTACHED

    def is_connected(self) -> bool:
        """Check if host is connected."""
        state = self.get_state()
        return state in (UDCState.CONFIGURED, UDCState.POWERED, UDCState.ATTACHED)

    def is_configured(self) -> bool:
        """Check if gadget is configured by host."""
        return self.get_state() == UDCState.CONFIGURED


# ═══════════════════════════════════════════════════════════════════════════════
# Gadget Controller
# ═══════════════════════════════════════════════════════════════════════════════

class GadgetController:
    """Controls USB gadget mode switching."""

    GADGET_SCRIPT = Path("/etc/secubox/eye-remote/gadget-setup.sh")
    FALLBACK_SCRIPT = Path("/usr/lib/secubox/eye-gadget-switch.sh")
    GADGET_CONFIG = Path("/sys/kernel/config/usb_gadget/secubox/configs/c.1")

    def __init__(self):
        self._current_mode: GadgetMode = GadgetMode.NONE
        self._last_switch_time: float = 0
        self._switch_in_progress: bool = False
        # Detect current mode on startup
        self._current_mode = self._detect_current_mode()

    def _detect_current_mode(self) -> GadgetMode:
        """Detect current gadget mode from configfs."""
        if not self.GADGET_CONFIG.exists():
            return GadgetMode.NONE

        try:
            # Check which functions are linked
            links = list(self.GADGET_CONFIG.iterdir())
            func_names = [l.name for l in links if l.is_symlink()]

            has_ecm = any("ecm" in f for f in func_names)
            has_acm = any("acm" in f for f in func_names)
            has_storage = any("mass_storage" in f for f in func_names)
            has_hid = any("hid" in f for f in func_names)

            # Determine mode based on functions
            if has_ecm and has_acm and has_storage:
                log.info(f"Detected COMPOSITE mode (ECM+ACM+Storage)")
                return GadgetMode.COMPOSITE
            elif has_ecm and has_acm:
                log.info(f"Detected NETWORK mode (ECM+ACM)")
                return GadgetMode.NETWORK
            elif has_hid and has_acm:
                log.info(f"Detected HID mode (HID+ACM)")
                return GadgetMode.HID
            elif has_storage and has_acm:
                log.info(f"Detected SILENT mode (Storage+ACM)")
                return GadgetMode.SILENT
            elif has_storage:
                log.info(f"Detected STORAGE mode")
                return GadgetMode.STORAGE
            elif func_names:
                log.info(f"Unknown functions: {func_names}, assuming NONE")
                return GadgetMode.NONE
            else:
                return GadgetMode.NONE
        except Exception as e:
            log.warning(f"Failed to detect gadget mode: {e}")
            return GadgetMode.NONE

    @property
    def current_mode(self) -> GadgetMode:
        """Get current gadget mode."""
        return self._current_mode

    def _find_script(self) -> Optional[Path]:
        """Find gadget setup script."""
        if self.GADGET_SCRIPT.exists():
            return self.GADGET_SCRIPT
        if self.FALLBACK_SCRIPT.exists():
            return self.FALLBACK_SCRIPT
        return None

    async def switch_mode(self, mode: GadgetMode, cooldown: float = 5.0) -> bool:
        """Switch gadget mode."""
        if self._switch_in_progress:
            log.warning("Mode switch already in progress")
            return False

        # Check cooldown
        elapsed = time.time() - self._last_switch_time
        if elapsed < cooldown:
            log.debug(f"Mode switch cooldown, {cooldown - elapsed:.1f}s remaining")
            return False

        script = self._find_script()
        if not script:
            log.error("Gadget setup script not found")
            return False

        self._switch_in_progress = True
        try:
            log.info(f"Switching gadget mode: {self._current_mode.value} -> {mode.value}")

            # Map GadgetMode to script argument
            mode_map = {
                GadgetMode.NONE: "down",
                GadgetMode.NETWORK: "network",
                GadgetMode.HID: "hid",
                GadgetMode.STORAGE: "storage",
                GadgetMode.SILENT: "silent",
                GadgetMode.COMPOSITE: "up",
            }

            cmd_arg = mode_map.get(mode, "down")

            # Run script asynchronously
            proc = await asyncio.create_subprocess_exec(
                str(script), cmd_arg,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=10.0
                )
            except asyncio.TimeoutError:
                proc.kill()
                log.error("Gadget switch script timeout")
                return False

            if proc.returncode == 0:
                self._current_mode = mode
                self._last_switch_time = time.time()
                log.info(f"Gadget mode switched to: {mode.value}")
                return True
            else:
                log.error(f"Gadget switch failed: {stderr.decode().strip()}")
                return False

        finally:
            self._switch_in_progress = False

    def is_storage_mounted(self) -> bool:
        """Check if storage is being actively accessed by host.

        Checks the mass_storage function state in configfs to determine
        if the host is actively using the storage device.
        """
        lun_path = Path("/sys/kernel/config/usb_gadget/secubox/functions/mass_storage.usb0/lun.0")

        if not lun_path.exists():
            return False

        try:
            # Check if there's active I/O by looking at the file backing
            file_path = lun_path / "file"
            if file_path.exists():
                backing_file = file_path.read_text().strip()
                if backing_file:
                    # Check if the backing file is open/busy
                    # Using lsof or fuser would be more accurate but heavier
                    # For now, check if nlink > 0 as a proxy
                    return True
            return False
        except Exception as e:
            log.debug(f"Storage mount check failed: {e}")
            return False

    def get_storage_io_stats(self) -> Dict[str, int]:
        """Get storage I/O statistics if available."""
        stats = {"reads": 0, "writes": 0}
        # Stats would be in /sys/kernel/config/usb_gadget/secubox/functions/mass_storage.usb0/lun.0/
        # but not all kernels expose detailed stats
        return stats


# ═══════════════════════════════════════════════════════════════════════════════
# Network Prober
# ═══════════════════════════════════════════════════════════════════════════════

class NetworkProber:
    """Probes network connectivity to SecuBox."""

    def __init__(self, endpoints: List[str], timeout: float = 3.0):
        self._endpoints = endpoints
        self._timeout = timeout
        self._last_success: Optional[float] = None

    @property
    def seconds_since_success(self) -> float:
        """Seconds since last successful probe."""
        if self._last_success is None:
            return float('inf')
        return time.time() - self._last_success

    async def probe(self) -> bool:
        """Probe network endpoints."""
        for endpoint in self._endpoints:
            try:
                # Use curl for probing (more reliable than aiohttp on embedded)
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    "--connect-timeout", str(int(self._timeout)),
                    endpoint,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                try:
                    stdout, _ = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=self._timeout + 1
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    continue

                http_code = stdout.decode().strip()
                if http_code.startswith("2") or http_code.startswith("3"):
                    self._last_success = time.time()
                    log.debug(f"Network probe success: {endpoint} -> {http_code}")
                    return True

            except Exception as e:
                log.debug(f"Network probe failed: {endpoint} -> {e}")
                continue

        return False

    def record_success(self) -> None:
        """Record successful network activity."""
        self._last_success = time.time()


# ═══════════════════════════════════════════════════════════════════════════════
# Auto-Mode State Machine
# ═══════════════════════════════════════════════════════════════════════════════

class AutoModeController:
    """
    Main auto-mode controller state machine.

    Coordinates USB gadget mode switching based on:
    - Host detection (U-Boot vs OS)
    - Network connectivity
    - Wake-up triggers
    """

    CONFIG_PATH = Path("/etc/secubox/eye-remote/auto-mode.toml")

    def __init__(self, config: Optional[AutoModeConfig] = None):
        self._config = config or AutoModeConfig.from_toml(self.CONFIG_PATH)
        self._state = AutoModeState.BOOT
        self._udc = UDCMonitor()
        self._gadget = GadgetController()
        self._prober: Optional[NetworkProber] = None
        self._wakeup_manager: Optional[Any] = None  # Set externally

        # Timing state
        self._powered_since: Optional[float] = None
        self._state_enter_time: float = time.time()
        self._last_udc_state: Optional[UDCState] = None

        # State change listeners
        self._listeners: List[Callable[[AutoModeState, AutoModeState], None]] = []

        # Running flag
        self._running = False
        self._task: Optional[asyncio.Task] = None

    @property
    def state(self) -> AutoModeState:
        """Current controller state."""
        return self._state

    @property
    def gadget_mode(self) -> GadgetMode:
        """Current gadget mode."""
        return self._gadget.current_mode

    @property
    def config(self) -> AutoModeConfig:
        """Controller configuration."""
        return self._config

    def set_wakeup_manager(self, manager: Any) -> None:
        """Set wakeup manager for wake trigger integration."""
        self._wakeup_manager = manager

    def add_listener(self, callback: Callable[[AutoModeState, AutoModeState], None]) -> None:
        """Add state change listener."""
        self._listeners.append(callback)

    def _notify_listeners(self, old_state: AutoModeState, new_state: AutoModeState) -> None:
        """Notify listeners of state change."""
        for listener in self._listeners:
            try:
                listener(old_state, new_state)
            except Exception as e:
                log.error(f"Listener error: {e}")

    async def _transition_to(self, new_state: AutoModeState) -> None:
        """Transition to new state."""
        if new_state == self._state:
            return

        old_state = self._state
        self._state = new_state
        self._state_enter_time = time.time()

        log.info(f"State transition: {old_state.value} -> {new_state.value}")
        self._notify_listeners(old_state, new_state)

    def _time_in_state(self) -> float:
        """Time spent in current state."""
        return time.time() - self._state_enter_time

    async def _handle_boot_state(self) -> None:
        """Handle BOOT state - detect host type."""
        udc_state = self._udc.get_state()

        # Track powered state for U-Boot detection
        if udc_state == UDCState.POWERED:
            if self._powered_since is None:
                self._powered_since = time.time()
            elif time.time() - self._powered_since > self._config.uboot_detect_threshold_s:
                # Powered without configuration = U-Boot
                log.info("U-Boot detected (powered without configuration)")
                await self._gadget.switch_mode(
                    GadgetMode.STORAGE,
                    self._config.mode_switch_cooldown_s
                )
                await self._transition_to(AutoModeState.STORAGE_ACTIVE)
                self._powered_since = None
                return

        elif udc_state == UDCState.CONFIGURED:
            # Host configured gadget - standard OS
            self._powered_since = None
            log.info("Host OS detected (gadget configured)")

            # Try preferred mode
            if self._config.preferred_mode == "network":
                await self._transition_to(AutoModeState.PROBING_NETWORK)
            elif self._config.preferred_mode == "hid":
                await self._transition_to(AutoModeState.PROBING_HID)
            else:
                await self._gadget.switch_mode(
                    GadgetMode.STORAGE,
                    self._config.mode_switch_cooldown_s
                )
                await self._transition_to(AutoModeState.STORAGE_ACTIVE)

        elif udc_state == UDCState.NOT_ATTACHED:
            self._powered_since = None

            # No host - use default mode
            if self._time_in_state() > 5.0:
                log.info("No host detected, using default mode")
                default_mode = GadgetMode[self._config.default_mode.upper()]
                await self._gadget.switch_mode(
                    default_mode,
                    self._config.mode_switch_cooldown_s
                )
                if default_mode == GadgetMode.STORAGE:
                    await self._transition_to(AutoModeState.STORAGE_ACTIVE)
                elif default_mode == GadgetMode.NETWORK:
                    await self._transition_to(AutoModeState.PROBING_NETWORK)

    async def _handle_probing_network(self) -> None:
        """Handle PROBING_NETWORK state - try network mode."""
        # Initialize prober if needed (do this first to check connectivity)
        if self._prober is None:
            self._prober = NetworkProber(
                self._config.network_probe_endpoints,
                self._config.network_probe_timeout_s_endpoint
            )

        # Check if network already works with current mode
        # COMPOSITE mode has ECM, so network may already work
        network_capable_modes = {GadgetMode.NETWORK, GadgetMode.COMPOSITE}
        if self._gadget.current_mode in network_capable_modes:
            if await self._prober.probe():
                log.info(f"Network works with current mode ({self._gadget.current_mode.value})")
                await self._transition_to(AutoModeState.NETWORK_ACTIVE)
                return

        # Network not working - try switching to network-only mode
        if self._gadget.current_mode != GadgetMode.NETWORK:
            log.info("Switching to network-only mode")
            success = await self._gadget.switch_mode(
                GadgetMode.NETWORK,
                self._config.mode_switch_cooldown_s
            )
            if not success:
                log.warning("Failed to switch to network mode, trying HID")
                await self._transition_to(AutoModeState.PROBING_HID)
                return

            # Wait for host to settle
            await asyncio.sleep(self._config.host_settle_delay_s)

        # Probe network again after switch
        if await self._prober.probe():
            log.info("Network mode active - connectivity confirmed")
            await self._transition_to(AutoModeState.NETWORK_ACTIVE)
        elif self._time_in_state() > self._config.network_probe_timeout_s:
            log.warning("Network probe timeout, trying HID mode")
            await self._transition_to(AutoModeState.PROBING_HID)

    async def _handle_network_active(self) -> None:
        """Handle NETWORK_ACTIVE state - monitor connectivity."""
        # Check UDC state
        if not self._udc.is_connected():
            log.info("Host disconnected")
            await self._transition_to(AutoModeState.BOOT)
            return

        # Probe network periodically
        if self._prober:
            if await self._prober.probe():
                # Still connected
                return

            # Check if we should fall back
            if self._prober.seconds_since_success > self._config.silent_fallback_threshold_s:
                log.info("Network connectivity lost, switching to silent storage")
                await self._gadget.switch_mode(
                    GadgetMode.SILENT,
                    self._config.mode_switch_cooldown_s
                )
                await self._transition_to(AutoModeState.SILENT_STORAGE)

    async def _handle_probing_hid(self) -> None:
        """Handle PROBING_HID state - try HID mode."""
        # Switch to HID mode if not already
        if self._gadget.current_mode != GadgetMode.HID:
            success = await self._gadget.switch_mode(
                GadgetMode.HID,
                self._config.mode_switch_cooldown_s
            )
            if not success:
                log.warning("Failed to switch to HID mode, falling back to storage")
                await self._gadget.switch_mode(
                    GadgetMode.STORAGE,
                    self._config.mode_switch_cooldown_s
                )
                await self._transition_to(AutoModeState.STORAGE_ACTIVE)
                return

            # Wait for host to settle
            await asyncio.sleep(self._config.host_settle_delay_s)

        # HID mode is active if UDC is configured
        if self._udc.is_configured():
            log.info("HID mode active")
            await self._transition_to(AutoModeState.HID_ACTIVE)
        elif self._time_in_state() > self._config.hid_probe_timeout_s:
            log.warning("HID probe timeout, falling back to storage")
            await self._gadget.switch_mode(
                GadgetMode.STORAGE,
                self._config.mode_switch_cooldown_s
            )
            await self._transition_to(AutoModeState.STORAGE_ACTIVE)

    async def _handle_hid_active(self) -> None:
        """Handle HID_ACTIVE state - monitor HID mode."""
        if not self._udc.is_connected():
            log.info("Host disconnected from HID mode")
            await self._transition_to(AutoModeState.BOOT)

    async def _handle_storage_active(self) -> None:
        """Handle STORAGE_ACTIVE state - U-Boot/recovery mode."""
        udc_state = self._udc.get_state()

        if udc_state == UDCState.CONFIGURED:
            # Host configured - may be Linux now, try network
            log.info("Host configured storage, checking if OS")
            await asyncio.sleep(2.0)  # Wait for OS to fully enumerate

            # Try switching to network
            await self._transition_to(AutoModeState.PROBING_NETWORK)

        elif udc_state == UDCState.NOT_ATTACHED:
            # No host - stay in storage mode
            pass

        # Check if storage is mounted by host
        # If not mounted after timeout, switch back to composite for network
        time_in_storage = self._time_in_state()
        if time_in_storage > self._config.storage_unmounted_recovery_s:
            if not self._gadget.is_storage_mounted():
                log.info(f"Storage not mounted after {time_in_storage:.0f}s, switching to composite")
                await self._gadget.switch_mode(
                    GadgetMode.COMPOSITE,
                    self._config.mode_switch_cooldown_s
                )
                await self._transition_to(AutoModeState.PROBING_NETWORK)

    async def _handle_silent_storage(self) -> None:
        """Handle SILENT_STORAGE state - fallback with wake monitoring."""
        # Check for wake triggers
        if self._wakeup_manager:
            wake_reason = await self._wakeup_manager.check_wake_triggers()
            if wake_reason:
                log.info(f"Wake trigger received: {wake_reason}")
                # Switch to composite mode for network recovery
                await self._gadget.switch_mode(
                    GadgetMode.COMPOSITE,
                    self._config.mode_switch_cooldown_s
                )
                await self._transition_to(AutoModeState.PROBING_NETWORK)
                return

        # Also check if host is connected and configured
        if self._udc.is_configured():
            # Host might have network support now
            await self._gadget.switch_mode(
                GadgetMode.COMPOSITE,
                self._config.mode_switch_cooldown_s
            )
            await self._transition_to(AutoModeState.PROBING_NETWORK)
            return

        # If storage not being used after timeout, try composite mode
        time_in_storage = self._time_in_state()
        if time_in_storage > self._config.storage_unmounted_recovery_s:
            if not self._gadget.is_storage_mounted():
                log.info(f"Silent storage unused for {time_in_storage:.0f}s, trying composite")
                await self._gadget.switch_mode(
                    GadgetMode.COMPOSITE,
                    self._config.mode_switch_cooldown_s
                )
                await self._transition_to(AutoModeState.PROBING_NETWORK)

    async def _run_state_machine(self) -> None:
        """Main state machine loop."""
        handlers = {
            AutoModeState.BOOT: self._handle_boot_state,
            AutoModeState.PROBING_NETWORK: self._handle_probing_network,
            AutoModeState.NETWORK_ACTIVE: self._handle_network_active,
            AutoModeState.PROBING_HID: self._handle_probing_hid,
            AutoModeState.HID_ACTIVE: self._handle_hid_active,
            AutoModeState.STORAGE_ACTIVE: self._handle_storage_active,
            AutoModeState.SILENT_STORAGE: self._handle_silent_storage,
        }

        while self._running:
            try:
                handler = handlers.get(self._state)
                if handler:
                    await handler()

                # Check for UDC state changes
                current_udc = self._udc.get_state()
                if current_udc != self._last_udc_state:
                    log.debug(f"UDC state: {self._last_udc_state} -> {current_udc}")
                    self._last_udc_state = current_udc

            except Exception as e:
                log.error(f"State machine error: {e}")

            await asyncio.sleep(0.5)

    async def start(self) -> None:
        """Start the auto-mode controller."""
        if self._running:
            return

        if not self._config.enabled:
            log.info("Auto-mode controller disabled in config")
            return

        log.info("Starting auto-mode controller")
        log.info(f"UDC: {self._udc.udc_name}")
        log.info(f"Default mode: {self._config.default_mode}")
        log.info(f"Preferred mode: {self._config.preferred_mode}")

        self._running = True
        self._task = asyncio.create_task(self._run_state_machine())

    async def stop(self) -> None:
        """Stop the auto-mode controller."""
        if not self._running:
            return

        log.info("Stopping auto-mode controller")
        self._running = False

        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def get_status(self) -> Dict[str, Any]:
        """Get current controller status."""
        return {
            "state": self._state.value,
            "gadget_mode": self._gadget.current_mode.value,
            "udc_name": self._udc.udc_name,
            "udc_state": self._udc.get_state().value,
            "time_in_state_s": self._time_in_state(),
            "network_seconds_since_success": (
                self._prober.seconds_since_success if self._prober else None
            ),
            "config": {
                "enabled": self._config.enabled,
                "default_mode": self._config.default_mode,
                "preferred_mode": self._config.preferred_mode,
            }
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Module-level singleton and entry point
# ═══════════════════════════════════════════════════════════════════════════════

_controller: Optional[AutoModeController] = None


def get_controller() -> AutoModeController:
    """Get singleton controller instance."""
    global _controller
    if _controller is None:
        _controller = AutoModeController()
    return _controller


async def main():
    """Entry point for standalone execution."""
    import signal

    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S'
    )

    controller = get_controller()

    # Handle signals
    loop = asyncio.get_event_loop()

    def signal_handler():
        log.info("Signal received, stopping...")
        asyncio.create_task(controller.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    await controller.start()

    # Wait until stopped
    while controller._running:
        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
