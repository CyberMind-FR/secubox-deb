#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote — Wake-up Manager

Handles wake-up triggers to exit silent storage mode and retry network.
All wake mechanisms are non-destructive to USB storage operations.

Wake-up Mechanisms:
1. Serial Console (ACM) - Send "WAKE" command via serial
2. Magic File - Create WAKE_NETWORK file on USB storage
3. GPIO Button - Long-press GPIO pin (default: 17)
4. Scheduled Check - Periodic retry every N minutes

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
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, List, Any

log = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class WakeupConfig:
    """Configuration for wake-up manager."""
    # Serial wake
    serial_enabled: bool = True
    serial_device: str = "/dev/ttyGS0"
    serial_patterns: List[str] = None  # Patterns that trigger wake

    # Magic file wake
    magic_file_enabled: bool = True
    magic_file_name: str = "WAKE_NETWORK"
    storage_mount_point: str = "/mnt/secubox-storage"
    storage_image: str = "/var/lib/secubox/eye-remote/storage.img"

    # GPIO button wake
    gpio_enabled: bool = True
    gpio_pin: int = 17
    gpio_long_press_s: float = 3.0

    # Scheduled check
    scheduled_enabled: bool = True
    scheduled_interval_m: int = 5

    def __post_init__(self):
        if self.serial_patterns is None:
            self.serial_patterns = ["WAKE", "wake", "NETWORK", "network"]


# ═══════════════════════════════════════════════════════════════════════════════
# Serial Console Monitor
# ═══════════════════════════════════════════════════════════════════════════════

class SerialWakeMonitor:
    """
    Monitors ACM serial console for wake patterns.
    ACM function works alongside mass storage, so this is always available.
    """

    def __init__(self, config: WakeupConfig):
        self._config = config
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._wake_triggered = False
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def wake_triggered(self) -> bool:
        """Check if wake was triggered and reset flag."""
        if self._wake_triggered:
            self._wake_triggered = False
            return True
        return False

    async def _monitor_serial(self) -> None:
        """Monitor serial port for wake patterns."""
        device = self._config.serial_device

        while self._running:
            try:
                # Check if device exists
                if not Path(device).exists():
                    await asyncio.sleep(1.0)
                    continue

                # Open serial device
                proc = await asyncio.create_subprocess_exec(
                    "stty", "-F", device, "115200", "raw", "-echo",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                await proc.wait()

                # Read from serial
                with open(device, 'rb') as f:
                    # Set non-blocking
                    os.set_blocking(f.fileno(), False)

                    buffer = b""
                    while self._running:
                        try:
                            chunk = f.read(64)
                            if chunk:
                                buffer += chunk
                                # Check for wake patterns
                                text = buffer.decode('utf-8', errors='ignore')
                                for pattern in self._config.serial_patterns:
                                    if pattern in text:
                                        log.info(f"Serial wake pattern detected: {pattern}")
                                        self._wake_triggered = True
                                        buffer = b""
                                        break
                                # Keep buffer manageable
                                if len(buffer) > 256:
                                    buffer = buffer[-128:]
                            else:
                                await asyncio.sleep(0.1)
                        except (BlockingIOError, IOError):
                            await asyncio.sleep(0.1)

            except Exception as e:
                log.debug(f"Serial monitor error: {e}")
                await asyncio.sleep(2.0)

    async def start(self) -> None:
        """Start serial monitoring."""
        if not self._config.serial_enabled:
            return

        if self._running:
            return

        log.info(f"Starting serial wake monitor on {self._config.serial_device}")
        self._running = True
        self._task = asyncio.create_task(self._monitor_serial())

    async def stop(self) -> None:
        """Stop serial monitoring."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# Magic File Monitor
# ═══════════════════════════════════════════════════════════════════════════════

class MagicFileWakeMonitor:
    """
    Monitors USB storage for magic wake file.
    Host can create WAKE_NETWORK file to signal Eye Remote to retry network.
    """

    def __init__(self, config: WakeupConfig):
        self._config = config
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._wake_triggered = False
        self._mount_point = Path(config.storage_mount_point)
        self._was_mounted = False

    @property
    def wake_triggered(self) -> bool:
        """Check if wake was triggered and reset flag."""
        if self._wake_triggered:
            self._wake_triggered = False
            return True
        return False

    def _is_storage_mounted(self) -> bool:
        """Check if storage image is mounted."""
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    if self._config.storage_mount_point in line:
                        return True
        except Exception:
            pass
        return False

    def _mount_storage(self) -> bool:
        """Mount storage image temporarily for checking."""
        if self._is_storage_mounted():
            return True

        if not Path(self._config.storage_image).exists():
            return False

        try:
            self._mount_point.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                ["mount", "-o", "loop,ro", self._config.storage_image, str(self._mount_point)],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception as e:
            log.debug(f"Failed to mount storage: {e}")
            return False

    def _unmount_storage(self) -> None:
        """Unmount storage image."""
        try:
            subprocess.run(
                ["umount", str(self._mount_point)],
                capture_output=True,
                timeout=5
            )
        except Exception:
            pass

    async def _check_magic_file(self) -> bool:
        """Check for magic wake file."""
        if not self._mount_storage():
            return False

        try:
            magic_file = self._mount_point / self._config.magic_file_name
            if magic_file.exists():
                log.info(f"Magic wake file detected: {magic_file}")
                # Remove the file to prevent repeated triggers
                try:
                    magic_file.unlink()
                except Exception:
                    pass
                return True
            return False
        finally:
            # Only unmount if we mounted it
            if not self._was_mounted:
                self._unmount_storage()

    async def _monitor_loop(self) -> None:
        """Monitor for magic file periodically."""
        while self._running:
            try:
                self._was_mounted = self._is_storage_mounted()

                if await self._check_magic_file():
                    self._wake_triggered = True

                # Check every 10 seconds
                await asyncio.sleep(10.0)

            except Exception as e:
                log.debug(f"Magic file monitor error: {e}")
                await asyncio.sleep(10.0)

    async def start(self) -> None:
        """Start magic file monitoring."""
        if not self._config.magic_file_enabled:
            return

        if self._running:
            return

        log.info(f"Starting magic file wake monitor, looking for: {self._config.magic_file_name}")
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        """Stop magic file monitoring."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# GPIO Button Monitor
# ═══════════════════════════════════════════════════════════════════════════════

class GPIOWakeMonitor:
    """
    Monitors GPIO button for long-press wake trigger.
    Requires gpiod library or sysfs GPIO access.
    """

    def __init__(self, config: WakeupConfig):
        self._config = config
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._wake_triggered = False
        self._press_start: Optional[float] = None

    @property
    def wake_triggered(self) -> bool:
        """Check if wake was triggered and reset flag."""
        if self._wake_triggered:
            self._wake_triggered = False
            return True
        return False

    def _setup_gpio(self) -> bool:
        """Setup GPIO pin using sysfs."""
        gpio_path = Path(f"/sys/class/gpio/gpio{self._config.gpio_pin}")

        try:
            # Export pin if needed
            if not gpio_path.exists():
                with open("/sys/class/gpio/export", "w") as f:
                    f.write(str(self._config.gpio_pin))
                time.sleep(0.1)

            # Set as input
            direction_path = gpio_path / "direction"
            if direction_path.exists():
                with open(direction_path, "w") as f:
                    f.write("in")

            # Set pull-up (edge detection)
            edge_path = gpio_path / "edge"
            if edge_path.exists():
                with open(edge_path, "w") as f:
                    f.write("both")

            return True

        except Exception as e:
            log.debug(f"GPIO setup failed: {e}")
            return False

    def _read_gpio(self) -> Optional[int]:
        """Read GPIO pin value."""
        value_path = Path(f"/sys/class/gpio/gpio{self._config.gpio_pin}/value")
        try:
            if value_path.exists():
                return int(value_path.read_text().strip())
        except Exception:
            pass
        return None

    async def _monitor_loop(self) -> None:
        """Monitor GPIO for long-press."""
        if not self._setup_gpio():
            log.warning("GPIO setup failed, disabling GPIO wake")
            return

        while self._running:
            try:
                value = self._read_gpio()

                if value == 0:  # Button pressed (active low with pull-up)
                    if self._press_start is None:
                        self._press_start = time.time()
                        log.debug("GPIO button press started")
                    elif time.time() - self._press_start >= self._config.gpio_long_press_s:
                        log.info(f"GPIO long-press wake detected on pin {self._config.gpio_pin}")
                        self._wake_triggered = True
                        self._press_start = None
                        # Debounce
                        await asyncio.sleep(1.0)
                else:
                    self._press_start = None

                await asyncio.sleep(0.05)  # 50ms polling

            except Exception as e:
                log.debug(f"GPIO monitor error: {e}")
                await asyncio.sleep(1.0)

    async def start(self) -> None:
        """Start GPIO monitoring."""
        if not self._config.gpio_enabled:
            return

        if self._running:
            return

        log.info(f"Starting GPIO wake monitor on pin {self._config.gpio_pin}")
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        """Stop GPIO monitoring."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# Scheduled Check Monitor
# ═══════════════════════════════════════════════════════════════════════════════

class ScheduledWakeMonitor:
    """
    Triggers periodic wake checks at configured intervals.
    Allows Eye Remote to retry network periodically.
    """

    def __init__(self, config: WakeupConfig):
        self._config = config
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._wake_triggered = False
        self._last_check: float = time.time()

    @property
    def wake_triggered(self) -> bool:
        """Check if wake was triggered and reset flag."""
        if self._wake_triggered:
            self._wake_triggered = False
            return True
        return False

    async def _monitor_loop(self) -> None:
        """Monitor for scheduled wake times."""
        interval_s = self._config.scheduled_interval_m * 60

        while self._running:
            try:
                elapsed = time.time() - self._last_check

                if elapsed >= interval_s:
                    log.info(f"Scheduled wake check triggered ({self._config.scheduled_interval_m} min interval)")
                    self._wake_triggered = True
                    self._last_check = time.time()

                await asyncio.sleep(30.0)  # Check every 30s

            except Exception as e:
                log.debug(f"Scheduled monitor error: {e}")
                await asyncio.sleep(30.0)

    async def start(self) -> None:
        """Start scheduled monitoring."""
        if not self._config.scheduled_enabled:
            return

        if self._running:
            return

        log.info(f"Starting scheduled wake monitor ({self._config.scheduled_interval_m} min interval)")
        self._running = True
        self._last_check = time.time()  # Reset on start
        self._task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        """Stop scheduled monitoring."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# Wake-up Manager
# ═══════════════════════════════════════════════════════════════════════════════

class WakeupManager:
    """
    Coordinates all wake-up mechanisms for silent storage mode.

    Usage:
        manager = WakeupManager()
        await manager.start()

        # In silent storage mode:
        while in_silent_mode:
            reason = await manager.check_wake_triggers()
            if reason:
                print(f"Wake triggered: {reason}")
                break
    """

    def __init__(self, config: Optional[WakeupConfig] = None):
        self._config = config or WakeupConfig()
        self._serial = SerialWakeMonitor(self._config)
        self._magic_file = MagicFileWakeMonitor(self._config)
        self._gpio = GPIOWakeMonitor(self._config)
        self._scheduled = ScheduledWakeMonitor(self._config)
        self._running = False

    @property
    def config(self) -> WakeupConfig:
        return self._config

    async def start(self) -> None:
        """Start all wake monitors."""
        if self._running:
            return

        log.info("Starting wake-up manager")
        self._running = True

        await self._serial.start()
        await self._magic_file.start()
        await self._gpio.start()
        await self._scheduled.start()

    async def stop(self) -> None:
        """Stop all wake monitors."""
        if not self._running:
            return

        log.info("Stopping wake-up manager")
        self._running = False

        await self._serial.stop()
        await self._magic_file.stop()
        await self._gpio.stop()
        await self._scheduled.stop()

    async def check_wake_triggers(self) -> Optional[str]:
        """
        Check all wake triggers and return reason if any triggered.

        Returns:
            Wake reason string if triggered, None otherwise.
        """
        if self._serial.wake_triggered:
            return "serial_console"

        if self._magic_file.wake_triggered:
            return "magic_file"

        if self._gpio.wake_triggered:
            return "gpio_button"

        if self._scheduled.wake_triggered:
            return "scheduled_check"

        return None

    def get_status(self) -> dict:
        """Get current status of all wake monitors."""
        return {
            "running": self._running,
            "monitors": {
                "serial": {
                    "enabled": self._config.serial_enabled,
                    "running": self._serial.is_running,
                    "device": self._config.serial_device,
                },
                "magic_file": {
                    "enabled": self._config.magic_file_enabled,
                    "file_name": self._config.magic_file_name,
                },
                "gpio": {
                    "enabled": self._config.gpio_enabled,
                    "pin": self._config.gpio_pin,
                    "long_press_s": self._config.gpio_long_press_s,
                },
                "scheduled": {
                    "enabled": self._config.scheduled_enabled,
                    "interval_m": self._config.scheduled_interval_m,
                },
            }
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Factory function
# ═══════════════════════════════════════════════════════════════════════════════

def create_wakeup_manager(
    serial_enabled: bool = True,
    serial_patterns: Optional[List[str]] = None,
    magic_file_enabled: bool = True,
    magic_file_name: str = "WAKE_NETWORK",
    gpio_enabled: bool = True,
    gpio_pin: int = 17,
    gpio_long_press_s: float = 3.0,
    scheduled_enabled: bool = True,
    scheduled_interval_m: int = 5,
) -> WakeupManager:
    """Create configured wake-up manager."""
    config = WakeupConfig(
        serial_enabled=serial_enabled,
        serial_patterns=serial_patterns or ["WAKE", "wake", "NETWORK", "network"],
        magic_file_enabled=magic_file_enabled,
        magic_file_name=magic_file_name,
        gpio_enabled=gpio_enabled,
        gpio_pin=gpio_pin,
        gpio_long_press_s=gpio_long_press_s,
        scheduled_enabled=scheduled_enabled,
        scheduled_interval_m=scheduled_interval_m,
    )
    return WakeupManager(config)


# ═══════════════════════════════════════════════════════════════════════════════
# Standalone test
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Test wake-up manager."""
    import signal

    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S'
    )

    manager = WakeupManager()

    # Handle signals
    loop = asyncio.get_event_loop()
    running = True

    def signal_handler():
        nonlocal running
        log.info("Signal received, stopping...")
        running = False

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    await manager.start()

    log.info("Wake-up manager running, waiting for triggers...")
    log.info("Triggers: serial 'WAKE', magic file, GPIO long-press, or 5 min scheduled")

    while running:
        reason = await manager.check_wake_triggers()
        if reason:
            log.info(f">>> WAKE TRIGGERED: {reason}")

        await asyncio.sleep(0.5)

    await manager.stop()


if __name__ == "__main__":
    asyncio.run(main())
