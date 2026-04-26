"""
SecuBox Eye Remote — Display Controller
Manages display brightness and power for HyperPixel 2.1 Round display.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class DisplayStatus:
    """Display status information."""
    brightness: int  # 0-100 percentage
    power_on: bool
    timeout_seconds: int


class DisplayController:
    """
    Controls display brightness and power.

    Provides an async interface for managing the HyperPixel 2.1 Round
    display on the Eye Remote device. Supports brightness control,
    power management (sleep/wake), and timeout-based auto-sleep.

    When no hardware backlight device is available, the controller
    operates in simulation mode, maintaining state internally.
    """

    BACKLIGHT_PATH = "/sys/class/backlight"

    def __init__(self, backlight_device: str = "rpi_backlight"):
        """
        Initialize the display controller.

        Args:
            backlight_device: Name of the backlight device in sysfs
                             (default: rpi_backlight)
        """
        self._device = backlight_device
        self._timeout = 300  # Default 5 minutes
        self._last_activity = time.time()

        # Simulation mode state
        self._simulation_mode = False
        self._sim_brightness = 100
        self._sim_power_on = True
        self._last_brightness = 100  # For wake restore

        # Lock for thread safety
        self._lock = asyncio.Lock()

    def _get_backlight_path(self) -> Path:
        """
        Get path to backlight device.

        Returns:
            Path object pointing to the backlight device directory
        """
        return Path(self.BACKLIGHT_PATH) / self._device

    def _get_brightness_path(self) -> Path:
        """Get path to brightness file."""
        return self._get_backlight_path() / "brightness"

    def _get_max_brightness_path(self) -> Path:
        """Get path to max_brightness file."""
        return self._get_backlight_path() / "max_brightness"

    def _get_bl_power_path(self) -> Path:
        """Get path to bl_power file (power control)."""
        return self._get_backlight_path() / "bl_power"

    def _device_exists(self) -> bool:
        """Check if the backlight device exists."""
        return self._get_backlight_path().exists()

    async def _read_sysfs(self, path: Path) -> Optional[str]:
        """
        Read a sysfs file asynchronously.

        Args:
            path: Path to the sysfs file

        Returns:
            File contents as string, or None on error
        """
        try:
            # Use asyncio.to_thread for blocking I/O
            def _read():
                return path.read_text().strip()

            return await asyncio.to_thread(_read)
        except (FileNotFoundError, PermissionError, OSError) as e:
            log.debug(f"Failed to read {path}: {e}")
            return None

    async def _write_sysfs(self, path: Path, value: str) -> bool:
        """
        Write to a sysfs file asynchronously.

        Args:
            path: Path to the sysfs file
            value: Value to write

        Returns:
            True if write succeeded, False otherwise
        """
        try:
            def _write():
                path.write_text(value)

            await asyncio.to_thread(_write)
            return True
        except (FileNotFoundError, PermissionError, OSError) as e:
            log.warning(f"Failed to write to {path}: {e}")
            return False

    async def _get_max_brightness_value(self) -> int:
        """
        Get the maximum brightness value from sysfs.

        Returns:
            Maximum brightness value, or 255 as default
        """
        content = await self._read_sysfs(self._get_max_brightness_path())
        if content:
            try:
                return int(content)
            except ValueError:
                log.warning(f"Invalid max_brightness value: {content}")
        return 255  # Default fallback

    async def set_brightness(self, level: int) -> bool:
        """
        Set display brightness level.

        Args:
            level: Brightness level 0-100 (percentage)

        Returns:
            True if brightness was set successfully, False otherwise
        """
        async with self._lock:
            # Clamp to valid range
            level = max(0, min(100, level))

            if not self._device_exists():
                # Simulation mode
                self._simulation_mode = True
                self._sim_brightness = level
                log.debug(f"Simulation mode: set brightness to {level}%")
                return True

            # Get max brightness
            max_brightness = await self._get_max_brightness_value()

            # Scale percentage to device value
            device_value = round((level / 100) * max_brightness)

            # Write to sysfs
            result = await self._write_sysfs(
                self._get_brightness_path(),
                str(device_value)
            )

            if result:
                log.info(f"Display brightness set to {level}% ({device_value}/{max_brightness})")
                self._last_brightness = level

            return result

    async def get_brightness(self) -> int:
        """
        Get current display brightness level.

        Returns:
            Brightness level 0-100 (percentage), 0 on error
        """
        async with self._lock:
            if not self._device_exists():
                # Simulation mode
                self._simulation_mode = True
                return self._sim_brightness

            # Read current brightness
            current = await self._read_sysfs(self._get_brightness_path())
            max_val = await self._read_sysfs(self._get_max_brightness_path())

            if current is None or max_val is None:
                return 0

            try:
                current_int = int(current)
                max_int = int(max_val)

                if max_int == 0:
                    return 0

                # Convert to percentage
                return round((current_int / max_int) * 100)

            except ValueError:
                log.warning(f"Invalid brightness values: current={current}, max={max_val}")
                return 0

    async def set_timeout(self, seconds: int) -> None:
        """
        Set display timeout before sleep.

        Args:
            seconds: Timeout duration in seconds (0 to disable)
        """
        self._timeout = max(0, seconds)
        log.info(f"Display timeout set to {self._timeout}s")

    async def wake(self) -> bool:
        """
        Wake display from sleep.

        Returns:
            True if display was woken successfully, False otherwise
        """
        async with self._lock:
            if not self._device_exists():
                # Simulation mode
                self._simulation_mode = True
                self._sim_power_on = True
                log.debug("Simulation mode: display woken")
                return True

            # First, try bl_power (0 = on)
            bl_power_path = self._get_bl_power_path()
            if bl_power_path.exists():
                result = await self._write_sysfs(bl_power_path, "0")
                if result:
                    log.info("Display woken via bl_power")

            # Restore previous brightness
            if self._last_brightness > 0:
                max_brightness = await self._get_max_brightness_value()
                device_value = round((self._last_brightness / 100) * max_brightness)
                await self._write_sysfs(
                    self._get_brightness_path(),
                    str(device_value)
                )

            self.record_activity()
            return True

    async def sleep(self) -> bool:
        """
        Put display to sleep.

        Returns:
            True if display was put to sleep successfully, False otherwise
        """
        async with self._lock:
            if not self._device_exists():
                # Simulation mode
                self._simulation_mode = True
                self._sim_power_on = False
                log.debug("Simulation mode: display sleeping")
                return True

            # Save current brightness for wake restore
            current = await self._read_sysfs(self._get_brightness_path())
            max_val = await self._read_sysfs(self._get_max_brightness_path())

            if current and max_val:
                try:
                    current_int = int(current)
                    max_int = int(max_val)
                    if max_int > 0 and current_int > 0:
                        self._last_brightness = round((current_int / max_int) * 100)
                except ValueError:
                    pass

            # Try bl_power first (1 = off)
            bl_power_path = self._get_bl_power_path()
            if bl_power_path.exists():
                result = await self._write_sysfs(bl_power_path, "1")
                if result:
                    log.info("Display sleeping via bl_power")
                    return True

            # Fallback: set brightness to 0
            result = await self._write_sysfs(self._get_brightness_path(), "0")
            if result:
                log.info("Display sleeping via brightness=0")

            return result

    async def status(self) -> DisplayStatus:
        """
        Get current display status.

        Returns:
            DisplayStatus with brightness, power state, and timeout
        """
        if not self._device_exists():
            # Simulation mode
            self._simulation_mode = True
            return DisplayStatus(
                brightness=self._sim_brightness,
                power_on=self._sim_power_on,
                timeout_seconds=self._timeout
            )

        # Get brightness
        brightness = await self.get_brightness()

        # Get power state
        power_on = True
        bl_power_content = await self._read_sysfs(self._get_bl_power_path())
        if bl_power_content:
            try:
                # bl_power: 0 = on, 1 = off
                power_on = int(bl_power_content) == 0
            except ValueError:
                # If we can't read bl_power, assume on if brightness > 0
                power_on = brightness > 0

        return DisplayStatus(
            brightness=brightness,
            power_on=power_on,
            timeout_seconds=self._timeout
        )

    def record_activity(self) -> None:
        """
        Record user activity to reset timeout.

        Should be called on any user interaction (touch, button press)
        to prevent auto-sleep during active use.
        """
        self._last_activity = time.time()

    async def check_timeout(self) -> bool:
        """
        Check if display should sleep due to timeout.

        Returns:
            True if timeout has expired and display should sleep,
            False otherwise
        """
        if self._timeout <= 0:
            # Timeout disabled
            return False

        elapsed = time.time() - self._last_activity
        return elapsed >= self._timeout

    @property
    def is_simulation_mode(self) -> bool:
        """Check if controller is running in simulation mode."""
        return self._simulation_mode

    @property
    def timeout_remaining(self) -> float:
        """
        Get remaining time before timeout.

        Returns:
            Seconds until timeout, 0 if already expired,
            -1 if timeout is disabled
        """
        if self._timeout <= 0:
            return -1

        elapsed = time.time() - self._last_activity
        remaining = self._timeout - elapsed
        return max(0, remaining)
