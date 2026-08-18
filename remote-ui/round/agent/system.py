# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote - System Controllers
Stub implementations for WiFi, Bluetooth, and Display management.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

log = logging.getLogger(__name__)


@dataclass
class WifiNetwork:
    """Represents a WiFi network."""
    ssid: str
    bssid: str = ""
    signal: int = 0
    security: str = "WPA2"
    connected: bool = False


class WifiManager:
    """
    Manages WiFi connections on the Pi Zero W.
    Uses wpa_supplicant via wpa_cli.
    """

    def __init__(self):
        self._connected = False
        self._current_ssid: Optional[str] = None
        self._interface = "wlan0"

    @property
    def is_connected(self) -> bool:
        """Check if WiFi is connected."""
        try:
            result = subprocess.run(
                ["iwgetid", "-r"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                self._connected = True
                self._current_ssid = result.stdout.strip()
                return True
        except Exception as e:
            log.debug(f"WiFi check error: {e}")
        self._connected = False
        return False

    @property
    def current_ssid(self) -> Optional[str]:
        """Get current SSID if connected."""
        self.is_connected  # Update state
        return self._current_ssid

    def scan(self) -> List[WifiNetwork]:
        """Scan for available networks."""
        networks = []
        try:
            result = subprocess.run(
                ["iwlist", self._interface, "scan"],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                # Parse iwlist output (simplified)
                current_ssid = None
                current_signal = 0
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if 'ESSID:' in line:
                        ssid = line.split('ESSID:')[1].strip('"')
                        if ssid:
                            networks.append(WifiNetwork(
                                ssid=ssid,
                                signal=current_signal,
                                connected=(ssid == self._current_ssid)
                            ))
                    elif 'Signal level=' in line:
                        try:
                            sig_part = line.split('Signal level=')[1]
                            current_signal = int(sig_part.split(' ')[0].replace('dBm', ''))
                        except (IndexError, ValueError):
                            current_signal = 0
        except Exception as e:
            log.error(f"WiFi scan error: {e}")
        return networks

    async def connect(self, ssid: str, password: str) -> bool:
        """Connect to a WiFi network."""
        log.info(f"Connecting to WiFi: {ssid}")
        # Would use wpa_cli or nmcli in production
        return False

    async def disconnect(self) -> bool:
        """Disconnect from current network."""
        log.info("Disconnecting from WiFi")
        return False


class BluetoothManager:
    """
    Manages Bluetooth connections.
    Stub implementation for future BLE device pairing.
    """

    def __init__(self):
        self._enabled = False
        self._paired_devices: List[str] = []

    @property
    def is_enabled(self) -> bool:
        """Check if Bluetooth is enabled."""
        try:
            result = subprocess.run(
                ["bluetoothctl", "show"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                self._enabled = "Powered: yes" in result.stdout
                return self._enabled
        except Exception as e:
            log.debug(f"Bluetooth check error: {e}")
        return False

    async def enable(self) -> bool:
        """Enable Bluetooth."""
        log.info("Enabling Bluetooth")
        return False

    async def disable(self) -> bool:
        """Disable Bluetooth."""
        log.info("Disabling Bluetooth")
        return False

    def get_paired_devices(self) -> List[str]:
        """Get list of paired devices."""
        return self._paired_devices


class DisplayController:
    """
    Controls the HyperPixel display.
    Manages brightness, rotation, and power state.
    """

    def __init__(self):
        self._brightness = 100
        self._backlight_path = Path("/sys/class/backlight/rpi_backlight/brightness")
        self._max_brightness = 255

    @property
    def brightness(self) -> int:
        """Get current brightness (0-100)."""
        return self._brightness

    def set_brightness(self, value: int) -> bool:
        """Set brightness (0-100)."""
        value = max(0, min(100, value))
        self._brightness = value

        # Try to set actual backlight if available
        if self._backlight_path.exists():
            try:
                hw_value = int(value * self._max_brightness / 100)
                self._backlight_path.write_text(str(hw_value))
                return True
            except Exception as e:
                log.error(f"Failed to set brightness: {e}")
                return False
        return True

    def blank(self) -> bool:
        """Blank the display (power save)."""
        log.info("Blanking display")
        try:
            with open("/dev/fb0", "wb") as fb:
                fb.write(b'\x00' * (480 * 480 * 4))
            return True
        except Exception as e:
            log.error(f"Failed to blank display: {e}")
            return False

    def unblank(self) -> bool:
        """Unblank the display."""
        log.info("Unblanking display")
        return True
