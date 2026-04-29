#!/usr/bin/env python3
"""
SecuBox Eye Remote - USB Gadget Control API

Manages USB OTG gadget modes and provides status information.
Supports ECM (Ethernet), ACM (Serial), Mass Storage, and Composite modes.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import os
import subprocess
import time
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Any, List


class GadgetMode(Enum):
    """USB Gadget modes."""
    NONE = "none"
    ECM = "ecm"              # CDC Ethernet (Network)
    ACM = "acm"              # CDC Serial (Console)
    MASS_STORAGE = "mass_storage"  # USB Mass Storage
    COMPOSITE = "composite"  # ECM + ACM + Mass Storage


class ConnectionState(Enum):
    """Host connection state."""
    DISCONNECTED = "disconnected"
    CONNECTED = "connected"
    TRANSFERRING = "transferring"


@dataclass
class GadgetStatus:
    """Current gadget status."""
    mode: GadgetMode = GadgetMode.NONE
    connection: ConnectionState = ConnectionState.DISCONNECTED
    host_ip: str = ""
    device_ip: str = "10.55.0.2"

    # ECM stats
    ecm_interface: str = "usb0"
    ecm_rx_bytes: int = 0
    ecm_tx_bytes: int = 0
    ecm_rx_packets: int = 0
    ecm_tx_packets: int = 0

    # ACM stats
    acm_device: str = "/dev/ttyGS0"
    acm_active: bool = False

    # Mass storage stats
    storage_partition: str = ""
    storage_mounted: bool = False
    storage_size_mb: int = 0
    storage_used_mb: int = 0

    # Transfer activity
    last_rx_bytes: int = 0
    last_tx_bytes: int = 0
    rx_rate_kbps: float = 0.0
    tx_rate_kbps: float = 0.0

    # Timestamps
    last_update: float = 0.0
    connected_since: float = 0.0


# ConfigFS paths
CONFIGFS_BASE = Path("/sys/kernel/config/usb_gadget")
GADGET_NAME = "secubox"
GADGET_PATH = CONFIGFS_BASE / GADGET_NAME

# Network interface
ECM_INTERFACE = "usb0"
HOST_IP = "10.55.0.1"
DEVICE_IP = "10.55.0.2"


class GadgetController:
    """Controls USB gadget configuration and monitors status."""

    def __init__(self):
        self._status = GadgetStatus()
        self._last_stats_time = 0
        self._stats_interval = 1.0

    def get_status(self) -> GadgetStatus:
        """Get current gadget status."""
        self._update_status()
        return self._status

    def _update_status(self):
        """Update status from system."""
        now = time.time()

        # Detect current mode
        self._status.mode = self._detect_mode()

        # Update ECM status
        if self._status.mode in (GadgetMode.ECM, GadgetMode.COMPOSITE):
            self._update_ecm_status()

        # Update ACM status
        if self._status.mode in (GadgetMode.ACM, GadgetMode.COMPOSITE):
            self._update_acm_status()

        # Update mass storage status
        if self._status.mode in (GadgetMode.MASS_STORAGE, GadgetMode.COMPOSITE):
            self._update_storage_status()

        # Calculate transfer rates
        if now - self._last_stats_time >= self._stats_interval:
            self._calculate_rates(now)
            self._last_stats_time = now

        self._status.last_update = now

    def _detect_mode(self) -> GadgetMode:
        """Detect current gadget mode from configfs."""
        if not GADGET_PATH.exists():
            return GadgetMode.NONE

        functions_path = GADGET_PATH / "configs" / "c.1"
        if not functions_path.exists():
            return GadgetMode.NONE

        # Check which functions are active
        has_ecm = (functions_path / "ecm.usb0").exists() or \
                  (functions_path / "eem.usb0").exists() or \
                  (functions_path / "rndis.usb0").exists()
        has_acm = (functions_path / "acm.usb0").exists() or \
                  (functions_path / "acm.GS0").exists()
        has_storage = (functions_path / "mass_storage.usb0").exists()

        if has_ecm and has_acm and has_storage:
            return GadgetMode.COMPOSITE
        elif has_ecm and has_acm:
            return GadgetMode.COMPOSITE
        elif has_ecm:
            return GadgetMode.ECM
        elif has_acm:
            return GadgetMode.ACM
        elif has_storage:
            return GadgetMode.MASS_STORAGE

        return GadgetMode.NONE

    def _update_ecm_status(self):
        """Update ECM (Ethernet) status."""
        iface = self._status.ecm_interface

        # Check if interface exists
        if not Path(f"/sys/class/net/{iface}").exists():
            self._status.connection = ConnectionState.DISCONNECTED
            return

        # Check carrier (cable connected)
        try:
            carrier_path = Path(f"/sys/class/net/{iface}/carrier")
            if carrier_path.exists():
                carrier = carrier_path.read_text().strip()
                if carrier == "1":
                    self._status.connection = ConnectionState.CONNECTED
                else:
                    self._status.connection = ConnectionState.DISCONNECTED
        except Exception:
            pass

        # Get stats
        try:
            stats_path = Path(f"/sys/class/net/{iface}/statistics")
            if stats_path.exists():
                rx_bytes = int((stats_path / "rx_bytes").read_text().strip())
                tx_bytes = int((stats_path / "tx_bytes").read_text().strip())
                rx_packets = int((stats_path / "rx_packets").read_text().strip())
                tx_packets = int((stats_path / "tx_packets").read_text().strip())

                self._status.ecm_rx_bytes = rx_bytes
                self._status.ecm_tx_bytes = tx_bytes
                self._status.ecm_rx_packets = rx_packets
                self._status.ecm_tx_packets = tx_packets
        except Exception:
            pass

        # Try to get host IP from ARP table
        try:
            result = subprocess.run(
                ['arp', '-n', '-i', iface],
                capture_output=True, text=True, timeout=1
            )
            for line in result.stdout.split('\n'):
                if HOST_IP in line or '10.55.0.' in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        self._status.host_ip = parts[0]
                        break
        except Exception:
            pass

    def _update_acm_status(self):
        """Update ACM (Serial) status."""
        tty_path = Path(self._status.acm_device)

        # Check if device exists
        if not tty_path.exists():
            self._status.acm_active = False
            return

        # Check if being used (has process attached)
        try:
            result = subprocess.run(
                ['fuser', str(tty_path)],
                capture_output=True, timeout=1
            )
            self._status.acm_active = result.returncode == 0
        except Exception:
            # Check via /proc
            self._status.acm_active = Path("/dev/ttyGS0").exists()

    def _update_storage_status(self):
        """Update mass storage status."""
        # Find storage backing file
        lun_path = GADGET_PATH / "functions" / "mass_storage.usb0" / "lun.0" / "file"

        if lun_path.exists():
            try:
                backing_file = lun_path.read_text().strip()
                if backing_file:
                    self._status.storage_partition = backing_file

                    # Get size
                    if Path(backing_file).exists():
                        size = os.path.getsize(backing_file)
                        self._status.storage_size_mb = size // (1024 * 1024)
                        self._status.storage_mounted = True
            except Exception:
                pass

    def _calculate_rates(self, now: float):
        """Calculate transfer rates."""
        if self._last_stats_time == 0:
            self._status.last_rx_bytes = self._status.ecm_rx_bytes
            self._status.last_tx_bytes = self._status.ecm_tx_bytes
            return

        elapsed = now - self._last_stats_time
        if elapsed <= 0:
            return

        rx_diff = self._status.ecm_rx_bytes - self._status.last_rx_bytes
        tx_diff = self._status.ecm_tx_bytes - self._status.last_tx_bytes

        self._status.rx_rate_kbps = (rx_diff / 1024) / elapsed
        self._status.tx_rate_kbps = (tx_diff / 1024) / elapsed

        # Mark as transferring if active
        if rx_diff > 100 or tx_diff > 100:
            self._status.connection = ConnectionState.TRANSFERRING

        self._status.last_rx_bytes = self._status.ecm_rx_bytes
        self._status.last_tx_bytes = self._status.ecm_tx_bytes

    def set_mode(self, mode: GadgetMode) -> bool:
        """Set gadget mode (requires root)."""
        try:
            if mode == GadgetMode.NONE:
                return self._disable_gadget()
            else:
                return self._configure_gadget(mode)
        except Exception as e:
            print(f"Failed to set mode: {e}")
            return False

    def _disable_gadget(self) -> bool:
        """Disable USB gadget."""
        try:
            # Unbind UDC
            udc_path = GADGET_PATH / "UDC"
            if udc_path.exists():
                udc_path.write_text("")
            return True
        except Exception:
            return False

    def _configure_gadget(self, mode: GadgetMode) -> bool:
        """Configure gadget for specified mode."""
        # This would normally call the gadget setup script
        try:
            script = "/usr/lib/secubox/eye-gadget-setup.sh"
            if Path(script).exists():
                result = subprocess.run(
                    [script, mode.value],
                    capture_output=True, timeout=10
                )
                return result.returncode == 0
        except Exception:
            pass
        return False

    def get_mode_info(self) -> Dict[str, Any]:
        """Get mode information for display."""
        mode = self._status.mode

        mode_info = {
            GadgetMode.NONE: {
                'icon': '⚫',
                'name': 'Disabled',
                'color': (80, 80, 80),
                'description': 'USB gadget not active',
            },
            GadgetMode.ECM: {
                'icon': '🌐',
                'name': 'Network',
                'color': (0, 180, 255),
                'description': 'CDC Ethernet (ECM)',
            },
            GadgetMode.ACM: {
                'icon': '📟',
                'name': 'Serial',
                'color': (255, 200, 0),
                'description': 'Serial Console (ACM)',
            },
            GadgetMode.MASS_STORAGE: {
                'icon': '💾',
                'name': 'Storage',
                'color': (0, 255, 120),
                'description': 'USB Mass Storage',
            },
            GadgetMode.COMPOSITE: {
                'icon': '🔗',
                'name': 'Composite',
                'color': (200, 100, 255),
                'description': 'ECM + ACM + Storage',
            },
        }

        return mode_info.get(mode, mode_info[GadgetMode.NONE])


# Singleton instance
_controller: Optional[GadgetController] = None


def get_controller() -> GadgetController:
    """Get singleton GadgetController instance."""
    global _controller
    if _controller is None:
        _controller = GadgetController()
    return _controller


def get_gadget_status() -> GadgetStatus:
    """Convenience function to get gadget status."""
    return get_controller().get_status()


def get_gadget_mode_info() -> Dict[str, Any]:
    """Convenience function to get mode info."""
    return get_controller().get_mode_info()
