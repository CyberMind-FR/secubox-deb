"""
SecuBox Eye Remote — Device Registry
Manages paired Eye Remote devices.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Optional

from models.device import PairedDevice, TransportType

log = logging.getLogger(__name__)

DEFAULT_STORAGE_PATH = Path("/var/lib/secubox/eye-remote/devices.json")


class DeviceRegistry:
    """
    Registry for paired Eye Remote devices.

    Stores device info in a JSON file.
    Thread-safe for concurrent access.
    """

    def __init__(self, storage_path: Path = DEFAULT_STORAGE_PATH):
        self.storage_path = storage_path
        self._devices: dict[str, PairedDevice] = {}
        self._lock = Lock()
        self._load()

    def _load(self):
        """Load devices from storage file."""
        if not self.storage_path.exists():
            return

        try:
            with open(self.storage_path) as f:
                data = json.load(f)

            for device_id, device_data in data.items():
                self._devices[device_id] = PairedDevice(**device_data)

            log.info("Loaded %d devices from registry", len(self._devices))
        except Exception as e:
            log.error("Failed to load device registry: %s", e)

    def _save(self):
        """Save devices to storage file."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            device_id: device.dict()
            for device_id, device in self._devices.items()
        }

        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    def add_device(self, device: PairedDevice):
        """Add or update a device in the registry."""
        with self._lock:
            self._devices[device.device_id] = device
            self._save()
            log.info("Added device: %s", device.device_id)

    def get_device(self, device_id: str) -> Optional[PairedDevice]:
        """Get a device by ID."""
        with self._lock:
            return self._devices.get(device_id)

    def remove_device(self, device_id: str) -> bool:
        """Remove a device from the registry."""
        with self._lock:
            if device_id in self._devices:
                del self._devices[device_id]
                self._save()
                log.info("Removed device: %s", device_id)
                return True
            return False

    def list_devices(self) -> list[PairedDevice]:
        """List all paired devices."""
        with self._lock:
            return list(self._devices.values())

    def update_last_seen(self, device_id: str, transport: str = "none"):
        """Update a device's last_seen timestamp."""
        with self._lock:
            device = self._devices.get(device_id)
            if device:
                device.last_seen = datetime.now(timezone.utc)
                device.transport = TransportType(transport)
                self._save()

    def validate_token(self, device_id: str, token_hash: str) -> bool:
        """Validate a device token."""
        with self._lock:
            device = self._devices.get(device_id)
            if device and device.token_hash == token_hash:
                return True
            return False


# Singleton instance
_registry: Optional[DeviceRegistry] = None


def get_device_registry() -> DeviceRegistry:
    """Get the global device registry instance."""
    global _registry
    if _registry is None:
        _registry = DeviceRegistry()
    return _registry
