"""
SecuBox Eye Remote — SecuBox Fleet Device Manager
Manages connections to multiple SecuBox appliances in a fleet.

Handles device discovery, registration, and connection state tracking
for Eye Remote dashboard and gateway modes.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Any

log = logging.getLogger(__name__)


class ConnectionState(Enum):
    """Connection state for a SecuBox device."""
    UNKNOWN = "unknown"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


@dataclass
class SecuBoxDevice:
    """
    Represents a SecuBox device in the fleet.

    Attributes:
        id: Unique identifier for this device
        name: Human-readable name
        host: IP address or hostname
        port: API port (default 8000)
        transport: Connection type ("http", "otg", "wifi")
        active: Whether device is enabled
        state: Current connection state
        last_seen: Unix timestamp of last successful contact
        metrics: Cached metrics from last poll
    """
    id: str
    name: str
    host: str
    port: int = 8000
    transport: str = "http"
    active: bool = True
    state: ConnectionState = ConnectionState.UNKNOWN
    last_seen: Optional[float] = None
    metrics: dict = field(default_factory=dict)


class DeviceManager:
    """
    Manages SecuBox device fleet.

    Thread-safe device management with async operations for:
    - Adding/removing devices
    - Tracking connection states
    - Setting primary device for dashboard mode
    - Network discovery (stub for actual nmap/mdns implementation)
    - Loading/saving device configuration

    Attributes:
        _devices: Dictionary of device_id -> SecuBoxDevice
        _primary_id: ID of the primary device for dashboard mode
        _config: Optional configuration object for persistence
        _lock: Asyncio lock for thread-safe operations
    """

    def __init__(self, config: Any = None):
        """
        Initialize the device manager.

        Args:
            config: Optional configuration object for loading/saving devices
        """
        self._devices: dict[str, SecuBoxDevice] = {}
        self._primary_id: Optional[str] = None
        self._config = config
        self._lock = asyncio.Lock()

        log.debug("DeviceManager initialized")

    def _generate_device_id(self, host: str, port: int) -> str:
        """
        Generate a unique device ID.

        Uses UUID4 to ensure uniqueness even for duplicate host:port.

        Args:
            host: Device host
            port: Device port

        Returns:
            Unique device ID string
        """
        return str(uuid.uuid4())[:8]

    def _generate_device_name(self, host: str) -> str:
        """
        Generate a default device name from host.

        Args:
            host: Device host

        Returns:
            Default device name
        """
        return f"SecuBox@{host}"

    async def load_from_config(self) -> None:
        """
        Load devices from configuration file.

        Reads device definitions from the config object and
        populates the device list. Sets primary if configured.
        """
        if self._config is None:
            log.debug("No config provided, skipping load")
            return

        async with self._lock:
            try:
                secuboxes = getattr(self._config, 'secuboxes', None)
                if secuboxes is None:
                    log.debug("No secuboxes section in config")
                    return

                devices = getattr(secuboxes, 'devices', [])
                primary_name = getattr(secuboxes, 'primary', None)

                for device_cfg in devices:
                    device_id = getattr(device_cfg, 'id', None) or \
                        self._generate_device_id(device_cfg.host, device_cfg.port)

                    device = SecuBoxDevice(
                        id=device_id,
                        name=getattr(device_cfg, 'name', self._generate_device_name(device_cfg.host)),
                        host=device_cfg.host,
                        port=getattr(device_cfg, 'port', 8000),
                        active=getattr(device_cfg, 'active', True),
                        state=ConnectionState.UNKNOWN,
                    )
                    self._devices[device.id] = device

                    # Set primary by name match
                    if primary_name and device.name == primary_name:
                        self._primary_id = device.id

                    log.info("Loaded device: %s (%s)", device.name, device.host)

            except Exception as e:
                log.error("Failed to load devices from config: %s", e)

    async def add_device(
        self,
        host: str,
        port: int = 8000,
        name: Optional[str] = None
    ) -> SecuBoxDevice:
        """
        Add a new device to the fleet.

        Args:
            host: IP address or hostname
            port: API port (default 8000)
            name: Optional display name

        Returns:
            The newly created SecuBoxDevice
        """
        async with self._lock:
            device_id = self._generate_device_id(host, port)
            device_name = name if name else self._generate_device_name(host)

            device = SecuBoxDevice(
                id=device_id,
                name=device_name,
                host=host,
                port=port,
                active=True,
                state=ConnectionState.UNKNOWN,
            )

            self._devices[device_id] = device

            log.info("Added device: %s (%s:%d)", device_name, host, port)

            # Persist to config if available
            if self._config is not None:
                await self._persist_to_config()

            return device

    async def remove_device(self, device_id: str) -> bool:
        """
        Remove a device from the fleet.

        Args:
            device_id: ID of the device to remove

        Returns:
            True if device was removed, False if not found
        """
        async with self._lock:
            if device_id not in self._devices:
                log.warning("Cannot remove device %s: not found", device_id)
                return False

            device = self._devices.pop(device_id)

            # Clear primary if this was the primary device
            if self._primary_id == device_id:
                self._primary_id = None
                log.info("Primary device cleared")

            log.info("Removed device: %s (%s)", device.name, device.host)

            # Persist to config if available
            if self._config is not None:
                await self._persist_to_config()

            return True

    async def get_device(self, device_id: str) -> Optional[SecuBoxDevice]:
        """
        Get device by ID.

        Args:
            device_id: ID of the device to retrieve

        Returns:
            SecuBoxDevice if found, None otherwise
        """
        async with self._lock:
            return self._devices.get(device_id)

    async def list_devices(self) -> List[SecuBoxDevice]:
        """
        List all devices in the fleet.

        Returns:
            List of all SecuBoxDevice objects
        """
        async with self._lock:
            return list(self._devices.values())

    async def set_primary(self, device_id: str) -> bool:
        """
        Set the primary device for dashboard mode.

        The primary device is used as the main data source
        for single-device dashboard display.

        Args:
            device_id: ID of the device to set as primary

        Returns:
            True if successful, False if device not found
        """
        async with self._lock:
            if device_id not in self._devices:
                log.warning("Cannot set primary: device %s not found", device_id)
                return False

            self._primary_id = device_id
            device = self._devices[device_id]

            log.info("Set primary device: %s (%s)", device.name, device.host)

            return True

    @property
    def primary_device(self) -> Optional[SecuBoxDevice]:
        """
        Get the primary device.

        Returns:
            Primary SecuBoxDevice if set, None otherwise
        """
        if self._primary_id is None:
            return None
        return self._devices.get(self._primary_id)

    async def update_device_state(
        self,
        device_id: str,
        state: ConnectionState
    ) -> None:
        """
        Update connection state of a device.

        Also updates last_seen timestamp when state changes.

        Args:
            device_id: ID of the device to update
            state: New connection state
        """
        async with self._lock:
            device = self._devices.get(device_id)
            if device is None:
                log.warning("Cannot update state: device %s not found", device_id)
                return

            old_state = device.state
            device.state = state
            device.last_seen = time.time()

            if old_state != state:
                log.info(
                    "Device %s state: %s -> %s",
                    device.name,
                    old_state.value,
                    state.value
                )

    async def scan_network(
        self,
        network: str = "192.168.1.0/24"
    ) -> List[SecuBoxDevice]:
        """
        Scan network for SecuBox devices.

        This is a stub implementation. Actual implementation would use
        nmap for port scanning or mDNS for service discovery.

        Args:
            network: CIDR network range to scan (e.g., "192.168.1.0/24")

        Returns:
            List of discovered SecuBoxDevice objects (empty in stub)
        """
        log.info("Network scan requested for %s (stub implementation)", network)

        # Stub: In real implementation, this would:
        # 1. Parse network CIDR
        # 2. Scan for hosts with port 8000 open (nmap)
        # 3. Or query mDNS for _secubox._tcp services
        # 4. Verify each host responds to /api/v1/health
        # 5. Return list of discovered devices

        return []

    async def _persist_to_config(self) -> None:
        """
        Persist current devices to configuration.

        Internal method called after add/remove operations.
        """
        # Stub: In real implementation, this would update
        # the config object and save to disk
        log.debug("Config persistence requested (stub)")

    async def close(self) -> None:
        """
        Clean up resources.

        Call this when shutting down the device manager.
        """
        log.info("DeviceManager closing, %d devices", len(self._devices))
        async with self._lock:
            self._devices.clear()
            self._primary_id = None
