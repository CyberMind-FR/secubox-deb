# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Eye Remote - SecuBox Device Management
Provides DeviceManager and FleetAggregator for multi-device support.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger(__name__)


@dataclass
class SecuBoxDevice:
    """Represents a SecuBox device."""
    id: str
    name: str
    host: str
    port: int = 8000
    token: Optional[str] = None
    online: bool = False
    metrics: Dict[str, Any] = field(default_factory=dict)
    last_seen: float = 0


class DeviceManager:
    """
    Manages connections to SecuBox devices.
    Handles discovery, connection, and metrics polling.
    """

    def __init__(self, config: Any = None):
        self.config = config
        self._devices: Dict[str, SecuBoxDevice] = {}
        self._active_device: Optional[str] = None
        self._listeners: List[Callable] = []

    def add_listener(self, callback: Callable) -> None:
        """Add metrics update listener."""
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable) -> None:
        """Remove metrics update listener."""
        if callback in self._listeners:
            self._listeners.remove(callback)

    def _notify_listeners(self, metrics: dict, device_name: str, transport: str) -> None:
        """Notify all listeners of metrics update."""
        for listener in self._listeners:
            try:
                listener(metrics, device_name, transport)
            except Exception as e:
                log.error(f"Listener error: {e}")

    @property
    def active_device(self) -> Optional[SecuBoxDevice]:
        """Get currently active device."""
        if self._active_device and self._active_device in self._devices:
            return self._devices[self._active_device]
        return None

    @property
    def devices(self) -> List[SecuBoxDevice]:
        """Get all registered devices."""
        return list(self._devices.values())

    async def discover(self) -> List[SecuBoxDevice]:
        """Discover SecuBox devices on network."""
        log.info("Discovering SecuBox devices...")
        # Would use mDNS/DNS-SD in production
        return []

    async def connect(self, device_id: str) -> bool:
        """Connect to a specific device."""
        log.info(f"Connecting to device: {device_id}")
        if device_id in self._devices:
            self._active_device = device_id
            return True
        return False

    async def disconnect(self) -> None:
        """Disconnect from current device."""
        self._active_device = None

    def register_device(self, device: SecuBoxDevice) -> None:
        """Register a device."""
        self._devices[device.id] = device

    def unregister_device(self, device_id: str) -> None:
        """Unregister a device."""
        if device_id in self._devices:
            del self._devices[device_id]


class FleetAggregator:
    """
    Aggregates metrics from multiple SecuBox devices.
    Used in gateway mode for fleet overview.
    """

    def __init__(self, device_manager: DeviceManager):
        self._device_manager = device_manager
        self._device_metrics: Dict[str, Dict[str, Any]] = {}
        self._running = False
        self._poll_task: Optional[asyncio.Task] = None
        self._listeners: List[Callable] = []

    def add_listener(self, callback: Callable) -> None:
        """Add fleet update listener."""
        self._listeners.append(callback)

    @property
    def device_count(self) -> int:
        """Get number of devices in fleet."""
        return len(self._device_metrics)

    @property
    def online_count(self) -> int:
        """Get number of online devices."""
        return sum(1 for m in self._device_metrics.values() if m.get('online', False))

    def get_aggregated_metrics(self) -> Dict[str, Any]:
        """Get aggregated fleet metrics."""
        if not self._device_metrics:
            return {}

        # Average metrics across fleet
        total_cpu = 0
        total_mem = 0
        total_disk = 0
        count = 0

        for device_id, metrics in self._device_metrics.items():
            if metrics.get('online'):
                total_cpu += metrics.get('cpu_percent', 0)
                total_mem += metrics.get('mem_percent', 0)
                total_disk += metrics.get('disk_percent', 0)
                count += 1

        if count == 0:
            return {}

        return {
            'fleet_cpu_avg': total_cpu / count,
            'fleet_mem_avg': total_mem / count,
            'fleet_disk_avg': total_disk / count,
            'fleet_device_count': len(self._device_metrics),
            'fleet_online_count': count,
        }

    async def start(self) -> None:
        """Start fleet aggregation."""
        log.info("Starting fleet aggregator")
        self._running = True
        self._poll_task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        """Stop fleet aggregation."""
        log.info("Stopping fleet aggregator")
        self._running = False
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass

    async def _poll_loop(self) -> None:
        """Main polling loop for fleet metrics."""
        while self._running:
            try:
                for device in self._device_manager.devices:
                    # Would poll each device in production
                    pass
                await asyncio.sleep(5)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Fleet poll error: {e}")
                await asyncio.sleep(10)
