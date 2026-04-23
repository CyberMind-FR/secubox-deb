"""
SecuBox Eye Remote — Device Manager
Manages connections to multiple SecuBox appliances.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Callable

from config import Config, SecuBoxConfig, get_active_secubox, set_active_secubox
from secubox_client import SecuBoxClient

log = logging.getLogger(__name__)


@dataclass
class DeviceManager:
    """
    Manages connections to multiple SecuBox appliances.

    Handles:
    - Connecting to the active SecuBox
    - Switching between SecuBoxes
    - Polling metrics
    - Notifying listeners of metric updates
    """
    config: Config

    _client: Optional[SecuBoxClient] = field(default=None, repr=False)
    _active_config: Optional[SecuBoxConfig] = field(default=None, repr=False)
    _listeners: list[Callable] = field(default_factory=list, repr=False)
    _last_metrics: dict = field(default_factory=dict, repr=False)

    def __post_init__(self):
        self._active_config = get_active_secubox(self.config)

    @property
    def active_secubox(self) -> Optional[SecuBoxConfig]:
        """Return the active SecuBox configuration."""
        return self._active_config

    @property
    def transport(self) -> str:
        """Return current transport type."""
        if self._client:
            return self._client.transport
        return "sim"

    def list_secuboxes(self) -> list[dict]:
        """
        List all configured SecuBoxes.

        Returns:
            List of dicts with name, host, active status
        """
        return [
            {
                "name": sb.name,
                "host": sb.host,
                "active": sb.active,
            }
            for sb in self.config.secuboxes
        ]

    async def connect(self):
        """
        Connect to the active SecuBox.

        Creates HTTP client and verifies connectivity.
        """
        if not self._active_config:
            log.warning("No active SecuBox configured")
            return

        # Close existing client
        if self._client:
            await self._client.close()

        # Create new client
        self._client = SecuBoxClient(
            host=self._active_config.host,
            token=self._active_config.token,
            fallback=self._active_config.fallback,
        )

        # Check health
        healthy = await self._client.check_health()
        if healthy:
            log.info("Connected to %s via %s",
                     self._active_config.name, self._client.transport)
        else:
            log.warning("SecuBox %s not reachable", self._active_config.name)

    async def switch_to(self, name: str) -> bool:
        """
        Switch to a different SecuBox.

        Args:
            name: Name of SecuBox to switch to

        Returns:
            True if switch successful
        """
        # Find the target
        target = None
        for sb in self.config.secuboxes:
            if sb.name == name:
                target = sb
                break

        if not target:
            log.error("SecuBox '%s' not found", name)
            return False

        # Update active status
        set_active_secubox(self.config, name)
        self._active_config = target

        # Reconnect
        await self.connect()

        log.info("Switched to %s", name)
        return True

    async def poll_metrics(self) -> dict:
        """
        Poll metrics from the active SecuBox.

        Returns:
            Dict with metrics or empty dict on failure
        """
        if not self._client:
            return {}

        try:
            metrics = await self._client.fetch_metrics()
            self._last_metrics = metrics

            # Notify listeners
            if self._active_config:
                for listener in self._listeners:
                    try:
                        listener(metrics, self._active_config.name, self._client.transport)
                    except Exception as e:
                        log.warning("Listener error: %s", e)

            return metrics
        except Exception as e:
            log.warning("Failed to poll metrics: %s", e)
            return self._last_metrics or {}

    def add_listener(self, callback: Callable[[dict, str, str], None]):
        """
        Add a metrics update listener.

        Args:
            callback: Function(metrics, secubox_name, transport)
        """
        self._listeners.append(callback)

    async def close(self):
        """Close all connections."""
        if self._client:
            await self._client.close()
            self._client = None
