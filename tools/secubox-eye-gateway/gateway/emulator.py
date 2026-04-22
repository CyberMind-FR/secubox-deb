"""
SecuBox Eye Gateway — SecuBox device emulator.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""

from typing import Dict, Any
import time
import uuid

from .profiles import EmulatedMetrics, PROFILES


class SecuBoxEmulator:
    """Emulates a SecuBox device for development and testing."""

    def __init__(self, name: str = "secubox-dev", profile: str = "normal") -> None:
        """Initialize the emulator.

        Args:
            name: Device name for identification
            profile: Emulation profile (idle, normal, busy, stressed)
        """
        if profile not in PROFILES:
            raise ValueError(f"Unknown profile '{profile}'. Valid profiles: {list(PROFILES.keys())}")

        self.name = name
        self.profile = profile
        self.device_id = str(uuid.uuid4())[:8]
        self.start_time = time.time()
        self._metrics = EmulatedMetrics(profile=profile)

    def get_metrics(self) -> Dict[str, Any]:
        """Get current system metrics with realistic drift.

        Returns:
            Dictionary containing all system metrics
        """
        self._metrics.update()
        metrics = self._metrics.to_dict()
        uptime_secs = int(time.time() - self.start_time)
        metrics.update({
            "device_name": self.name,
            "device_id": self.device_id,
            "hostname": self.name,
            "uptime": uptime_secs,
            "uptime_seconds": uptime_secs,
            "emulated": True,
        })
        return metrics

    def get_health(self) -> Dict[str, Any]:
        """Get device health status.

        Returns:
            Health check response
        """
        return {
            "status": "ok",
            "emulated": True,
            "device_name": self.name,
            "device_id": self.device_id,
            "profile": self.profile,
            "uptime": int(time.time() - self.start_time),
        }

    def get_discovery_info(self) -> Dict[str, Any]:
        """Get device discovery information.

        Returns:
            Device information for discovery responses
        """
        return {
            "name": self.name,
            "device_id": self.device_id,
            "type": "secubox",
            "version": "2.0.0-emulated",
            "profile": self.profile,
            "emulated": True,
            "features": [
                "metrics",
                "alerts",
                "logs",
                "firewall",
                "services",
            ],
            "api_version": "v1",
        }
