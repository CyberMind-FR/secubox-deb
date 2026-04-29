#!/usr/bin/env python3
"""
SecuBox Eye Remote - Setup Wizard API

Handles the self-setup portal for new SecuBox configuration.
Guides user through 7-step wizard on HyperPixel display.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import os
import json
import asyncio
import aiohttp
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from typing import Optional, List, Dict, Any


# API endpoints
API_BASE_OTG = "http://10.55.0.1:8000"
API_BASE_WIFI = "http://secubox.local:8000"

# Setup state file
SETUP_STATE_FILE = Path("/var/lib/secubox/eye-remote/setup_state.json")


class SetupStep(IntEnum):
    """Setup wizard steps."""
    WELCOME = 0
    NETWORK = 1
    SECURITY = 2
    SERVICES = 3
    MESH = 4
    VERIFY = 5
    COMPLETE = 6


class SetupStatus(Enum):
    """Overall setup status."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class StepStatus(Enum):
    """Individual step status."""
    PENDING = "pending"
    CURRENT = "current"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class SecuBoxInfo:
    """Information about connected SecuBox."""
    detected: bool = False
    hostname: str = ""
    model: str = ""
    version: str = ""
    ip_address: str = ""
    connection_type: str = ""  # "otg" or "wifi"
    uptime: int = 0


@dataclass
class NetworkConfig:
    """Network configuration settings."""
    wan_interface: str = "eth0"
    wan_dhcp: bool = True
    wan_ip: str = ""
    wan_netmask: str = ""
    wan_gateway: str = ""
    wan_dns: List[str] = field(default_factory=list)

    lan_interface: str = "eth1"
    lan_ip: str = "192.168.1.1"
    lan_netmask: str = "255.255.255.0"
    lan_dhcp_enabled: bool = True
    lan_dhcp_start: str = "192.168.1.100"
    lan_dhcp_end: str = "192.168.1.200"


@dataclass
class SecurityConfig:
    """Security configuration settings."""
    admin_password_set: bool = False
    tls_cert_generated: bool = False
    ssh_key_installed: bool = False
    root_login_disabled: bool = True


@dataclass
class ServicesConfig:
    """Services configuration settings."""
    crowdsec_enabled: bool = True
    wireguard_enabled: bool = True
    firewall_enabled: bool = True
    dpi_enabled: bool = False
    dns_filtering_enabled: bool = True
    ids_enabled: bool = False


@dataclass
class MeshConfig:
    """Mesh network configuration."""
    mode: str = "standalone"  # "standalone", "join", "create"
    mirrornet_enabled: bool = False
    mirrornet_peer_url: str = ""
    wireguard_peer_pubkey: str = ""


@dataclass
class StepData:
    """Data for a setup step."""
    step: SetupStep
    status: StepStatus = StepStatus.PENDING
    title: str = ""
    description: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step.value,
            "step_name": self.step.name,
            "status": self.status.value,
            "title": self.title,
            "description": self.description,
            "data": self.data,
            "errors": self.errors,
        }


@dataclass
class SetupState:
    """Complete setup wizard state."""
    status: SetupStatus = SetupStatus.NOT_STARTED
    current_step: SetupStep = SetupStep.WELCOME
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    secubox_info: SecuBoxInfo = field(default_factory=SecuBoxInfo)
    network_config: NetworkConfig = field(default_factory=NetworkConfig)
    security_config: SecurityConfig = field(default_factory=SecurityConfig)
    services_config: ServicesConfig = field(default_factory=ServicesConfig)
    mesh_config: MeshConfig = field(default_factory=MeshConfig)

    steps: Dict[int, StepData] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize step data."""
        if not self.steps:
            self.steps = {
                SetupStep.WELCOME.value: StepData(
                    step=SetupStep.WELCOME,
                    title="Welcome",
                    description="Detect and identify SecuBox",
                ),
                SetupStep.NETWORK.value: StepData(
                    step=SetupStep.NETWORK,
                    title="Network",
                    description="Configure WAN/LAN interfaces",
                ),
                SetupStep.SECURITY.value: StepData(
                    step=SetupStep.SECURITY,
                    title="Security",
                    description="Set admin password and generate TLS certificate",
                ),
                SetupStep.SERVICES.value: StepData(
                    step=SetupStep.SERVICES,
                    title="Services",
                    description="Enable security modules",
                ),
                SetupStep.MESH.value: StepData(
                    step=SetupStep.MESH,
                    title="Mesh",
                    description="Configure MirrorNet P2P mode",
                ),
                SetupStep.VERIFY.value: StepData(
                    step=SetupStep.VERIFY,
                    title="Verify",
                    description="Test connectivity and configuration",
                ),
                SetupStep.COMPLETE.value: StepData(
                    step=SetupStep.COMPLETE,
                    title="Complete",
                    description="Finalize and reboot",
                ),
            }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "current_step": self.current_step.value,
            "current_step_name": self.current_step.name,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "secubox_info": {
                "detected": self.secubox_info.detected,
                "hostname": self.secubox_info.hostname,
                "model": self.secubox_info.model,
                "version": self.secubox_info.version,
                "ip_address": self.secubox_info.ip_address,
                "connection_type": self.secubox_info.connection_type,
                "uptime": self.secubox_info.uptime,
            },
            "steps": {k: v.to_dict() for k, v in self.steps.items()},
        }


class SetupWizard:
    """Setup wizard controller."""

    TIMEOUT = 5  # seconds

    def __init__(self):
        self._state = SetupState()
        self._api_base = API_BASE_OTG
        self._load_state()

    @property
    def state(self) -> SetupState:
        return self._state

    @property
    def is_complete(self) -> bool:
        return self._state.status == SetupStatus.COMPLETED

    @property
    def current_step(self) -> SetupStep:
        return self._state.current_step

    def _load_state(self):
        """Load saved state from file."""
        if SETUP_STATE_FILE.exists():
            try:
                with open(SETUP_STATE_FILE) as f:
                    data = json.load(f)

                self._state.status = SetupStatus(data.get("status", "not_started"))
                self._state.current_step = SetupStep(data.get("current_step", 0))

                if data.get("started_at"):
                    self._state.started_at = datetime.fromisoformat(data["started_at"])
                if data.get("completed_at"):
                    self._state.completed_at = datetime.fromisoformat(data["completed_at"])

                # Restore step statuses
                for step_num, step_data in data.get("steps", {}).items():
                    if int(step_num) in self._state.steps:
                        self._state.steps[int(step_num)].status = StepStatus(
                            step_data.get("status", "pending")
                        )
                        self._state.steps[int(step_num)].data = step_data.get("data", {})

            except Exception as e:
                print(f"Error loading setup state: {e}")

    def _save_state(self):
        """Save state to file."""
        try:
            SETUP_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "status": self._state.status.value,
                "current_step": self._state.current_step.value,
                "started_at": self._state.started_at.isoformat() if self._state.started_at else None,
                "completed_at": self._state.completed_at.isoformat() if self._state.completed_at else None,
                "steps": {
                    str(k): {
                        "status": v.status.value,
                        "data": v.data,
                        "errors": v.errors,
                    }
                    for k, v in self._state.steps.items()
                },
            }

            with open(SETUP_STATE_FILE, "w") as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            print(f"Error saving setup state: {e}")

    async def _api_request(self,
                           method: str,
                           endpoint: str,
                           data: Optional[Dict] = None) -> Optional[Dict]:
        """Make API request to SecuBox."""
        url = f"{self._api_base}{endpoint}"

        try:
            timeout = aiohttp.ClientTimeout(total=self.TIMEOUT)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                if method == "GET":
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            return await resp.json()
                elif method == "POST":
                    async with session.post(url, json=data) as resp:
                        if resp.status in (200, 201):
                            return await resp.json()
        except Exception as e:
            print(f"API request failed: {e}")

        return None

    async def start(self) -> bool:
        """Start the setup wizard."""
        self._state.status = SetupStatus.IN_PROGRESS
        self._state.started_at = datetime.now()
        self._state.current_step = SetupStep.WELCOME

        # Mark welcome as current
        self._state.steps[SetupStep.WELCOME.value].status = StepStatus.CURRENT

        self._save_state()
        return True

    async def detect_secubox(self) -> SecuBoxInfo:
        """Detect connected SecuBox and gather info."""
        info = SecuBoxInfo()

        # Try OTG first
        result = await self._api_request("GET", "/api/v1/system/info")
        if result:
            info.detected = True
            info.hostname = result.get("hostname", "secubox")
            info.model = result.get("model", "Unknown")
            info.version = result.get("version", "")
            info.ip_address = "10.55.0.1"
            info.connection_type = "otg"
            info.uptime = result.get("uptime_seconds", 0)
            self._api_base = API_BASE_OTG
        else:
            # Try WiFi
            self._api_base = API_BASE_WIFI
            result = await self._api_request("GET", "/api/v1/system/info")
            if result:
                info.detected = True
                info.hostname = result.get("hostname", "secubox")
                info.model = result.get("model", "Unknown")
                info.version = result.get("version", "")
                info.ip_address = "secubox.local"
                info.connection_type = "wifi"
                info.uptime = result.get("uptime_seconds", 0)

        self._state.secubox_info = info
        self._save_state()
        return info

    async def next_step(self) -> Optional[StepData]:
        """Move to next step."""
        current = self._state.current_step

        # Mark current as completed
        self._state.steps[current.value].status = StepStatus.COMPLETED

        # Move to next
        if current.value < SetupStep.COMPLETE.value:
            next_step = SetupStep(current.value + 1)
            self._state.current_step = next_step
            self._state.steps[next_step.value].status = StepStatus.CURRENT
            self._save_state()
            return self._state.steps[next_step.value]

        return None

    async def previous_step(self) -> Optional[StepData]:
        """Move to previous step."""
        current = self._state.current_step

        if current.value > SetupStep.WELCOME.value:
            # Mark current as pending again
            self._state.steps[current.value].status = StepStatus.PENDING

            prev_step = SetupStep(current.value - 1)
            self._state.current_step = prev_step
            self._state.steps[prev_step.value].status = StepStatus.CURRENT
            self._save_state()
            return self._state.steps[prev_step.value]

        return None

    async def skip_step(self) -> Optional[StepData]:
        """Skip current step (where allowed)."""
        current = self._state.current_step

        # Steps that can be skipped
        skippable = {SetupStep.SERVICES, SetupStep.MESH}

        if current in skippable:
            self._state.steps[current.value].status = StepStatus.SKIPPED
            return await self.next_step()

        return None

    async def apply_network_config(self, config: Dict[str, Any]) -> bool:
        """Apply network configuration to SecuBox."""
        result = await self._api_request(
            "POST",
            "/api/v1/system/network/configure",
            config
        )

        if result and result.get("status") == "success":
            self._state.network_config.wan_interface = config.get("wan_interface", "eth0")
            self._state.network_config.wan_dhcp = config.get("wan_dhcp", True)
            self._state.steps[SetupStep.NETWORK.value].data = config
            self._save_state()
            return True

        return False

    async def apply_security_config(self, config: Dict[str, Any]) -> bool:
        """Apply security configuration."""
        success = True

        # Set admin password
        if config.get("admin_password"):
            result = await self._api_request(
                "POST",
                "/api/v1/auth/set-password",
                {"password": config["admin_password"]}
            )
            if result and result.get("status") == "success":
                self._state.security_config.admin_password_set = True
            else:
                success = False

        # Generate TLS certificate
        if config.get("generate_tls"):
            result = await self._api_request(
                "POST",
                "/api/v1/system/tls/generate",
                {"domain": config.get("domain", "secubox.local")}
            )
            if result and result.get("status") == "success":
                self._state.security_config.tls_cert_generated = True
            else:
                success = False

        if success:
            self._state.steps[SetupStep.SECURITY.value].data = {
                "admin_password_set": self._state.security_config.admin_password_set,
                "tls_cert_generated": self._state.security_config.tls_cert_generated,
            }
            self._save_state()

        return success

    async def apply_services_config(self, config: Dict[str, Any]) -> bool:
        """Apply services configuration."""
        result = await self._api_request(
            "POST",
            "/api/v1/system/modules/configure",
            config
        )

        if result and result.get("status") == "success":
            self._state.services_config.crowdsec_enabled = config.get("crowdsec", True)
            self._state.services_config.wireguard_enabled = config.get("wireguard", True)
            self._state.services_config.firewall_enabled = config.get("firewall", True)
            self._state.services_config.dpi_enabled = config.get("dpi", False)
            self._state.services_config.dns_filtering_enabled = config.get("dns_filtering", True)
            self._state.steps[SetupStep.SERVICES.value].data = config
            self._save_state()
            return True

        return False

    async def apply_mesh_config(self, config: Dict[str, Any]) -> bool:
        """Apply mesh network configuration."""
        self._state.mesh_config.mode = config.get("mode", "standalone")

        if self._state.mesh_config.mode != "standalone":
            result = await self._api_request(
                "POST",
                "/api/v1/mirrornet/configure",
                config
            )

            if not result or result.get("status") != "success":
                return False

        self._state.steps[SetupStep.MESH.value].data = config
        self._save_state()
        return True

    async def verify_configuration(self) -> Dict[str, Any]:
        """Verify the configuration is working."""
        results = {
            "network": False,
            "services": {},
            "api": False,
            "errors": [],
        }

        # Test API connectivity
        result = await self._api_request("GET", "/api/v1/health")
        if result and result.get("status") == "ok":
            results["api"] = True
        else:
            results["errors"].append("API connectivity failed")

        # Test network
        result = await self._api_request("GET", "/api/v1/system/network/status")
        if result and result.get("status") == "connected":
            results["network"] = True
        else:
            results["errors"].append("Network configuration failed")

        # Test services
        for service in ["crowdsec", "wireguard", "firewall"]:
            result = await self._api_request("GET", f"/api/v1/{service}/status")
            if result:
                results["services"][service] = result.get("status") == "active"
            else:
                results["services"][service] = False

        self._state.steps[SetupStep.VERIFY.value].data = results
        self._save_state()

        return results

    async def complete_setup(self, reboot: bool = False) -> bool:
        """Complete the setup wizard."""
        self._state.status = SetupStatus.COMPLETED
        self._state.completed_at = datetime.now()
        self._state.steps[SetupStep.COMPLETE.value].status = StepStatus.COMPLETED

        # Notify SecuBox that setup is complete
        await self._api_request(
            "POST",
            "/api/v1/system/setup/complete",
            {"reboot": reboot}
        )

        self._save_state()

        if reboot:
            # Request SecuBox reboot
            await self._api_request("POST", "/api/v1/system/reboot", {})

        return True

    async def cancel_setup(self) -> bool:
        """Cancel the setup wizard."""
        self._state.status = SetupStatus.NOT_STARTED
        self._state.current_step = SetupStep.WELCOME

        # Reset all steps
        for step in self._state.steps.values():
            step.status = StepStatus.PENDING
            step.data = {}
            step.errors = []

        self._save_state()
        return True

    def get_step_info(self, step: SetupStep) -> StepData:
        """Get information about a specific step."""
        return self._state.steps.get(step.value, StepData(step=step))

    def get_progress(self) -> Dict[str, Any]:
        """Get overall progress information."""
        completed = sum(
            1 for s in self._state.steps.values()
            if s.status in (StepStatus.COMPLETED, StepStatus.SKIPPED)
        )
        total = len(self._state.steps)

        return {
            "completed_steps": completed,
            "total_steps": total,
            "progress_percent": int((completed / total) * 100),
            "current_step": self._state.current_step.value,
            "current_step_name": self._state.current_step.name,
        }


# Singleton instance
_setup_wizard: Optional[SetupWizard] = None


def get_setup_wizard() -> SetupWizard:
    """Get singleton setup wizard instance."""
    global _setup_wizard
    if _setup_wizard is None:
        _setup_wizard = SetupWizard()
    return _setup_wizard
