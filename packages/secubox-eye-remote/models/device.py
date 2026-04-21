"""
SecuBox Eye Remote — Device Models
Pydantic models for Eye Remote device management.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class TransportType(str, Enum):
    """Transport types for Eye Remote connection."""
    OTG = "otg"
    WIFI = "wifi"
    NONE = "none"


class DeviceCapability(str, Enum):
    """Capabilities an Eye Remote device can have."""
    SCREENSHOT = "screenshot"
    REBOOT = "reboot"
    OTA = "ota"
    SERIAL = "serial"


class DeviceScope(str, Enum):
    """Permission scopes for Eye Remote devices."""
    METRICS_READ = "metrics:read"
    SERVICES_RESTART = "services:restart"
    OTG_CONTROL = "otg:control"
    ALERTS_DISMISS = "alerts:dismiss"
    SYSTEM_LOCKDOWN = "system:lockdown"
    SYSTEM_REBOOT = "system:reboot"


class PairedDevice(BaseModel):
    """A paired Eye Remote device."""
    device_id: str = Field(..., description="Unique device identifier")
    name: str = Field(..., description="User-friendly device name")
    token_hash: str = Field(..., description="SHA256 hash of device token")
    paired_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: Optional[datetime] = None
    transport: TransportType = TransportType.NONE
    firmware: str = "unknown"
    capabilities: list[DeviceCapability] = Field(default_factory=list)
    scopes: list[DeviceScope] = Field(default_factory=lambda: [DeviceScope.METRICS_READ])
    ssh_pubkey: Optional[str] = None
    ssh_enabled: bool = False


class DeviceListResponse(BaseModel):
    """Response for listing devices."""
    devices: list[PairedDevice]
    count: int


class PairRequest(BaseModel):
    """Request to pair a new device."""
    device_id: str
    name: str = "Eye Remote"
    pubkey: Optional[str] = None
    capabilities: list[DeviceCapability] = Field(default_factory=list)


class PairResponse(BaseModel):
    """Response after successful pairing."""
    success: bool
    device_id: str
    token: str = Field(..., description="Device token (only returned once)")
    ssh_user: Optional[str] = None
    ssh_port: int = 22


class CommandRequest(BaseModel):
    """Request to send command to Eye Remote."""
    cmd: str = Field(..., description="Command: screenshot, reboot, config_update, ota_update")
    params: dict = Field(default_factory=dict)


class CommandResponse(BaseModel):
    """Response from command execution."""
    success: bool
    request_id: str
    data: Optional[dict] = None
    error: Optional[str] = None
