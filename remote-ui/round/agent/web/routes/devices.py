"""
SecuBox Eye Remote — Devices API Routes
Endpoints for SecuBox device management (fleet/gateway mode).

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel

log = logging.getLogger(__name__)

router = APIRouter()


class DeviceInfo(BaseModel):
    """SecuBox device information."""
    id: str
    name: str
    host: str
    port: int = 8000
    transport: str = "otg"
    active: bool = False
    connected: bool = False
    last_seen: Optional[str] = None


class DevicesResponse(BaseModel):
    """Response for device list."""
    devices: List[DeviceInfo]
    primary: Optional[str] = None


class ScanResponse(BaseModel):
    """Response for device scan."""
    status: str
    message: str
    devices_found: int = 0


class DeviceSelectRequest(BaseModel):
    """Request to select a device."""
    device_id: str


class DeviceSelectResponse(BaseModel):
    """Response for device selection."""
    success: bool
    message: str
    active_device: Optional[str] = None


@router.get("", response_model=DevicesResponse)
async def list_devices(request: Request) -> DevicesResponse:
    """
    Get list of known SecuBox devices.

    Returns:
        List of configured SecuBox devices
    """
    config = request.app.state.config

    devices = []
    primary = None

    if config and hasattr(config, 'secuboxes'):
        primary = config.secuboxes.primary
        for sb in config.secuboxes.devices:
            devices.append(DeviceInfo(
                id=sb.id or sb.name,
                name=sb.name,
                host=sb.host,
                port=sb.port,
                transport=sb.transport,
                active=sb.active,
                connected=False,  # TODO: Check actual connection
            ))

    return DevicesResponse(
        devices=devices,
        primary=primary,
    )


@router.post("/scan", response_model=ScanResponse)
async def scan_devices(request: Request) -> ScanResponse:
    """
    Scan for SecuBox devices on the network.

    Returns:
        Scan status
    """
    # TODO: Implement actual network scan for SecuBox devices
    log.info("Device scan requested")
    return ScanResponse(
        status="scanning",
        message="Device scan initiated",
        devices_found=0,
    )


@router.post("/select", response_model=DeviceSelectResponse)
async def select_device(request: Request, body: DeviceSelectRequest) -> DeviceSelectResponse:
    """
    Select a SecuBox device as active.

    Args:
        body: Device selection request

    Returns:
        Selection result
    """
    config = request.app.state.config

    if config is None:
        return DeviceSelectResponse(
            success=False,
            message="Configuration unavailable",
        )

    # TODO: Implement actual device selection
    log.info(f"Device selection requested: {body.device_id}")
    return DeviceSelectResponse(
        success=False,
        message="Device selection not implemented",
    )


@router.get("/{device_id}")
async def get_device(request: Request, device_id: str) -> dict:
    """
    Get information about a specific device.

    Args:
        device_id: Device ID to query

    Returns:
        Device information
    """
    config = request.app.state.config

    if config and hasattr(config, 'secuboxes'):
        for sb in config.secuboxes.devices:
            if sb.id == device_id or sb.name == device_id:
                return {
                    "id": sb.id or sb.name,
                    "name": sb.name,
                    "host": sb.host,
                    "port": sb.port,
                    "transport": sb.transport,
                    "active": sb.active,
                    "connected": False,
                }

    return {"error": f"Device not found: {device_id}"}


@router.delete("/{device_id}")
async def forget_device(request: Request, device_id: str) -> dict:
    """
    Remove a device from the known devices list.

    Args:
        device_id: Device ID to forget

    Returns:
        Operation result
    """
    # TODO: Implement actual device removal
    log.info(f"Device forget requested: {device_id}")
    return {
        "success": False,
        "message": "Device removal not implemented",
    }
