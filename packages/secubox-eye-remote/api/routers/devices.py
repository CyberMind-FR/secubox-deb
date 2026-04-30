"""
SecuBox Eye Remote — Devices Router
API endpoints for managing paired Eye Remote devices.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from pydantic import BaseModel, Field

from ...core.device_registry import get_device_registry
from ...models.device import DeviceListResponse, PairedDevice

log = logging.getLogger(__name__)


class UnpairResponse(BaseModel):
    """Response after unpairing a device."""
    success: bool = Field(..., description="Whether the unpair succeeded")
    message: str = Field(..., description="Status message")

router = APIRouter(prefix="/devices", tags=["devices"])


# JWT auth dependency - import from secubox_core
try:
    from secubox_core.auth import require_jwt
except ImportError:
    # Fallback for standalone eye-remote deployment on Pi Zero
    def require_jwt():
        """Fallback JWT auth when secubox_core not available."""
        return None


@router.get("", response_model=DeviceListResponse)
async def list_devices(_: None = Depends(require_jwt)) -> DeviceListResponse:
    """
    List all paired Eye Remote devices.

    Returns:
        List of paired devices with count.
    """
    registry = get_device_registry()
    devices = registry.list_devices()

    log.debug("Listing %d paired devices", len(devices))

    return DeviceListResponse(
        devices=devices,
        count=len(devices),
    )


@router.get("/{device_id}", response_model=PairedDevice)
async def get_device(
    device_id: str,
    _: None = Depends(require_jwt),
) -> PairedDevice:
    """
    Get a specific paired device by ID.

    Args:
        device_id: The unique device identifier.

    Returns:
        The paired device details.

    Raises:
        HTTPException 404: Device not found.
    """
    registry = get_device_registry()
    device = registry.get_device(device_id)

    if device is None:
        log.warning("Device not found: %s", device_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {device_id}",
        )

    return device


@router.delete("/{device_id}", response_model=UnpairResponse)
async def unpair_device(
    device_id: str,
    _: None = Depends(require_jwt),
) -> UnpairResponse:
    """
    Unpair (remove) a device from the registry.

    Args:
        device_id: The unique device identifier.

    Returns:
        Success message.

    Raises:
        HTTPException 404: Device not found.
    """
    registry = get_device_registry()

    if not registry.remove_device(device_id):
        log.warning("Cannot unpair: device not found: %s", device_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device not found: {device_id}",
        )

    log.info("Unpaired device: %s", device_id)

    return UnpairResponse(
        success=True,
        message=f"Device {device_id} unpaired",
    )
