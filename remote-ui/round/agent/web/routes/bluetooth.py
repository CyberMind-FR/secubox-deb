"""
SecuBox Eye Remote — Bluetooth API Routes
Endpoints for Bluetooth configuration and status.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

log = logging.getLogger(__name__)

router = APIRouter()


class BluetoothDevice(BaseModel):
    """Bluetooth device information."""
    address: str
    name: Optional[str] = None
    paired: bool = False
    connected: bool = False
    device_type: str = "unknown"


class BluetoothStatus(BaseModel):
    """Bluetooth adapter status."""
    enabled: bool
    discoverable: bool = False
    pairable: bool = False
    adapter_name: Optional[str] = None


class BluetoothDevicesResponse(BaseModel):
    """Response for device list."""
    devices: List[BluetoothDevice]
    scanning: bool = False


class BluetoothPairRequest(BaseModel):
    """Request to pair with a Bluetooth device."""
    address: str


class BluetoothPairResponse(BaseModel):
    """Response for Bluetooth pairing attempt."""
    success: bool
    message: str


@router.get("/status", response_model=BluetoothStatus)
async def get_bluetooth_status(request: Request) -> BluetoothStatus:
    """
    Get Bluetooth adapter status.

    Returns:
        Bluetooth adapter status
    """
    try:
        bluetooth_manager = request.app.state.bluetooth_manager
        status = await bluetooth_manager.status()
        return BluetoothStatus(
            enabled=status.powered,
            discoverable=status.discovering,
            pairable=status.pairable,
            adapter_name=status.adapter_name,
        )
    except Exception as e:
        log.error(f"Bluetooth status check failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to get Bluetooth status")


@router.get("/devices", response_model=BluetoothDevicesResponse)
async def get_bluetooth_devices(request: Request) -> BluetoothDevicesResponse:
    """
    Get list of known Bluetooth devices.

    Returns:
        List of paired and discovered devices
    """
    try:
        bluetooth_manager = request.app.state.bluetooth_manager
        devices = await bluetooth_manager.list_devices()
        return BluetoothDevicesResponse(
            devices=[
                BluetoothDevice(
                    address=d.address,
                    name=d.name,
                    paired=d.paired,
                    connected=d.connected,
                    device_type="unknown",
                )
                for d in devices
            ],
            scanning=False,
        )
    except Exception as e:
        log.error(f"Bluetooth list devices failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to list Bluetooth devices")


@router.post("/scan", response_model=BluetoothDevicesResponse)
async def scan_bluetooth_devices(request: Request) -> BluetoothDevicesResponse:
    """
    Trigger Bluetooth device scan.

    Returns:
        Scan status and any currently known devices
    """
    try:
        bluetooth_manager = request.app.state.bluetooth_manager
        devices = await bluetooth_manager.scan()
        return BluetoothDevicesResponse(
            devices=[
                BluetoothDevice(
                    address=d.address,
                    name=d.name,
                    paired=d.paired,
                    connected=d.connected,
                    device_type="unknown",
                )
                for d in devices
            ],
            scanning=False,
        )
    except Exception as e:
        log.error(f"Bluetooth scan failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to scan Bluetooth devices")


@router.post("/enable")
async def enable_bluetooth(request: Request) -> dict:
    """
    Enable Bluetooth adapter.

    Returns:
        Operation result
    """
    try:
        bluetooth_manager = request.app.state.bluetooth_manager
        log.info("Bluetooth enable request")
        success = await bluetooth_manager.enable()
        if success:
            return {"success": True, "message": "Bluetooth enabled"}
        else:
            return {"success": False, "message": "Failed to enable Bluetooth"}
    except Exception as e:
        log.error(f"Bluetooth enable failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to enable Bluetooth")


@router.post("/disable")
async def disable_bluetooth(request: Request) -> dict:
    """
    Disable Bluetooth adapter.

    Returns:
        Operation result
    """
    try:
        bluetooth_manager = request.app.state.bluetooth_manager
        log.info("Bluetooth disable request")
        success = await bluetooth_manager.disable()
        if success:
            return {"success": True, "message": "Bluetooth disabled"}
        else:
            return {"success": False, "message": "Failed to disable Bluetooth"}
    except Exception as e:
        log.error(f"Bluetooth disable failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to disable Bluetooth")


@router.post("/pair", response_model=BluetoothPairResponse)
async def pair_bluetooth_device(
    request: Request, body: BluetoothPairRequest
) -> BluetoothPairResponse:
    """
    Pair with a Bluetooth device.

    Args:
        body: Pair request with device address

    Returns:
        Pairing result
    """
    try:
        bluetooth_manager = request.app.state.bluetooth_manager
        log.info(f"Bluetooth pair request for address: {body.address}")
        success = await bluetooth_manager.pair(body.address)
        if success:
            return BluetoothPairResponse(
                success=True,
                message=f"Paired with {body.address}",
            )
        else:
            return BluetoothPairResponse(
                success=False,
                message=f"Failed to pair with {body.address}",
            )
    except Exception as e:
        log.error(f"Bluetooth pair failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to pair Bluetooth device")


@router.post("/forget", response_model=BluetoothPairResponse)
async def forget_bluetooth_device(
    request: Request, body: BluetoothPairRequest
) -> BluetoothPairResponse:
    """
    Forget (unpair) a Bluetooth device.

    Args:
        body: Request with device address to forget

    Returns:
        Operation result
    """
    try:
        bluetooth_manager = request.app.state.bluetooth_manager
        log.info(f"Bluetooth forget request for address: {body.address}")
        success = await bluetooth_manager.forget(body.address)
        if success:
            return BluetoothPairResponse(
                success=True,
                message=f"Forgot device {body.address}",
            )
        else:
            return BluetoothPairResponse(
                success=False,
                message=f"Failed to forget device {body.address}",
            )
    except Exception as e:
        log.error(f"Bluetooth forget failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to forget Bluetooth device")
