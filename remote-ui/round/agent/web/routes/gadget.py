#!/usr/bin/env python3
"""
SecuBox Eye Remote - Gadget Control API Routes

FastAPI routes for USB gadget mode control.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from ...api.gadget import get_controller, get_gadget_status, GadgetMode
from ...api.gadget_config import get_config, reload_config, save_config, GadgetConfig
from ...api.gadget_switcher import (
    switch_mode, get_available_modes, get_current_mode,
    is_gadget_bound, SwitchResult
)


router = APIRouter(prefix="/gadget", tags=["gadget"])


# Request/Response models
class ModeChangeRequest(BaseModel):
    """Request to change gadget mode."""
    mode: str


class ModeChangeResponse(BaseModel):
    """Response from mode change."""
    success: bool
    message: str
    previous_mode: str
    current_mode: str
    duration_ms: float


class GadgetStatusResponse(BaseModel):
    """Current gadget status."""
    mode: str
    mode_name: str
    host_connected: bool
    host_ip: Optional[str]
    device_ip: str
    bound: bool
    available_modes: List[str]

    # Transfer stats (ECM mode)
    rx_rate_kbps: float = 0.0
    tx_rate_kbps: float = 0.0
    rx_bytes: int = 0
    tx_bytes: int = 0

    # ACM status
    acm_active: bool = False
    acm_device: str = ""

    # Storage status
    storage_mounted: bool = False
    storage_size_mb: int = 0


class ConfigUpdateRequest(BaseModel):
    """Request to update gadget configuration."""
    default_mode: Optional[str] = None
    auto_switch: Optional[bool] = None
    ecm_host_ip: Optional[str] = None
    ecm_device_ip: Optional[str] = None
    acm_baudrate: Optional[int] = None
    storage_partition: Optional[str] = None
    storage_readonly: Optional[bool] = None


class ConfigResponse(BaseModel):
    """Gadget configuration response."""
    default_mode: str
    auto_switch: bool
    vendor_id: str
    product_id: str
    manufacturer: str
    product: str
    serial_number: str

    ecm_host_ip: str
    ecm_device_ip: str
    ecm_netmask: str

    acm_baudrate: int
    acm_console_enabled: bool

    storage_partition: str
    storage_readonly: bool


@router.get("/status", response_model=GadgetStatusResponse)
async def get_status():
    """Get current gadget status."""
    controller = get_controller()
    status = controller.get_status()
    mode_info = controller.get_mode_info()
    config = get_config()

    return GadgetStatusResponse(
        mode=status.mode.value,
        mode_name=mode_info.get("name", status.mode.value),
        host_connected=status.connection.value != "disconnected",
        host_ip=status.host_ip or None,
        device_ip=status.device_ip,
        bound=is_gadget_bound(),
        available_modes=get_available_modes(),
        rx_rate_kbps=status.rx_rate_kbps,
        tx_rate_kbps=status.tx_rate_kbps,
        rx_bytes=status.ecm_rx_bytes,
        tx_bytes=status.ecm_tx_bytes,
        acm_active=status.acm_active,
        acm_device=status.acm_device,
        storage_mounted=status.storage_mounted,
        storage_size_mb=status.storage_size_mb,
    )


@router.post("/mode", response_model=ModeChangeResponse)
async def change_mode(request: ModeChangeRequest):
    """Change gadget mode."""
    result = switch_mode(request.mode)

    if result.result == SwitchResult.PERMISSION_DENIED:
        raise HTTPException(
            status_code=403,
            detail="Permission denied - root privileges required"
        )

    return ModeChangeResponse(
        success=result.result in (SwitchResult.SUCCESS, SwitchResult.ALREADY_ACTIVE),
        message=result.message,
        previous_mode=result.previous_mode,
        current_mode=result.current_mode,
        duration_ms=result.duration_ms,
    )


@router.get("/modes", response_model=List[str])
async def list_modes():
    """List available gadget modes."""
    return get_available_modes()


@router.get("/config", response_model=ConfigResponse)
async def get_gadget_config():
    """Get gadget configuration."""
    config = get_config()

    return ConfigResponse(
        default_mode=config.default_mode,
        auto_switch=config.auto_switch,
        vendor_id=config.vendor_id,
        product_id=config.product_id,
        manufacturer=config.manufacturer,
        product=config.product,
        serial_number=config.serial_number,
        ecm_host_ip=config.ecm.host_ip,
        ecm_device_ip=config.ecm.device_ip,
        ecm_netmask=config.ecm.netmask,
        acm_baudrate=config.acm.baudrate,
        acm_console_enabled=config.acm.console_enabled,
        storage_partition=config.mass_storage.partition,
        storage_readonly=config.mass_storage.readonly,
    )


@router.put("/config", response_model=ConfigResponse)
async def update_gadget_config(request: ConfigUpdateRequest):
    """Update gadget configuration."""
    config = get_config()

    # Apply updates
    if request.default_mode is not None:
        config.default_mode = request.default_mode
    if request.auto_switch is not None:
        config.auto_switch = request.auto_switch
    if request.ecm_host_ip is not None:
        config.ecm.host_ip = request.ecm_host_ip
    if request.ecm_device_ip is not None:
        config.ecm.device_ip = request.ecm_device_ip
    if request.acm_baudrate is not None:
        config.acm.baudrate = request.acm_baudrate
    if request.storage_partition is not None:
        config.mass_storage.partition = request.storage_partition
    if request.storage_readonly is not None:
        config.mass_storage.readonly = request.storage_readonly

    # Save configuration
    if not save_config(config):
        raise HTTPException(status_code=500, detail="Failed to save configuration")

    return await get_gadget_config()


@router.post("/reload")
async def reload_gadget_config():
    """Reload configuration from file."""
    reload_config()
    return {"status": "ok", "message": "Configuration reloaded"}
