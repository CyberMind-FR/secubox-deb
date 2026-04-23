"""SecuBox Eye Remote — Pydantic models."""
from .device import *
from .boot_media import (
    BootSlot,
    BootImage,
    BootMediaState,
    UploadResponse,
    SwapResponse,
    TftpStatusResponse,
)

__all__ = [
    # device.py exports
    "TransportType",
    "DeviceCapability",
    "DeviceScope",
    "PairedDevice",
    "DeviceListResponse",
    "PairRequest",
    "PairResponse",
    "CommandRequest",
    "CommandResponse",
    # boot_media.py exports
    "BootSlot",
    "BootImage",
    "BootMediaState",
    "UploadResponse",
    "SwapResponse",
    "TftpStatusResponse",
]
