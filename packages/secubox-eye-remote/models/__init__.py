# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

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
