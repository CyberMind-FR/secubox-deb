"""
SecuBox Eye Remote — Boot Media Models
Pydantic models for boot media management (LUN + TFTP).

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class BootSlot(str, Enum):
    """Boot media slots for 4R double-buffer."""
    ACTIVE = "active"
    SHADOW = "shadow"


class BootImage(BaseModel):
    """A boot media image."""
    path: str = Field(..., description="Relative path within images/ directory")
    sha256: str = Field(..., description="SHA256 hash of image content")
    size_bytes: int = Field(..., description="Image size in bytes")
    created_at: datetime = Field(..., description="Upload timestamp")
    label: Optional[str] = Field(None, description="User-friendly label")


class BootMediaState(BaseModel):
    """Current state of boot media slots."""
    active: Optional[BootImage] = Field(None, description="Currently active boot image")
    shadow: Optional[BootImage] = Field(None, description="Shadow slot (for testing/swap)")
    lun_attached: bool = Field(..., description="Whether LUN is attached to USB gadget")
    last_swap_at: Optional[datetime] = Field(None, description="Last active/shadow swap timestamp")
    tftp_armed: bool = Field(..., description="Whether TFTP is serving shadow boot files")


class UploadResponse(BaseModel):
    """Response after uploading boot image."""
    success: bool
    image: BootImage
    message: str = "Image uploaded to shadow slot"


class SwapResponse(BaseModel):
    """Response after swap operation."""
    success: bool
    state: BootMediaState
    message: str


class TftpStatusResponse(BaseModel):
    """TFTP service status."""
    alive: bool = Field(..., description="Whether dnsmasq TFTP is running")
    root: str = Field(..., description="TFTP root directory path")
    files: list[str] = Field(default_factory=list, description="Files in TFTP directory")
