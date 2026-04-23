"""
SecuBox Eye Remote — Boot Media Router
API endpoints for boot media management (LUN + TFTP).

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import logging
import subprocess
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status

from ...core.boot_media import get_boot_media_manager
from ...models.boot_media import (
    BootMediaState,
    SwapResponse,
    TftpStatusResponse,
    UploadResponse,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/boot-media", tags=["boot-media"])


# JWT auth dependency placeholder
def require_jwt():
    """JWT authentication dependency."""
    pass


@router.get("/state", response_model=BootMediaState)
async def get_state(_: None = Depends(require_jwt)) -> BootMediaState:
    """Get current boot media state."""
    manager = get_boot_media_manager()
    return manager.get_state()


@router.post("/upload", response_model=UploadResponse)
async def upload_image(
    file: UploadFile = File(..., description="Boot image file (FAT32 or ext)"),
    label: Optional[str] = Form(None, description="User-friendly label"),
    _: None = Depends(require_jwt),
) -> UploadResponse:
    """Upload boot image to shadow slot."""
    manager = get_boot_media_manager()
    try:
        image = manager.upload_to_shadow(file.file, label=label)
        log.info("Uploaded boot image: %s (%s)", image.sha256[:8], label or "no label")
        return UploadResponse(
            success=True,
            image=image,
            message=f"Image uploaded to shadow slot: {image.sha256[:8]}",
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        log.error("Upload failed: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Upload failed: {e}")


@router.post("/swap", response_model=SwapResponse)
async def swap_slots(_: None = Depends(require_jwt)) -> SwapResponse:
    """Swap active and shadow slots atomically."""
    manager = get_boot_media_manager()
    try:
        state = manager.swap()
        log.info("Swapped boot media slots")
        return SwapResponse(success=True, state=state, message="Active and shadow slots swapped")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Gadget operation failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Swap failed: {e}")


@router.post("/rollback", response_model=SwapResponse)
async def rollback(_: None = Depends(require_jwt)) -> SwapResponse:
    """Rollback to previous active image."""
    manager = get_boot_media_manager()
    try:
        state = manager.rollback()
        if state.shadow is None:
            return SwapResponse(success=True, state=state, message="No shadow to rollback to (no-op)")
        log.info("Rolled back boot media")
        return SwapResponse(success=True, state=state, message="Rolled back to previous active")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Rollback failed: {e}")


@router.get("/tftp/status", response_model=TftpStatusResponse)
async def tftp_status(_: None = Depends(require_jwt)) -> TftpStatusResponse:
    """Get TFTP service status."""
    manager = get_boot_media_manager()
    result = subprocess.run(["systemctl", "is-active", "dnsmasq"], capture_output=True)
    alive = result.returncode == 0
    files = [f.name for f in manager.tftp_dir.glob("*") if f.is_file()]
    return TftpStatusResponse(alive=alive, root=str(manager.tftp_dir), files=files)
