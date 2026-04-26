"""
SecuBox Eye Remote — Mode API Routes
Endpoints for mode control and status.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from agent.mode_manager import Mode

log = logging.getLogger(__name__)

router = APIRouter()


class ModeRequest(BaseModel):
    """Request body for mode change."""
    mode: str


class ModeResponse(BaseModel):
    """Response for mode queries."""
    mode: str
    previous_mode: Optional[str] = None
    changed: bool = False


# Map string mode names to Mode enum
MODE_MAP = {
    "dashboard": Mode.DASHBOARD,
    "local": Mode.LOCAL,
    "flash": Mode.FLASH,
    "gateway": Mode.GATEWAY,
}


@router.get("/mode", response_model=ModeResponse)
async def get_mode(request: Request) -> ModeResponse:
    """
    Get current operating mode.

    Returns:
        Current mode and previous mode
    """
    mode_manager = request.app.state.mode_manager

    if mode_manager is None:
        raise HTTPException(
            status_code=503,
            detail="Mode manager unavailable"
        )

    current = mode_manager.current_mode
    previous = mode_manager.previous_mode

    return ModeResponse(
        mode=current.value,
        previous_mode=previous.value if previous else None,
        changed=False,
    )


@router.post("/mode", response_model=ModeResponse)
async def set_mode(request: Request, body: ModeRequest) -> ModeResponse:
    """
    Set operating mode.

    Args:
        body: Mode request with target mode name

    Returns:
        Updated mode status
    """
    mode_manager = request.app.state.mode_manager

    if mode_manager is None:
        raise HTTPException(
            status_code=503,
            detail="Mode manager unavailable"
        )

    # Validate mode name
    mode_name = body.mode.lower()
    if mode_name not in MODE_MAP:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode: {body.mode}. Valid modes: {list(MODE_MAP.keys())}"
        )

    target_mode = MODE_MAP[mode_name]
    previous = mode_manager.current_mode

    # Attempt mode change
    changed = await mode_manager.set_mode(target_mode)

    log.info(f"Mode change request: {body.mode} (changed={changed})")

    return ModeResponse(
        mode=mode_manager.current_mode.value,
        previous_mode=previous.value if changed else None,
        changed=changed,
    )
