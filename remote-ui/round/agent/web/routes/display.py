"""
SecuBox Eye Remote — Display API Routes
Endpoints for display settings and control.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass  # Future type imports

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

router = APIRouter()


class DisplaySettings(BaseModel):
    """Display settings."""
    brightness: int = Field(ge=0, le=100, default=80)
    timeout_seconds: int = Field(ge=0, default=300)
    theme: str = "neon"
    rotation: int = Field(ge=0, le=270, default=0)


class BrightnessRequest(BaseModel):
    """Request to set brightness."""
    value: int = Field(ge=0, le=100)


class BrightnessResponse(BaseModel):
    """Response for brightness change."""
    success: bool
    brightness: int


class ThemeRequest(BaseModel):
    """Request to set theme."""
    theme: str


class TimeoutRequest(BaseModel):
    """Request to set screen timeout."""
    timeout_seconds: int = Field(ge=0)


class OperationResponse(BaseModel):
    """Generic operation response."""
    success: bool
    message: str = ""


@router.get("/settings", response_model=DisplaySettings)
async def get_display_settings(request: Request) -> DisplaySettings:
    """
    Get current display settings.

    Returns:
        Current display settings
    """
    try:
        display_controller = request.app.state.display_controller
        status = await display_controller.status()

        # Get theme from config if available
        theme = "neon"
        config = request.app.state.config
        if config and hasattr(config, 'display') and hasattr(config.display, 'theme'):
            theme = config.display.theme

        return DisplaySettings(
            brightness=status.brightness,
            timeout_seconds=status.timeout_seconds,
            theme=theme,
            rotation=0,
        )
    except Exception as e:
        log.error(f"Display settings check failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to get display settings")


@router.post("/brightness", response_model=BrightnessResponse)
async def set_brightness(request: Request, body: BrightnessRequest) -> BrightnessResponse:
    """
    Set display brightness.

    Args:
        body: Brightness request with value 0-100

    Returns:
        Operation result with new brightness
    """
    try:
        display_controller = request.app.state.display_controller
        log.info(f"Setting brightness to {body.value}")
        success = await display_controller.set_brightness(body.value)
        if success:
            return BrightnessResponse(
                success=True,
                brightness=body.value,
            )
        else:
            return BrightnessResponse(
                success=False,
                brightness=await display_controller.get_brightness(),
            )
    except Exception as e:
        log.error(f"Set brightness failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to set display brightness")


@router.post("/theme", response_model=OperationResponse)
async def set_theme(request: Request, body: ThemeRequest) -> OperationResponse:
    """
    Set display theme.

    Args:
        body: Theme request with theme name

    Returns:
        Operation result
    """
    valid_themes = ["neon", "classic", "minimal"]
    if body.theme not in valid_themes:
        return OperationResponse(
            success=False,
            message=f"Invalid theme: {body.theme}. Valid themes: {valid_themes}",
        )

    # TODO: Implement actual theme change
    log.info(f"Setting theme to {body.theme}")
    return OperationResponse(
        success=True,
        message=f"Theme set to {body.theme}",
    )


@router.post("/timeout", response_model=OperationResponse)
async def set_timeout(request: Request, body: TimeoutRequest) -> OperationResponse:
    """
    Set screen timeout.

    Args:
        body: Timeout request with timeout in seconds (0 = disabled)

    Returns:
        Operation result
    """
    try:
        display_controller = request.app.state.display_controller
        log.info(f"Setting screen timeout to {body.timeout_seconds}s")
        await display_controller.set_timeout(body.timeout_seconds)
        return OperationResponse(
            success=True,
            message=f"Timeout set to {body.timeout_seconds}s",
        )
    except Exception as e:
        log.error(f"Set timeout failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to set display timeout")


@router.post("/wake", response_model=OperationResponse)
async def wake_display(request: Request) -> OperationResponse:
    """
    Wake the display from sleep.

    Returns:
        Operation result
    """
    try:
        display_controller = request.app.state.display_controller
        log.info("Waking display")
        success = await display_controller.wake()
        if success:
            return OperationResponse(
                success=True,
                message="Display woken",
            )
        else:
            return OperationResponse(
                success=False,
                message="Failed to wake display",
            )
    except Exception as e:
        log.error(f"Wake display failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to wake display")


@router.post("/sleep", response_model=OperationResponse)
async def sleep_display(request: Request) -> OperationResponse:
    """
    Put the display to sleep.

    Returns:
        Operation result
    """
    try:
        display_controller = request.app.state.display_controller
        log.info("Sleeping display")
        success = await display_controller.sleep()
        if success:
            return OperationResponse(
                success=True,
                message="Display sleeping",
            )
        else:
            return OperationResponse(
                success=False,
                message="Failed to put display to sleep",
            )
    except Exception as e:
        log.error(f"Sleep display failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to put display to sleep")
