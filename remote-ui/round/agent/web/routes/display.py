"""
SecuBox Eye Remote — Display API Routes
Endpoints for display settings and control.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Request
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
    # Get config if available
    config = request.app.state.config
    if config and hasattr(config, 'display'):
        return DisplaySettings(
            brightness=config.display.brightness,
            timeout_seconds=config.display.timeout_seconds,
            theme=config.display.theme,
        )

    return DisplaySettings()


@router.post("/brightness", response_model=BrightnessResponse)
async def set_brightness(request: Request, body: BrightnessRequest) -> BrightnessResponse:
    """
    Set display brightness.

    Args:
        body: Brightness request with value 0-100

    Returns:
        Operation result with new brightness
    """
    # TODO: Implement actual brightness control via sysfs/backlight
    log.info(f"Setting brightness to {body.value}")
    return BrightnessResponse(
        success=True,
        brightness=body.value,
    )


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
    # TODO: Implement actual timeout control
    log.info(f"Setting screen timeout to {body.timeout_seconds}s")
    return OperationResponse(
        success=True,
        message=f"Timeout set to {body.timeout_seconds}s",
    )


@router.post("/wake", response_model=OperationResponse)
async def wake_display(request: Request) -> OperationResponse:
    """
    Wake the display from sleep.

    Returns:
        Operation result
    """
    # TODO: Implement actual display wake
    log.info("Waking display")
    return OperationResponse(
        success=True,
        message="Display wake requested",
    )


@router.post("/sleep", response_model=OperationResponse)
async def sleep_display(request: Request) -> OperationResponse:
    """
    Put the display to sleep.

    Returns:
        Operation result
    """
    # TODO: Implement actual display sleep
    log.info("Sleeping display")
    return OperationResponse(
        success=True,
        message="Display sleep requested",
    )
