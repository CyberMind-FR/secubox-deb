"""Status router — Container status and control endpoints."""
import subprocess
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("mitmproxy.status")

CONTAINER_NAME = "mitmproxy-waf"


class StatusResponse(BaseModel):
    container_exists: bool
    container_running: bool
    mitmproxy_running: bool
    threats_today: int = 0
    by_category: dict = {}
    by_severity: dict = {}


class ActionResponse(BaseModel):
    success: bool
    message: str


def _lxc_exists() -> bool:
    """Check if LXC container exists."""
    result = subprocess.run(["lxc-ls"], capture_output=True, text=True)
    return CONTAINER_NAME in result.stdout.split()


def _lxc_running() -> bool:
    """Check if LXC container is running."""
    result = subprocess.run(
        ["lxc-info", "-n", CONTAINER_NAME, "-s"],
        capture_output=True, text=True
    )
    return "RUNNING" in result.stdout


def _mitmproxy_running() -> bool:
    """Check if mitmproxy is running inside container."""
    if not _lxc_running():
        return False
    result = subprocess.run(
        ["lxc-attach", "-n", CONTAINER_NAME, "--", "pgrep", "-f", "mitmdump"],
        capture_output=True
    )
    return result.returncode == 0


@router.get("/status", response_model=StatusResponse)
async def get_status(user=Depends(require_jwt)):
    """Get container and WAF status."""
    from ..main import get_stats_cache

    stats = get_stats_cache()

    return StatusResponse(
        container_exists=_lxc_exists(),
        container_running=_lxc_running(),
        mitmproxy_running=_mitmproxy_running(),
        threats_today=stats.get("threats_today", 0),
        by_category=stats.get("by_category", {}),
        by_severity=stats.get("by_severity", {})
    )


@router.post("/start", response_model=ActionResponse)
async def start_container(user=Depends(require_jwt)):
    """Start the WAF container."""
    if not _lxc_exists():
        raise HTTPException(400, "Container not installed. Run: mitmproxyctl install")

    if _lxc_running():
        return ActionResponse(success=True, message="Container already running")

    result = subprocess.run(["mitmproxyctl", "start"], capture_output=True, text=True)

    if result.returncode == 0:
        return ActionResponse(success=True, message="Container started")
    else:
        raise HTTPException(500, f"Failed to start: {result.stderr}")


@router.post("/stop", response_model=ActionResponse)
async def stop_container(user=Depends(require_jwt)):
    """Stop the WAF container."""
    if not _lxc_running():
        return ActionResponse(success=True, message="Container not running")

    result = subprocess.run(["mitmproxyctl", "stop"], capture_output=True, text=True)

    if result.returncode == 0:
        return ActionResponse(success=True, message="Container stopped")
    else:
        raise HTTPException(500, f"Failed to stop: {result.stderr}")


@router.post("/restart", response_model=ActionResponse)
async def restart_container(user=Depends(require_jwt)):
    """Restart the WAF container."""
    result = subprocess.run(["mitmproxyctl", "restart"], capture_output=True, text=True)

    if result.returncode == 0:
        return ActionResponse(success=True, message="Container restarted")
    else:
        raise HTTPException(500, f"Failed to restart: {result.stderr}")
