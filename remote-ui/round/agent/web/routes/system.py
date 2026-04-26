"""
SecuBox Eye Remote — System API Routes
Endpoints for system information and control.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import logging
import os
import socket
from typing import Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel

log = logging.getLogger(__name__)

router = APIRouter()


class SystemInfo(BaseModel):
    """System information."""
    hostname: str
    uptime: str
    cpu_temp: Optional[float] = None
    memory_used_percent: Optional[float] = None
    disk_used_percent: Optional[float] = None
    kernel_version: Optional[str] = None
    eye_remote_version: str = "1.0.0"


class RebootResponse(BaseModel):
    """Response for system reboot."""
    status: str
    message: str


class ShutdownResponse(BaseModel):
    """Response for system shutdown."""
    status: str
    message: str


def _get_uptime() -> str:
    """Get system uptime as human-readable string."""
    try:
        with open("/proc/uptime", "r") as f:
            uptime_seconds = float(f.readline().split()[0])

        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)

        if hours > 24:
            days = hours // 24
            hours = hours % 24
            return f"{days}d {hours}h {minutes}m"
        return f"{hours}h {minutes}m"
    except Exception:
        return "unknown"


def _get_cpu_temp() -> Optional[float]:
    """Get CPU temperature in Celsius."""
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
            return float(f.read().strip()) / 1000.0
    except Exception:
        return None


def _get_memory_percent() -> Optional[float]:
    """Get memory usage percentage."""
    try:
        with open("/proc/meminfo", "r") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(':')] = int(parts[1])

            total = meminfo.get("MemTotal", 0)
            available = meminfo.get("MemAvailable", 0)

            if total > 0:
                return round((1 - available / total) * 100, 1)
    except Exception:
        pass
    return None


def _get_disk_percent() -> Optional[float]:
    """Get root disk usage percentage."""
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        if total > 0:
            return round((1 - free / total) * 100, 1)
    except Exception:
        pass
    return None


def _get_kernel_version() -> Optional[str]:
    """Get kernel version."""
    try:
        return os.uname().release
    except Exception:
        return None


@router.get("/info", response_model=SystemInfo)
async def get_system_info(_request: Request) -> SystemInfo:
    """
    Get system information.

    Returns:
        System information including hostname, uptime, temperatures
    """
    return SystemInfo(
        hostname=socket.gethostname(),
        uptime=_get_uptime(),
        cpu_temp=_get_cpu_temp(),
        memory_used_percent=_get_memory_percent(),
        disk_used_percent=_get_disk_percent(),
        kernel_version=_get_kernel_version(),
    )


@router.post("/reboot", response_model=RebootResponse)
async def reboot_system(_request: Request) -> RebootResponse:
    """
    Request system reboot.

    Returns:
        Reboot status
    """
    # TODO: Implement actual reboot (requires privileges)
    log.warning("System reboot requested")
    return RebootResponse(
        status="pending",
        message="Reboot requested - requires system privileges",
    )


@router.post("/shutdown", response_model=ShutdownResponse)
async def shutdown_system(_request: Request) -> ShutdownResponse:
    """
    Request system shutdown.

    Returns:
        Shutdown status
    """
    # TODO: Implement actual shutdown (requires privileges)
    log.warning("System shutdown requested")
    return ShutdownResponse(
        status="pending",
        message="Shutdown requested - requires system privileges",
    )


@router.get("/logs")
async def get_system_logs(
    _request: Request,
    lines: int = 50,  # noqa: ARG001 - Reserved for pagination
) -> dict:
    """
    Get recent system logs.

    Args:
        lines: Number of log lines to return

    Returns:
        Recent log entries
    """
    # TODO: Implement actual log retrieval
    _ = lines  # Will be used when implemented
    return {
        "logs": [],
        "message": "Log retrieval not implemented",
    }


@router.get("/storage")
async def get_storage_info(_request: Request) -> dict:
    """
    Get storage information.

    Returns:
        Storage usage for all mounted filesystems
    """
    # TODO: Implement detailed storage info
    disk_percent = _get_disk_percent()
    return {
        "root": {
            "used_percent": disk_percent,
            "total_gb": None,
            "free_gb": None,
        }
    }
