"""
SecuBox Eye Remote — Metrics Router
API endpoints for system metrics (consumed by Eye Remote devices).

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from ...core.device_registry import get_device_registry
from ...core.token_manager import hash_token

log = logging.getLogger(__name__)

router = APIRouter(tags=["metrics"])


class SystemMetrics(BaseModel):
    """System metrics for Eye Remote display."""
    timestamp: datetime = Field(..., description="Metrics timestamp (UTC)")
    uptime: int = Field(..., description="System uptime in seconds")
    cpu_percent: float = Field(..., description="CPU usage percentage")
    memory_percent: float = Field(..., description="Memory usage percentage")
    disk_percent: float = Field(..., description="Disk usage percentage")
    network_rx_bytes: int = Field(default=0, description="Network bytes received")
    network_tx_bytes: int = Field(default=0, description="Network bytes transmitted")
    load_1m: float = Field(default=0.0, description="1-minute load average")
    load_5m: float = Field(default=0.0, description="5-minute load average")
    load_15m: float = Field(default=0.0, description="15-minute load average")
    active_connections: int = Field(default=0, description="Active network connections")
    blocked_threats: int = Field(default=0, description="Blocked threats (24h)")
    services_running: int = Field(default=0, description="Running services count")
    services_total: int = Field(default=0, description="Total services count")


def validate_device_token(authorization: Optional[str]) -> str:
    """
    Validate device token from Authorization header.

    Args:
        authorization: Authorization header value (Bearer <token>).

    Returns:
        Device ID if token is valid.

    Raises:
        HTTPException 401: Invalid or missing token.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Extract token from "Bearer <token>"
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]
    token_hashed = hash_token(token)

    # Find device with matching token hash
    registry = get_device_registry()
    devices = registry.list_devices()

    for device in devices:
        if device.token_hash == token_hashed:
            # Update last seen
            registry.update_last_seen(device.device_id, "wifi")
            log.debug("Validated token for device: %s", device.device_id)
            return device.device_id

    log.warning("Invalid device token")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid device token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_system_metrics() -> SystemMetrics:
    """
    Collect system metrics.

    This is a fallback implementation when secubox_core.system is not available.
    Uses standard Linux /proc filesystem.

    Returns:
        System metrics for Eye Remote display.
    """
    # Get uptime
    try:
        with open("/proc/uptime") as f:
            uptime = int(float(f.read().split()[0]))
    except Exception:
        uptime = 0

    # Get load averages
    try:
        load_1m, load_5m, load_15m = os.getloadavg()
    except Exception:
        load_1m = load_5m = load_15m = 0.0

    # Get CPU usage (simplified - uses load average as approximation)
    try:
        # Count CPUs
        cpu_count = os.cpu_count() or 1
        # Approximate CPU % from 1-minute load
        cpu_percent = min(100.0, (load_1m / cpu_count) * 100)
    except Exception:
        cpu_percent = 0.0

    # Get memory usage from /proc/meminfo
    try:
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    value = int(parts[1])
                    meminfo[key] = value

            total = meminfo.get("MemTotal", 1)
            available = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
            memory_percent = ((total - available) / total) * 100
    except Exception:
        memory_percent = 0.0

    # Get disk usage
    try:
        statvfs = os.statvfs("/")
        total = statvfs.f_blocks * statvfs.f_frsize
        free = statvfs.f_bavail * statvfs.f_frsize
        if total > 0:
            disk_percent = ((total - free) / total) * 100
        else:
            disk_percent = 0.0
    except Exception:
        disk_percent = 0.0

    # Get network stats from /proc/net/dev
    network_rx = 0
    network_tx = 0
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if ":" not in line:
                    continue
                iface, data = line.split(":", 1)
                iface = iface.strip()
                # Skip loopback
                if iface == "lo":
                    continue
                parts = data.split()
                if len(parts) >= 9:
                    network_rx += int(parts[0])  # bytes received
                    network_tx += int(parts[8])  # bytes transmitted
    except Exception:
        pass

    # Count active connections (from /proc/net/tcp + tcp6)
    active_connections = 0
    try:
        for proto in ["tcp", "tcp6"]:
            path = f"/proc/net/{proto}"
            if os.path.exists(path):
                with open(path) as f:
                    # Skip header line
                    lines = f.readlines()[1:]
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 4:
                            # st == 01 means ESTABLISHED
                            state = parts[3]
                            if state == "01":
                                active_connections += 1
    except Exception:
        pass

    return SystemMetrics(
        timestamp=datetime.now(timezone.utc),
        uptime=uptime,
        cpu_percent=round(cpu_percent, 1),
        memory_percent=round(memory_percent, 1),
        disk_percent=round(disk_percent, 1),
        network_rx_bytes=network_rx,
        network_tx_bytes=network_tx,
        load_1m=round(load_1m, 2),
        load_5m=round(load_5m, 2),
        load_15m=round(load_15m, 2),
        active_connections=active_connections,
        blocked_threats=0,  # Would come from CrowdSec integration
        services_running=0,  # Would come from systemd integration
        services_total=0,
    )


@router.get("/metrics", response_model=SystemMetrics)
async def get_metrics(
    authorization: Optional[str] = Header(None),
) -> SystemMetrics:
    """
    Get system metrics for Eye Remote display.

    Requires device authentication via Bearer token.

    Args:
        authorization: Bearer token for device authentication.

    Returns:
        System metrics including CPU, memory, disk, network stats.

    Raises:
        HTTPException 401: Invalid or missing device token.
    """
    # Validate device token
    device_id = validate_device_token(authorization)

    log.debug("Serving metrics to device: %s", device_id)

    # Try to use secubox_core.system if available
    try:
        from secubox_core.system import get_metrics as core_get_metrics
        return core_get_metrics()
    except ImportError:
        # Fall back to local implementation
        return get_system_metrics()
