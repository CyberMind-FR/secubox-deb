"""
SecuBox Eye Remote — SecuBox API Routes
Endpoints for SecuBox connection status and metrics.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel

log = logging.getLogger(__name__)

router = APIRouter()


class SecuBoxStatus(BaseModel):
    """SecuBox connection status."""
    connected: bool
    transport: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    last_poll: Optional[str] = None
    latency_ms: Optional[float] = None


class SecuBoxMetrics(BaseModel):
    """SecuBox metrics snapshot."""
    cpu_percent: Optional[float] = None
    mem_percent: Optional[float] = None
    disk_percent: Optional[float] = None
    wifi_rssi: Optional[int] = None
    load_avg_1: Optional[float] = None
    cpu_temp: Optional[float] = None
    uptime_seconds: Optional[int] = None
    hostname: Optional[str] = None
    secubox_version: Optional[str] = None
    modules_active: List[str] = []


class SecuBoxModule(BaseModel):
    """SecuBox module status."""
    name: str
    status: str
    enabled: bool


class SecuBoxModulesResponse(BaseModel):
    """Response for module list."""
    modules: List[SecuBoxModule]


class SecuBoxAlert(BaseModel):
    """SecuBox alert."""
    id: str
    level: str  # info, warn, crit
    module: str
    message: str
    timestamp: str


class SecuBoxAlertsResponse(BaseModel):
    """Response for alerts list."""
    alerts: List[SecuBoxAlert]


@router.get("/status", response_model=SecuBoxStatus)
async def get_secubox_status(request: Request) -> SecuBoxStatus:
    """
    Get SecuBox connection status.

    Returns:
        Connection status and transport info
    """
    failover = request.app.state.failover_monitor
    _config = request.app.state.config  # Reserved for future use

    if failover:
        # TODO: Get actual status from failover monitor
        pass

    return SecuBoxStatus(
        connected=False,
        transport=None,
        host=None,
        port=None,
    )


@router.get("/metrics", response_model=SecuBoxMetrics)
async def get_secubox_metrics(_request: Request) -> SecuBoxMetrics:
    """
    Get SecuBox metrics.

    Returns:
        Latest metrics from connected SecuBox
    """
    # TODO: Implement actual metrics retrieval from SecuBox API
    return SecuBoxMetrics(
        cpu_percent=None,
        mem_percent=None,
        disk_percent=None,
        modules_active=[],
    )


@router.get("/modules", response_model=SecuBoxModulesResponse)
async def get_secubox_modules(_request: Request) -> SecuBoxModulesResponse:
    """
    Get SecuBox module status.

    Returns:
        List of modules with their status
    """
    # TODO: Implement actual module status retrieval
    return SecuBoxModulesResponse(
        modules=[
            SecuBoxModule(name="AUTH", status="unknown", enabled=True),
            SecuBoxModule(name="WALL", status="unknown", enabled=True),
            SecuBoxModule(name="BOOT", status="unknown", enabled=True),
            SecuBoxModule(name="MIND", status="unknown", enabled=True),
            SecuBoxModule(name="ROOT", status="unknown", enabled=True),
            SecuBoxModule(name="MESH", status="unknown", enabled=True),
        ]
    )


@router.get("/alerts", response_model=SecuBoxAlertsResponse)
async def get_secubox_alerts(_request: Request) -> SecuBoxAlertsResponse:
    """
    Get SecuBox alerts.

    Returns:
        List of active alerts
    """
    # TODO: Implement actual alerts retrieval
    return SecuBoxAlertsResponse(alerts=[])


@router.post("/reconnect")
async def reconnect_secubox(request: Request) -> dict:
    """
    Force reconnection to SecuBox.

    Returns:
        Reconnection status
    """
    failover = request.app.state.failover_monitor

    if failover:
        # TODO: Trigger reconnection via failover monitor
        pass

    log.info("SecuBox reconnection requested")
    return {
        "status": "pending",
        "message": "Reconnection requested",
    }


@router.post("/module/{module_name}/restart")
async def restart_secubox_module(request: Request, module_name: str) -> dict:
    """
    Request restart of a SecuBox module.

    Args:
        module_name: Name of the module to restart

    Returns:
        Restart status
    """
    # TODO: Implement module restart via SecuBox API
    log.info(f"Module restart requested: {module_name}")
    return {
        "status": "pending",
        "message": f"Restart requested for module: {module_name}",
    }


@router.get("/logs")
async def get_secubox_logs(
    _request: Request,
    module: Optional[str] = None,  # noqa: ARG001 - Reserved for filtering
    lines: int = 50,  # noqa: ARG001 - Reserved for pagination
) -> dict:
    """
    Get SecuBox logs.

    Args:
        module: Optional module name to filter logs
        lines: Number of log lines to return

    Returns:
        Log entries
    """
    # TODO: Implement log retrieval from SecuBox
    _ = module, lines  # Will be used when implemented
    return {
        "logs": [],
        "message": "Log retrieval not implemented",
    }
