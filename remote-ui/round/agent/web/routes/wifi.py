"""
SecuBox Eye Remote — WiFi API Routes
Endpoints for WiFi configuration and status.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

log = logging.getLogger(__name__)

router = APIRouter()


class WifiNetwork(BaseModel):
    """WiFi network information."""
    ssid: str
    signal: int
    security: str
    connected: bool = False


class WifiStatus(BaseModel):
    """WiFi connection status."""
    connected: bool
    ssid: Optional[str] = None
    signal: Optional[int] = None
    ip_address: Optional[str] = None


class WifiNetworksResponse(BaseModel):
    """Response for network scan."""
    networks: List[WifiNetwork]
    scanning: bool = False


class WifiConnectRequest(BaseModel):
    """Request to connect to a WiFi network."""
    ssid: str
    password: Optional[str] = None


class WifiConnectResponse(BaseModel):
    """Response for WiFi connection attempt."""
    success: bool
    message: str


@router.get("/status", response_model=WifiStatus)
async def get_wifi_status(request: Request) -> WifiStatus:
    """
    Get current WiFi connection status.

    Returns:
        WiFi connection status
    """
    try:
        wifi_manager = request.app.state.wifi_manager
        status = await wifi_manager.status()
        return WifiStatus(
            connected=status.connected,
            ssid=status.ssid,
            signal=status.signal,
            ip_address=status.ip_address,
        )
    except Exception as e:
        log.error(f"WiFi status check failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to get WiFi status")


@router.get("/networks", response_model=WifiNetworksResponse)
async def get_wifi_networks(request: Request) -> WifiNetworksResponse:
    """
    Get list of available WiFi networks.

    Returns:
        List of detected networks
    """
    try:
        wifi_manager = request.app.state.wifi_manager
        networks = await wifi_manager.get_networks()
        return WifiNetworksResponse(
            networks=[
                WifiNetwork(
                    ssid=n.ssid,
                    signal=n.signal,
                    security=n.security,
                    connected=n.connected,
                )
                for n in networks
            ],
            scanning=False,
        )
    except Exception as e:
        log.error(f"WiFi get networks failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to get WiFi networks")


@router.post("/scan", response_model=WifiNetworksResponse)
async def scan_wifi_networks(request: Request) -> WifiNetworksResponse:
    """
    Trigger WiFi network scan.

    Returns:
        Scan status and any currently known networks
    """
    try:
        wifi_manager = request.app.state.wifi_manager
        networks = await wifi_manager.scan()
        return WifiNetworksResponse(
            networks=[
                WifiNetwork(
                    ssid=n.ssid,
                    signal=n.signal,
                    security=n.security,
                    connected=n.connected,
                )
                for n in networks
            ],
            scanning=False,
        )
    except Exception as e:
        log.error(f"WiFi scan failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to scan WiFi networks")


@router.post("/connect", response_model=WifiConnectResponse)
async def connect_wifi(request: Request, body: WifiConnectRequest) -> WifiConnectResponse:
    """
    Connect to a WiFi network.

    Args:
        body: Connection request with SSID and optional password

    Returns:
        Connection result
    """
    try:
        wifi_manager = request.app.state.wifi_manager
        log.info(f"WiFi connect request for SSID: {body.ssid}")
        success = await wifi_manager.connect(body.ssid, body.password or "")
        if success:
            return WifiConnectResponse(
                success=True,
                message=f"Connected to {body.ssid}",
            )
        else:
            return WifiConnectResponse(
                success=False,
                message=f"Failed to connect to {body.ssid}",
            )
    except Exception as e:
        log.error(f"WiFi connect failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to connect to WiFi")


@router.post("/disconnect", response_model=WifiConnectResponse)
async def disconnect_wifi(request: Request) -> WifiConnectResponse:
    """
    Disconnect from current WiFi network.

    Returns:
        Disconnection result
    """
    try:
        wifi_manager = request.app.state.wifi_manager
        log.info("WiFi disconnect request")
        success = await wifi_manager.disconnect()
        if success:
            return WifiConnectResponse(
                success=True,
                message="Disconnected from WiFi",
            )
        else:
            return WifiConnectResponse(
                success=False,
                message="Failed to disconnect from WiFi",
            )
    except Exception as e:
        log.error(f"WiFi disconnect failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to disconnect from WiFi")
