"""
SecuBox Eye Remote — Pairing Router
API endpoints for device pairing and discovery.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import logging
import secrets
import socket
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from ...core.device_registry import get_device_registry
from ...core.token_manager import (
    generate_device_token,
    generate_pairing_code,
    hash_token,
)
from ...models.device import (
    DeviceScope,
    PairedDevice,
    PairRequest,
    PairResponse,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/pair", tags=["pairing"])

# In-memory pairing sessions (short-lived)
_pairing_sessions: dict[str, dict] = {}

# Default pairing session TTL in seconds
PAIRING_SESSION_TTL = 300


class PairingQRResponse(BaseModel):
    """Response with QR code pairing data."""
    code: str = Field(..., description="6-character pairing code")
    url: str = Field(..., description="Pairing URL for QR code")
    host: str = Field(..., description="SecuBox hostname or IP")
    expires_in: int = Field(..., description="Seconds until session expires")


class DiscoverResponse(BaseModel):
    """Response for SecuBox discovery."""
    name: str = Field(..., description="SecuBox instance name")
    version: str = Field(..., description="Eye Remote API version")
    hostname: str = Field(..., description="SecuBox hostname")
    supports_otg: bool = Field(default=True, description="OTG transport supported")
    supports_wifi: bool = Field(default=True, description="WiFi transport supported")


def get_pairing_session(code: str) -> Optional[dict]:
    """
    Get a pairing session by code.

    Args:
        code: 6-character pairing code.

    Returns:
        Session dict or None if not found/expired.
    """
    session = _pairing_sessions.get(code)
    if session is None:
        return None

    # Check expiration
    if datetime.now(timezone.utc) > session["expires_at"]:
        del _pairing_sessions[code]
        return None

    return session


def _get_local_hostname() -> str:
    """Get local hostname or IP address."""
    try:
        return socket.gethostname()
    except Exception:
        return "secubox.local"


def _get_local_ip() -> str:
    """Get local IP address (best effort)."""
    try:
        # Create a socket to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


@router.get("/qr", response_model=PairingQRResponse)
async def generate_pairing_qr() -> PairingQRResponse:
    """
    Generate a QR code pairing session.

    Creates a temporary pairing code that Eye Remote can scan.
    The code expires after 5 minutes.

    Returns:
        QR code data including code, URL, and expiration.
    """
    # Generate unique pairing code
    code = generate_pairing_code()

    # Ensure uniqueness
    while code in _pairing_sessions:
        code = generate_pairing_code()

    # Get SecuBox host info
    host = _get_local_ip()
    hostname = _get_local_hostname()

    # Create pairing URL
    url = f"http://{host}:8000/api/v1/eye-remote/pair?code={code}"

    # Store session
    expires_at = datetime.now(timezone.utc).timestamp() + PAIRING_SESSION_TTL
    _pairing_sessions[code] = {
        "code": code,
        "host": host,
        "hostname": hostname,
        "expires_at": datetime.fromtimestamp(expires_at, tz=timezone.utc),
        "created_at": datetime.now(timezone.utc),
    }

    log.info("Created pairing session: %s (expires in %ds)", code, PAIRING_SESSION_TTL)

    return PairingQRResponse(
        code=code,
        url=url,
        host=host,
        expires_in=PAIRING_SESSION_TTL,
    )


@router.get("/discover", response_model=DiscoverResponse)
async def discover() -> DiscoverResponse:
    """
    Discover SecuBox instance.

    This endpoint does not require authentication and is used
    by Eye Remote devices to discover SecuBox on the local network.

    Returns:
        SecuBox instance information.
    """
    hostname = _get_local_hostname()

    return DiscoverResponse(
        name="SecuBox",
        version="2.0.0",
        hostname=hostname,
        supports_otg=True,
        supports_wifi=True,
    )


@router.post("", response_model=PairResponse)
async def pair_device(request: PairRequest) -> PairResponse:
    """
    Pair a new Eye Remote device.

    Generates a token for the device and stores it in the registry.
    The token is only returned once - it should be stored securely
    by the Eye Remote device.

    Args:
        request: Pairing request with device info.

    Returns:
        Pairing response with token (only returned once).

    Raises:
        HTTPException 409: Device already paired.
    """
    registry = get_device_registry()

    # Check if device already exists
    existing = registry.get_device(request.device_id)
    if existing is not None:
        log.warning("Device already paired: %s", request.device_id)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Device already paired: {request.device_id}",
        )

    # Generate device token
    token = generate_device_token(request.device_id)
    token_hash = hash_token(token)

    # Create paired device
    device = PairedDevice(
        device_id=request.device_id,
        name=request.name,
        token_hash=token_hash,
        paired_at=datetime.now(timezone.utc),
        capabilities=request.capabilities,
        scopes=[DeviceScope.METRICS_READ],  # Default scope
        ssh_pubkey=request.pubkey,
        ssh_enabled=request.pubkey is not None,
    )

    # Store in registry
    registry.add_device(device)

    log.info("Paired new device: %s (%s)", request.device_id, request.name)

    return PairResponse(
        success=True,
        device_id=request.device_id,
        token=token,
        ssh_user="eye-remote" if request.pubkey else None,
        ssh_port=22,
    )
