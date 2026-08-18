# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Modem Connection Router
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>

API endpoints for connection management.
"""
import json
from pathlib import Path
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

from core.mm_client import ModemManagerClient, ConnectionConfig

log = get_logger("modem-connection")
router = APIRouter()

# Config storage
CONFIG_DIR = Path("/var/lib/secubox/modem")
CONFIG_FILE = CONFIG_DIR / "connection.json"
SECRETS_DIR = Path("/etc/secubox/secrets")
PIN_FILE = SECRETS_DIR / "modem-pin"

CONFIG_DIR.mkdir(parents=True, exist_ok=True)


# Global client
_mm_client: Optional[ModemManagerClient] = None


def get_mm_client() -> ModemManagerClient:
    global _mm_client
    if _mm_client is None:
        _mm_client = ModemManagerClient()
    return _mm_client


def _load_config() -> Dict[str, Any]:
    """Load saved connection config."""
    try:
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text())
    except Exception as e:
        log.error("Failed to load config: %s", e)
    return {
        "apn": "",
        "user": "",
        "ip_type": "ipv4",
        "auth": "none",
        "auto_connect": False,
    }


def _save_config(config: Dict[str, Any]):
    """Save connection config."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def _load_pin() -> Optional[str]:
    """Load SIM PIN from secrets file."""
    try:
        if PIN_FILE.exists():
            return PIN_FILE.read_text().strip()
    except Exception:
        pass
    return None


def _save_pin(pin: str):
    """Save SIM PIN to secrets file."""
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    PIN_FILE.write_text(pin)
    PIN_FILE.chmod(0o600)


# === Request/Response Models ===

class ConnectRequest(BaseModel):
    apn: str
    user: str = ""
    password: str = ""
    ip_type: str = "ipv4"
    auth: str = "none"
    save: bool = True


class ConfigResponse(BaseModel):
    apn: str = ""
    user: str = ""
    ip_type: str = "ipv4"
    auth: str = "none"
    auto_connect: bool = False
    has_pin: bool = False


class ConfigUpdateRequest(BaseModel):
    apn: Optional[str] = None
    user: Optional[str] = None
    password: Optional[str] = None
    ip_type: Optional[str] = None
    auth: Optional[str] = None
    auto_connect: Optional[bool] = None
    pin: Optional[str] = None


# === Endpoints ===

@router.post("/connect")
async def connect(req: ConnectRequest, user=Depends(require_jwt)):
    """Connect to cellular network with specified APN."""
    log.info("Connect request: APN=%s", req.apn)

    mm = get_mm_client()

    config = ConnectionConfig(
        apn=req.apn,
        user=req.user,
        password=req.password,
        ip_type=req.ip_type,
        auth=req.auth,
    )

    result = await mm.connect(config)

    if result.get("success") and req.save:
        # Save config (without password)
        _save_config({
            "apn": req.apn,
            "user": req.user,
            "ip_type": req.ip_type,
            "auth": req.auth,
            "auto_connect": False,
        })

    return result


@router.post("/disconnect")
async def disconnect(user=Depends(require_jwt)):
    """Disconnect from cellular network."""
    log.info("Disconnect request")

    mm = get_mm_client()
    result = await mm.disconnect()

    return result


@router.get("/config", response_model=ConfigResponse)
async def get_config(user=Depends(require_jwt)):
    """Get current connection configuration."""
    config = _load_config()
    has_pin = PIN_FILE.exists()

    return ConfigResponse(
        apn=config.get("apn", ""),
        user=config.get("user", ""),
        ip_type=config.get("ip_type", "ipv4"),
        auth=config.get("auth", "none"),
        auto_connect=config.get("auto_connect", False),
        has_pin=has_pin,
    )


@router.post("/config")
async def update_config(req: ConfigUpdateRequest, user=Depends(require_jwt)):
    """Update connection configuration."""
    config = _load_config()

    if req.apn is not None:
        config["apn"] = req.apn
    if req.user is not None:
        config["user"] = req.user
    if req.ip_type is not None:
        config["ip_type"] = req.ip_type
    if req.auth is not None:
        config["auth"] = req.auth
    if req.auto_connect is not None:
        config["auto_connect"] = req.auto_connect

    _save_config(config)

    # Handle PIN separately (stored in secrets)
    if req.pin is not None:
        if req.pin:
            _save_pin(req.pin)
        else:
            # Empty string = remove PIN
            if PIN_FILE.exists():
                PIN_FILE.unlink()

    return {"success": True, "config": config}


@router.post("/power/on")
async def power_on(user=Depends(require_jwt)):
    """Power on the modem."""
    mm = get_mm_client()
    result = await mm.set_power_state(on=True)
    return result


@router.post("/power/off")
async def power_off(user=Depends(require_jwt)):
    """Power off the modem."""
    mm = get_mm_client()
    result = await mm.set_power_state(on=False)
    return result


@router.post("/reset")
async def reset_modem(user=Depends(require_jwt)):
    """Reset the modem."""
    mm = get_mm_client()
    result = await mm.reset()
    return result


@router.get("/bearers")
async def get_bearers(user=Depends(require_jwt)):
    """Get active bearer (connection) information."""
    mm = get_mm_client()
    status = await mm.get_status()

    return {
        "connected": status.connected,
        "bearer_path": status.bearer_path,
        "ip_address": status.ip_address,
        "dns_servers": status.dns_servers,
        "mtu": status.mtu,
    }


# === Known APN Database ===

KNOWN_APNS = {
    "fr": [
        {"operator": "Orange", "apn": "orange", "user": "orange", "auth": "pap"},
        {"operator": "Orange M2M", "apn": "orange.m2m.spec", "user": "", "auth": "none"},
        {"operator": "SFR", "apn": "sl2sfr", "user": "", "auth": "none"},
        {"operator": "Bouygues", "apn": "mmsbouygtel.com", "user": "", "auth": "none"},
        {"operator": "Free", "apn": "free", "user": "", "auth": "none"},
    ],
    "us": [
        {"operator": "AT&T", "apn": "broadband", "user": "", "auth": "none"},
        {"operator": "T-Mobile", "apn": "fast.t-mobile.com", "user": "", "auth": "none"},
        {"operator": "Verizon", "apn": "vzwinternet", "user": "", "auth": "none"},
    ],
    "generic": [
        {"operator": "Hologram", "apn": "hologram", "user": "", "auth": "none"},
        {"operator": "1nce", "apn": "iot.1nce.net", "user": "", "auth": "none"},
    ],
}


@router.get("/apn/database")
async def get_apn_database(
    country: Optional[str] = None,
    user=Depends(require_jwt)
):
    """Get known APN configurations."""
    if country:
        return {"apns": KNOWN_APNS.get(country.lower(), [])}
    return {"apns": KNOWN_APNS}
