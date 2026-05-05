"""
SecuBox-Deb :: Eye Remote Host API
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Host-side API for SecuBox Eye Remote integration.
Handles auto-detection, metrics relay, and WebUI control.
"""
from __future__ import annotations

import asyncio
import socket
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Initialize
app = FastAPI(
    title="SecuBox Eye Remote",
    description="Eye Remote USB Gadget Integration API",
    version="2.1.0",
)

logger = logging.getLogger("secubox.eye-remote")

# Constants
INTERFACE_NAME = "usb0"
PEER_IP = "10.55.0.2"
HOST_IP = "10.55.0.1"


class EyeRemoteStatus(BaseModel):
    """Eye Remote connection status."""
    connected: bool
    interface: Optional[str] = None
    peer_ip: Optional[str] = None
    host_ip: Optional[str] = None
    uptime_seconds: Optional[int] = None
    last_seen: Optional[datetime] = None
    gadget_mode: Optional[str] = None


class EyeRemoteMetrics(BaseModel):
    """Metrics from Eye Remote device."""
    cpu_percent: float
    mem_percent: float
    disk_percent: float
    cpu_temp: float
    wifi_rssi: Optional[int] = None
    hostname: str
    uptime_seconds: int


class GadgetModeRequest(BaseModel):
    """Request to change gadget mode."""
    mode: str  # normal, flash, debug, tty, auth


# State
_eye_state = {
    "connected": False,
    "last_seen": None,
    "metrics": None,
}


def _check_interface() -> bool:
    """Check if Eye Remote interface exists and is up."""
    try:
        result = subprocess.run(
            ["ip", "link", "show", INTERFACE_NAME],
            capture_output=True,
            timeout=5,
            text=True,
        )
        # Check for UP flag in interface output (handles state UNKNOWN for USB)
        return result.returncode == 0 and ",UP," in result.stdout
    except Exception:
        return False


def _check_peer_reachable() -> bool:
    """Check if Eye Remote peer is reachable via TCP or ARP.

    Uses TCP connect and ARP table check instead of ping,
    as the service runs as non-root user without CAP_NET_RAW.
    """
    # Try TCP connect to Eye Remote API port
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((PEER_IP, 8000))
        sock.close()
        if result == 0:
            return True
    except Exception:
        pass

    # Fallback: check ARP table for resolved MAC
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", PEER_IP],
            capture_output=True,
            timeout=3,
            text=True,
        )
        # If we have a resolved MAC (REACHABLE, STALE, or DELAY state)
        if result.returncode == 0 and PEER_IP in result.stdout:
            if any(state in result.stdout for state in ["REACHABLE", "STALE", "DELAY"]):
                return True
    except Exception:
        pass

    return False


@app.get("/api/v1/eye-remote/status", response_model=EyeRemoteStatus)
async def get_status():
    """Get Eye Remote connection status."""
    interface_up = _check_interface()
    peer_reachable = _check_peer_reachable() if interface_up else False
    
    return EyeRemoteStatus(
        connected=peer_reachable,
        interface=INTERFACE_NAME if interface_up else None,
        peer_ip=PEER_IP if peer_reachable else None,
        host_ip=HOST_IP if interface_up else None,
        last_seen=_eye_state.get("last_seen"),
        gadget_mode="normal" if peer_reachable else None,
    )


@app.post("/api/v1/eye-remote/connected")
async def notify_connected(peer_ip: str = PEER_IP):
    """Called by udev when Eye Remote connects."""
    _eye_state["connected"] = True
    _eye_state["last_seen"] = datetime.now()
    logger.info(f"Eye Remote connected: {peer_ip}")
    return {"status": "ok", "peer_ip": peer_ip}


@app.post("/api/v1/eye-remote/disconnected")
async def notify_disconnected():
    """Called by udev when Eye Remote disconnects."""
    _eye_state["connected"] = False
    logger.info("Eye Remote disconnected")
    return {"status": "ok"}


@app.get("/api/v1/eye-remote/metrics")
async def get_eye_metrics():
    """Get latest metrics from Eye Remote."""
    if not _eye_state.get("connected"):
        raise HTTPException(status_code=503, detail="Eye Remote not connected")
    
    # Relay metrics from Eye Remote
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://{PEER_IP}:8000/api/v1/status")
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        logger.warning(f"Failed to fetch Eye Remote metrics: {e}")
    
    raise HTTPException(status_code=503, detail="Cannot reach Eye Remote")


@app.post("/api/v1/eye-remote/mode")
async def set_gadget_mode(request: GadgetModeRequest):
    """Change Eye Remote gadget mode."""
    valid_modes = ["normal", "flash", "debug", "tty", "auth"]
    if request.mode not in valid_modes:
        raise HTTPException(status_code=400, detail=f"Invalid mode. Valid: {valid_modes}")
    
    if not _eye_state.get("connected"):
        raise HTTPException(status_code=503, detail="Eye Remote not connected")
    
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"http://{PEER_IP}:8000/api/v1/gadget/mode",
                json={"mode": request.mode},
            )
            if resp.status_code == 200:
                logger.info(f"Gadget mode changed to: {request.mode}")
                return {"status": "ok", "mode": request.mode}
    except Exception as e:
        logger.error(f"Failed to change gadget mode: {e}")
    
    raise HTTPException(status_code=503, detail="Failed to change mode")


@app.get("/api/v1/eye-remote/serial/status")
async def get_serial_status():
    """Get serial console status."""
    tty_exists = Path("/dev/ttyACM0").exists()
    return {
        "available": tty_exists,
        "device": "/dev/ttyACM0" if tty_exists else None,
        "baud": 115200,
    }


@app.get("/api/v1/eye-remote/pizero/metrics")
async def get_pizero_metrics():
    """Get Pi Zero metrics - public endpoint for dashboard.

    This endpoint relays metrics from the Pi Zero without requiring auth,
    so the dashboard can display them without complex auth setup.
    """
    # First check if peer is reachable (don't rely on state which might be stale)
    interface_up = _check_interface()
    peer_reachable = _check_peer_reachable() if interface_up else False

    if not peer_reachable:
        raise HTTPException(status_code=503, detail="Pi Zero not connected")

    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://{PEER_IP}:8000/api/v1/status")
            if resp.status_code == 200:
                return resp.json()
    except Exception as e:
        logger.warning(f"Failed to fetch Pi Zero metrics: {e}")

    raise HTTPException(status_code=503, detail="Cannot reach Pi Zero")


@app.post("/api/v1/eye-remote/auto-pair")
async def auto_pair():
    """Auto-pair with connected Eye Remote device.

    Updates existing entry if device with same IP exists,
    otherwise creates new entry. Prevents duplicate pairings.
    """
    # Check if device is connected
    interface_up = _check_interface()
    peer_reachable = _check_peer_reachable() if interface_up else False

    if not peer_reachable:
        return {"success": False, "error": "No Eye Remote device connected"}

    # Try to get device info from Pi Zero
    hostname = "eye-remote"
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"http://{PEER_IP}:8000/api/v1/status")
            if resp.status_code == 200:
                data = resp.json()
                hostname = data.get("hostname", "eye-remote")
    except Exception:
        pass

    import json

    # Save to paired devices storage (list format for console display)
    storage_path = Path("/var/lib/secubox/eye-remote/auto-paired.json")
    storage_path.parent.mkdir(parents=True, exist_ok=True)

    devices = []
    if storage_path.exists():
        try:
            with open(storage_path) as f:
                devices = json.load(f)
        except Exception:
            pass

    # Check if device with this IP already exists
    existing_idx = None
    for i, d in enumerate(devices):
        if d.get("peer_ip") == PEER_IP:
            existing_idx = i
            break

    device_entry = {
        "device_id": hostname,
        "hostname": hostname,
        "peer_ip": PEER_IP,
        "transport": "usb",
        "paired_at": datetime.now().isoformat(),
        "last_seen": datetime.now().isoformat(),
    }

    if existing_idx is not None:
        # Update existing - keep original paired_at
        device_entry["paired_at"] = devices[existing_idx].get("paired_at", device_entry["paired_at"])
        devices[existing_idx] = device_entry
        message = f"Device {hostname} updated"
    else:
        devices.append(device_entry)
        message = f"Device {hostname} paired successfully"

    with open(storage_path, 'w') as f:
        json.dump(devices, f, indent=2)

    logger.info(f"Auto-paired device: {hostname} @ {PEER_IP}")

    return {
        "success": True,
        "device_id": hostname,
        "hostname": hostname,
        "message": message,
    }


@app.get("/api/v1/eye-remote/paired-devices")
async def get_paired_devices():
    """List all paired Eye Remote devices."""
    storage_path = Path("/var/lib/secubox/eye-remote/auto-paired.json")

    if not storage_path.exists():
        return {"devices": [], "count": 0}

    try:
        import json
        with open(storage_path) as f:
            devices = json.load(f)

        # Handle both list and dict formats
        if isinstance(devices, list):
            device_list = devices
        else:
            device_list = list(devices.values())

        return {"devices": device_list, "count": len(device_list)}
    except Exception as e:
        logger.error(f"Failed to read paired devices: {e}")
        return {"devices": [], "count": 0, "error": str(e)}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "secubox-eye-remote"}
