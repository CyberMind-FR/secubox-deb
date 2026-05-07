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


# =============================================================================
# System Metrics — MOCHAbin host metrics for Round UI dashboard
# =============================================================================
# Double Pre-Cache Buffer for Metrics
# Background task updates cache every 2s, API returns instantly from cache
# =============================================================================
import asyncio
import time
import os

_metrics_cache = {
    "active": {},      # Current metrics (read by API)
    "shadow": {},      # Being updated by background task
    "last_swap": 0,    # Timestamp of last swap
}
_cpu_state = {"prev_idle": 0, "prev_total": 0, "prev_time": 0}
_cache_task = None

# Connections tracking for Round Eye MIND metric
# Peak persisted to file for resilience across restarts
_PEAK_CONNECTIONS_FILE = Path("/var/cache/secubox/eye-remote/peak_connections")
_connections_state = {"current": 0, "peak": 0, "last_reset": None}


def _load_peak_connections() -> int:
    """Load peak connections from persistent file."""
    try:
        if _PEAK_CONNECTIONS_FILE.exists():
            return int(_PEAK_CONNECTIONS_FILE.read_text().strip())
    except Exception:
        pass
    return 0


def _save_peak_connections(peak: int) -> None:
    """Persist peak connections to file."""
    try:
        _PEAK_CONNECTIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _PEAK_CONNECTIONS_FILE.write_text(str(peak))
    except Exception:
        pass


def _count_tcp_connections() -> int:
    """Count established TCP connections using /proc/net/tcp.

    Faster than calling ss/netstat subprocess.
    """
    count = 0
    try:
        # /proc/net/tcp format: sl local remote st ... (st=01 is ESTABLISHED)
        with open("/proc/net/tcp") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] == "01":  # 01 = ESTABLISHED
                    count += 1
        # Also count tcp6
        with open("/proc/net/tcp6") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] == "01":
                    count += 1
    except Exception:
        pass
    return count


def _update_connections_state() -> tuple[int, int]:
    """Update connections state and return (current, peak).

    Called by metrics background task every 2s.
    Returns: (current_connections, peak_connections)
    """
    global _connections_state

    current = _count_tcp_connections()
    _connections_state["current"] = current

    # Load peak from state (or file on first call)
    if _connections_state["peak"] == 0:
        _connections_state["peak"] = _load_peak_connections()

    # Update peak if current exceeds it
    if current > _connections_state["peak"]:
        _connections_state["peak"] = current
        _save_peak_connections(current)

    # Ensure peak is at least 1 to avoid division by zero
    peak = max(1, _connections_state["peak"])

    return current, peak


def _read_cpu_percent() -> float:
    """Calculate real CPU usage from /proc/stat delta."""
    import time
    global _cpu_state

    try:
        with open("/proc/stat") as f:
            line = f.readline()
        parts = line.split()
        if parts[0] != "cpu":
            return 0.0

        # user, nice, system, idle, iowait, irq, softirq, steal
        values = [int(x) for x in parts[1:9]]
        idle = values[3] + values[4]  # idle + iowait
        total = sum(values)
        now = time.time()

        # Calculate delta from previous reading
        prev_idle = _cpu_state["prev_idle"]
        prev_total = _cpu_state["prev_total"]
        prev_time = _cpu_state["prev_time"]

        # Update state
        _cpu_state["prev_idle"] = idle
        _cpu_state["prev_total"] = total
        _cpu_state["prev_time"] = now

        # Need at least 100ms between readings for accuracy
        if prev_time > 0 and (now - prev_time) > 0.1:
            idle_delta = idle - prev_idle
            total_delta = total - prev_total
            if total_delta > 0:
                return round(100.0 * (1.0 - idle_delta / total_delta), 1)

        # Fallback for first reading: use 1-second sample
        import os
        load = os.getloadavg()[0]
        cpus = os.cpu_count() or 4
        return round(min(95.0, (load / cpus) * 80), 1)  # Scale down load-based estimate

    except Exception:
        return 0.0


def _get_host_metrics() -> dict:
    """Collect MOCHAbin host system metrics for round UI display."""
    import os
    from datetime import timezone

    metrics = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "hostname": "secubox-mochabin",
    }

    # CPU usage - real delta calculation
    metrics["cpu_percent"] = _read_cpu_percent()

    # Memory from /proc/meminfo
    try:
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
            total_kb = meminfo.get("MemTotal", 1)
            avail_kb = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
            metrics["mem_percent"] = round(((total_kb - avail_kb) / total_kb) * 100, 1)
    except Exception:
        metrics["mem_percent"] = 0.0

    # Disk from statvfs
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        metrics["disk_percent"] = round(((total - free) / total) * 100, 1) if total > 0 else 0.0
    except Exception:
        metrics["disk_percent"] = 0.0

    # CPU temperature
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            metrics["cpu_temp"] = round(int(f.read().strip()) / 1000.0, 1)
    except Exception:
        metrics["cpu_temp"] = 0.0

    # Load average
    try:
        load1, load5, load15 = os.getloadavg()
        metrics["load_1m"] = round(load1, 2)
        metrics["load_5m"] = round(load5, 2)
        metrics["load_15m"] = round(load15, 2)
    except Exception:
        metrics["load_1m"] = metrics["load_5m"] = metrics["load_15m"] = 0.0

    # Uptime
    try:
        with open("/proc/uptime") as f:
            metrics["uptime_seconds"] = int(float(f.read().split()[0]))
    except Exception:
        metrics["uptime_seconds"] = 0

    # Connections tracking for Round Eye MIND metric
    # Returns current connections and peak (highest ever seen)
    # Round Eye calculates: connections / peak_connections * 100 for ring %
    current_conns, peak_conns = _update_connections_state()
    metrics["connections"] = current_conns
    metrics["peak_connections"] = peak_conns
    # Pre-calculated percentage for convenience (current / peak * 100)
    metrics["connections_percent"] = round((current_conns / peak_conns) * 100, 1)

    return metrics


async def _metrics_background_task():
    """Background task that updates metrics cache every 2 seconds.

    Pattern: Double Pre-Cache Buffer (per SecuBox guidelines)
    - shadow buffer updated in background
    - atomic swap to active buffer
    - API reads from active (instant response)
    """
    global _metrics_cache

    while True:
        try:
            # Collect metrics into shadow buffer
            _metrics_cache["shadow"] = _get_host_metrics()

            # Atomic swap: shadow → active
            _metrics_cache["active"] = _metrics_cache["shadow"].copy()
            _metrics_cache["last_swap"] = time.time()

        except Exception as e:
            logger.warning(f"Metrics cache update failed: {e}")

        await asyncio.sleep(2)  # Update every 2 seconds


@app.on_event("startup")
async def start_metrics_cache():
    """Start background metrics caching on API startup."""
    global _cache_task

    # Initial cache population
    _metrics_cache["active"] = _get_host_metrics()
    _metrics_cache["last_swap"] = time.time()

    # Start background updater
    _cache_task = asyncio.create_task(_metrics_background_task())
    logger.info("Metrics pre-cache started (2s refresh)")


@app.on_event("shutdown")
async def stop_metrics_cache():
    """Stop background task on shutdown."""
    global _cache_task
    if _cache_task:
        _cache_task.cancel()
        try:
            await _cache_task
        except asyncio.CancelledError:
            pass


@app.get("/api/v1/system/metrics")
async def get_system_metrics():
    """Get MOCHAbin host system metrics for round UI dashboard.

    Returns cached metrics (updated every 2s by background task).
    Pattern: Double Pre-Cache Buffer for instant response.
    """
    if _metrics_cache["active"]:
        return _metrics_cache["active"]
    # Fallback if cache not ready
    return _get_host_metrics()


# =============================================================================
# USB Gadget Metrics — Issue #61
# =============================================================================

class GadgetFunctionState(BaseModel):
    """State of a USB gadget function."""
    state: str  # connected, disconnected, active, inactive
    rx_bytes: int = 0
    tx_bytes: int = 0
    sessions: int = 0
    image: Optional[str] = None


class GadgetMetrics(BaseModel):
    """USB gadget metrics for monitoring."""
    ecm: Optional[GadgetFunctionState] = None
    acm: Optional[GadgetFunctionState] = None
    mass_storage: Optional[GadgetFunctionState] = None
    udc: Optional[str] = None
    uptime: int = 0
    last_activity: Optional[datetime] = None


def _get_gadget_metrics() -> dict:
    """Collect USB gadget metrics from configfs and sysfs."""
    from datetime import timezone

    gadget_base = Path("/sys/kernel/config/usb_gadget/g1")
    metrics = {
        "ecm": None,
        "acm": None,
        "mass_storage": None,
        "udc": None,
        "uptime": 0,
        "last_activity": None,
    }

    # Check if gadget is configured
    if not gadget_base.exists():
        return metrics

    # Get UDC (USB Device Controller) - shows if gadget is bound
    udc_file = gadget_base / "UDC"
    if udc_file.exists():
        try:
            udc = udc_file.read_text().strip()
            metrics["udc"] = udc if udc else None
        except Exception:
            pass

    # ECM (Ethernet) gadget function
    ecm_func = gadget_base / "functions" / "ecm.usb0"
    if ecm_func.exists():
        ecm_state = {"state": "configured", "rx_bytes": 0, "tx_bytes": 0}

        # Check network interface stats
        net_stats = Path("/sys/class/net/usb0/statistics")
        if net_stats.exists():
            ecm_state["state"] = "connected"
            try:
                rx_file = net_stats / "rx_bytes"
                tx_file = net_stats / "tx_bytes"
                if rx_file.exists():
                    ecm_state["rx_bytes"] = int(rx_file.read_text().strip())
                if tx_file.exists():
                    ecm_state["tx_bytes"] = int(tx_file.read_text().strip())
            except Exception:
                pass
        else:
            ecm_state["state"] = "disconnected"

        metrics["ecm"] = ecm_state

    # ACM (Serial) gadget function
    acm_func = gadget_base / "functions" / "acm.usb0"
    if acm_func.exists():
        acm_state = {"state": "configured", "sessions": 0}

        # Check if ttyGS0 exists (gadget serial device)
        if Path("/dev/ttyGS0").exists():
            acm_state["state"] = "active"
            # Count active sessions by checking if device is open
            try:
                result = subprocess.run(
                    ["fuser", "/dev/ttyGS0"],
                    capture_output=True, timeout=2
                )
                if result.returncode == 0 and result.stdout.strip():
                    acm_state["sessions"] = len(result.stdout.decode().split())
            except Exception:
                pass
        else:
            acm_state["state"] = "inactive"

        metrics["acm"] = acm_state

    # Mass Storage gadget function
    ms_func = gadget_base / "functions" / "mass_storage.usb0"
    if ms_func.exists():
        ms_state = {"state": "configured", "image": None}

        # Check LUN0 file
        lun0_file = ms_func / "lun.0" / "file"
        if lun0_file.exists():
            try:
                image = lun0_file.read_text().strip()
                if image:
                    ms_state["image"] = image
                    ms_state["state"] = "mounted"
                else:
                    ms_state["state"] = "unmounted"
            except Exception:
                pass

        metrics["mass_storage"] = ms_state

    # Get uptime
    try:
        with open("/proc/uptime") as f:
            metrics["uptime"] = int(float(f.read().split()[0]))
    except Exception:
        pass

    # Last activity from state
    if _eye_state.get("last_seen"):
        metrics["last_activity"] = _eye_state["last_seen"].isoformat()
    else:
        metrics["last_activity"] = datetime.now(timezone.utc).isoformat()

    return metrics


@app.get("/api/v1/eye-remote/gadget/metrics")
async def get_gadget_metrics():
    """Get USB gadget metrics for monitoring.

    Returns state of USB gadget functions:
    - ECM (Ethernet): connection state, RX/TX bytes
    - ACM (Serial): active state, session count
    - Mass Storage: mount state, image path

    Issue: #61
    """
    return _get_gadget_metrics()


@app.get("/api/v1/eye-remote/gadget/status")
async def get_gadget_status():
    """Get simplified USB gadget status.

    Quick check for dashboard display.
    """
    metrics = _get_gadget_metrics()

    # Determine overall status
    if not metrics.get("udc"):
        status = "unconfigured"
    elif metrics.get("ecm", {}).get("state") == "connected":
        status = "connected"
    elif metrics.get("udc"):
        status = "ready"
    else:
        status = "unknown"

    return {
        "status": status,
        "udc": metrics.get("udc"),
        "ecm_connected": metrics.get("ecm", {}).get("state") == "connected",
        "acm_active": metrics.get("acm", {}).get("state") == "active",
        "mass_storage_mounted": metrics.get("mass_storage", {}).get("state") == "mounted",
    }
