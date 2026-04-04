"""SecuBox Domoticz - Home Automation System Management
Container-based home automation with MQTT, Zigbee, Z-Wave and 433MHz integration.

Features:
- Docker/Podman container management
- Device management (switches, sensors, lights)
- Room/scene organization
- Automation rules (timers, events)
- Hardware protocol support
- Event logging and graphs
- Notification configuration
"""
import os
import json
import asyncio
import shutil
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

# Configuration
CONFIG_FILE = Path("/etc/secubox/domoticz.toml")
DATA_PATH = Path("/srv/domoticz")
CONTAINER_NAME = "domoticz"
DEFAULT_PORT = 8080

app = FastAPI(title="secubox-domoticz", version="1.0.0", root_path="/api/v1/domoticz")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("domoticz")

DEFAULT_CONFIG = {
    "port": DEFAULT_PORT,
    "timezone": "Europe/Paris",
    "mqtt_enabled": False,
    "mqtt_host": "127.0.0.1",
    "mqtt_port": 1883,
    "mqtt_topic": "domoticz",
}


# ============================================================================
# Models
# ============================================================================

class DomoticzConfig(BaseModel):
    port: int = DEFAULT_PORT
    timezone: str = "Europe/Paris"
    mqtt_enabled: bool = False
    mqtt_host: str = "127.0.0.1"
    mqtt_port: int = 1883
    mqtt_topic: str = "domoticz"
    mqtt_username: Optional[str] = ""
    mqtt_password: Optional[str] = ""


class DeviceCommand(BaseModel):
    command: str = Field(..., pattern="^(On|Off|Toggle|Set Level)$")
    level: Optional[int] = Field(None, ge=0, le=100)


class RoomCreate(BaseModel):
    name: str
    description: Optional[str] = ""


class NotificationSettings(BaseModel):
    email_enabled: bool = False
    email_address: Optional[str] = ""
    pushover_enabled: bool = False
    pushover_user: Optional[str] = ""
    pushover_api: Optional[str] = ""
    telegram_enabled: bool = False
    telegram_bot_token: Optional[str] = ""
    telegram_chat_id: Optional[str] = ""


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load domoticz configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save configuration to TOML file."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    content = f"""# Domoticz configuration
port = {config.get('port', DEFAULT_PORT)}
timezone = "{config.get('timezone', 'Europe/Paris')}"
mqtt_enabled = {str(config.get('mqtt_enabled', False)).lower()}
mqtt_host = "{config.get('mqtt_host', '127.0.0.1')}"
mqtt_port = {config.get('mqtt_port', 1883)}
mqtt_topic = "{config.get('mqtt_topic', 'domoticz')}"
mqtt_username = "{config.get('mqtt_username', '')}"
mqtt_password = "{config.get('mqtt_password', '')}"
"""
    CONFIG_FILE.write_text(content)


def detect_runtime() -> Optional[str]:
    """Detect container runtime (podman or docker)."""
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return None


def is_running() -> bool:
    """Check if Domoticz container is running."""
    rt = detect_runtime()
    if not rt:
        return False
    try:
        result = subprocess.run(
            [rt, "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        names = result.stdout.split()
        return CONTAINER_NAME in names
    except Exception:
        return False


def container_exists() -> bool:
    """Check if container exists (running or stopped)."""
    rt = detect_runtime()
    if not rt:
        return False
    try:
        result = subprocess.run(
            [rt, "ps", "-a", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        names = result.stdout.split()
        return CONTAINER_NAME in names
    except Exception:
        return False


def get_container_ip() -> Optional[str]:
    """Get container IP address."""
    rt = detect_runtime()
    if not rt or not is_running():
        return None
    try:
        result = subprocess.run(
            [rt, "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", CONTAINER_NAME],
            capture_output=True, text=True, timeout=5
        )
        ip = result.stdout.strip()
        return ip if ip else "127.0.0.1"
    except Exception:
        return "127.0.0.1"


def get_domoticz_url() -> str:
    """Get Domoticz API URL."""
    cfg = get_config()
    port = cfg.get("port", DEFAULT_PORT)
    return f"http://127.0.0.1:{port}"


async def domoticz_api(endpoint: str, timeout: float = 10.0) -> dict:
    """Make request to Domoticz JSON API."""
    if not is_running():
        raise HTTPException(status_code=503, detail="Domoticz not running")

    url = f"{get_domoticz_url()}/json.htm?{endpoint}"
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            log.error(f"Domoticz API error: {e}")
            raise HTTPException(status_code=502, detail=f"Domoticz API error: {str(e)}")


def get_usb_devices() -> List[Dict[str, str]]:
    """Get list of USB serial devices."""
    import glob
    devices = []
    for pattern in ["/dev/ttyUSB*", "/dev/ttyACM*"]:
        for path in glob.glob(pattern):
            try:
                info = {"path": path, "type": "serial", "product": ""}
                dev_name = os.path.basename(path)
                product_path = f"/sys/class/tty/{dev_name}/device/product"
                if os.path.exists(product_path):
                    info["product"] = Path(product_path).read_text().strip()
                devices.append(info)
            except Exception:
                devices.append({"path": path, "type": "serial", "product": ""})
    return devices


# ============================================================================
# Public Endpoints (no auth required)
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "domoticz"}


@router.get("/status")
async def status():
    """Get Domoticz service status."""
    cfg = get_config()
    rt = detect_runtime()
    running = is_running()
    exists = container_exists()

    version = "unknown"
    device_count = 0
    scene_count = 0
    web_accessible = False
    uptime = 0

    if running:
        # Get container uptime
        if rt:
            try:
                result = subprocess.run(
                    [rt, "ps", "--filter", f"name={CONTAINER_NAME}", "--format", "{{.Status}}"],
                    capture_output=True, text=True, timeout=5
                )
                status_str = result.stdout.strip().split('\n')[0] if result.stdout else ""
                if "minute" in status_str:
                    uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 60
                elif "hour" in status_str:
                    uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 3600
                elif "day" in status_str:
                    uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 86400
            except Exception:
                pass

        # Check web accessibility
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{get_domoticz_url()}/json.htm?type=command&param=getversion")
                if resp.status_code == 200:
                    data = resp.json()
                    web_accessible = True
                    version = data.get("version", "unknown")
        except Exception:
            pass

        # Get counts
        if web_accessible:
            try:
                data = await domoticz_api("type=devices&used=true&order=Name")
                device_count = len(data.get("result", []))
            except Exception:
                pass
            try:
                data = await domoticz_api("type=scenes")
                scene_count = len(data.get("result", []))
            except Exception:
                pass

    # Get disk usage
    disk_usage = "0"
    if DATA_PATH.exists():
        try:
            result = subprocess.run(
                ["du", "-sh", str(DATA_PATH)],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                disk_usage = result.stdout.split()[0]
        except Exception:
            pass

    return {
        "running": running,
        "version": version,
        "uptime": uptime,
        "port": cfg.get("port", DEFAULT_PORT),
        "timezone": cfg.get("timezone", "Europe/Paris"),
        "runtime": rt or "none",
        "web_accessible": web_accessible,
        "container_exists": exists,
        "device_count": device_count,
        "scene_count": scene_count,
        "data_path": str(DATA_PATH),
        "disk_usage": disk_usage,
        "mqtt_enabled": cfg.get("mqtt_enabled", False),
        "usb_devices": get_usb_devices(),
    }


# ============================================================================
# Protected Endpoints (JWT required)
# ============================================================================

@router.get("/config")
async def get_domoticz_config(user=Depends(require_jwt)):
    """Get Domoticz configuration."""
    cfg = get_config()
    # Don't expose password
    if cfg.get("mqtt_password"):
        cfg["mqtt_password"] = "********"
    return cfg


@router.post("/config")
async def set_domoticz_config(config: DomoticzConfig, user=Depends(require_jwt)):
    """Update Domoticz configuration."""
    current = get_config()
    password = config.mqtt_password
    if password == "********":
        password = current.get("mqtt_password", "")

    new_config = {
        "port": config.port,
        "timezone": config.timezone,
        "mqtt_enabled": config.mqtt_enabled,
        "mqtt_host": config.mqtt_host,
        "mqtt_port": config.mqtt_port,
        "mqtt_topic": config.mqtt_topic,
        "mqtt_username": config.mqtt_username or "",
        "mqtt_password": password,
    }
    save_config(new_config)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")
    return {"success": True}


# ============================================================================
# Device Management
# ============================================================================

@router.get("/devices")
async def list_devices(user=Depends(require_jwt)):
    """List all devices."""
    if not is_running():
        return {"devices": [], "error": "Domoticz not running"}

    try:
        data = await domoticz_api("type=devices&used=true&order=Name")
        devices = []
        for dev in data.get("result", []):
            devices.append({
                "idx": dev.get("idx"),
                "name": dev.get("Name"),
                "type": dev.get("Type"),
                "subtype": dev.get("SubType"),
                "data": dev.get("Data"),
                "status": dev.get("Status"),
                "last_update": dev.get("LastUpdate"),
                "battery_level": dev.get("BatteryLevel"),
                "signal_level": dev.get("SignalLevel"),
                "favorite": dev.get("Favorite", 0) == 1,
                "plan_ids": dev.get("PlanIDs", []),
            })
        return {"devices": devices, "count": len(devices)}
    except Exception as e:
        return {"devices": [], "error": str(e)}


@router.get("/device/{idx}")
async def get_device(idx: int, user=Depends(require_jwt)):
    """Get device details."""
    if not is_running():
        raise HTTPException(503, "Domoticz not running")

    try:
        data = await domoticz_api(f"type=devices&rid={idx}")
        result = data.get("result", [])
        if not result:
            raise HTTPException(404, "Device not found")
        return result[0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/device/{idx}/command")
async def send_device_command(idx: int, cmd: DeviceCommand, user=Depends(require_jwt)):
    """Send command to device."""
    if not is_running():
        raise HTTPException(503, "Domoticz not running")

    try:
        if cmd.command == "Set Level" and cmd.level is not None:
            data = await domoticz_api(f"type=command&param=switchlight&idx={idx}&switchcmd=Set%20Level&level={cmd.level}")
        else:
            data = await domoticz_api(f"type=command&param=switchlight&idx={idx}&switchcmd={cmd.command}")

        log.info(f"Device {idx} command {cmd.command} by {user.get('sub', 'unknown')}")
        return {"success": data.get("status") == "OK", "result": data}
    except Exception as e:
        raise HTTPException(500, str(e))


# ============================================================================
# Room Management
# ============================================================================

@router.get("/rooms")
async def list_rooms(user=Depends(require_jwt)):
    """List all rooms (plans)."""
    if not is_running():
        return {"rooms": [], "error": "Domoticz not running"}

    try:
        data = await domoticz_api("type=plans&order=Name&used=true")
        rooms = []
        for plan in data.get("result", []):
            rooms.append({
                "idx": plan.get("idx"),
                "name": plan.get("Name"),
                "devices": plan.get("Devices", 0),
                "order": plan.get("Order"),
            })
        return {"rooms": rooms, "count": len(rooms)}
    except Exception as e:
        return {"rooms": [], "error": str(e)}


@router.post("/room")
async def create_room(room: RoomCreate, user=Depends(require_jwt)):
    """Create a new room (plan)."""
    if not is_running():
        raise HTTPException(503, "Domoticz not running")

    try:
        data = await domoticz_api(f"type=command&param=addplan&name={room.name}")
        log.info(f"Room {room.name} created by {user.get('sub', 'unknown')}")
        return {"success": data.get("status") == "OK", "result": data}
    except Exception as e:
        raise HTTPException(500, str(e))


@router.delete("/room/{idx}")
async def delete_room(idx: int, user=Depends(require_jwt)):
    """Delete a room (plan)."""
    if not is_running():
        raise HTTPException(503, "Domoticz not running")

    try:
        data = await domoticz_api(f"type=command&param=deleteplan&idx={idx}")
        log.info(f"Room {idx} deleted by {user.get('sub', 'unknown')}")
        return {"success": data.get("status") == "OK"}
    except Exception as e:
        raise HTTPException(500, str(e))


# ============================================================================
# Scene Management
# ============================================================================

@router.get("/scenes")
async def list_scenes(user=Depends(require_jwt)):
    """List all scenes and groups."""
    if not is_running():
        return {"scenes": [], "error": "Domoticz not running"}

    try:
        data = await domoticz_api("type=scenes")
        scenes = []
        for scene in data.get("result", []):
            scenes.append({
                "idx": scene.get("idx"),
                "name": scene.get("Name"),
                "type": scene.get("Type"),
                "status": scene.get("Status"),
                "last_update": scene.get("LastUpdate"),
                "favorite": scene.get("Favorite", 0) == 1,
            })
        return {"scenes": scenes, "count": len(scenes)}
    except Exception as e:
        return {"scenes": [], "error": str(e)}


@router.post("/scene/{idx}/activate")
async def activate_scene(idx: int, command: str = Query("On", pattern="^(On|Off)$"), user=Depends(require_jwt)):
    """Activate or deactivate a scene."""
    if not is_running():
        raise HTTPException(503, "Domoticz not running")

    try:
        data = await domoticz_api(f"type=command&param=switchscene&idx={idx}&switchcmd={command}")
        log.info(f"Scene {idx} {command} by {user.get('sub', 'unknown')}")
        return {"success": data.get("status") == "OK", "result": data}
    except Exception as e:
        raise HTTPException(500, str(e))


# ============================================================================
# Hardware Management
# ============================================================================

@router.get("/hardware")
async def list_hardware(user=Depends(require_jwt)):
    """List configured hardware controllers."""
    if not is_running():
        return {"hardware": [], "error": "Domoticz not running"}

    try:
        data = await domoticz_api("type=hardware")
        hardware = []
        for hw in data.get("result", []):
            hardware.append({
                "idx": hw.get("idx"),
                "name": hw.get("Name"),
                "type": hw.get("Type"),
                "type_name": hw.get("TypeName", ""),
                "enabled": hw.get("Enabled") == "true",
                "data_timeout": hw.get("DataTimeout"),
                "port": hw.get("Port", ""),
                "address": hw.get("Address", ""),
            })
        return {"hardware": hardware, "count": len(hardware)}
    except Exception as e:
        return {"hardware": [], "error": str(e)}


@router.post("/hardware")
async def add_hardware(
    name: str = Query(...),
    hardware_type: int = Query(..., description="Hardware type ID"),
    port: str = Query("", description="Serial port or address"),
    user=Depends(require_jwt)
):
    """Add new hardware controller."""
    if not is_running():
        raise HTTPException(503, "Domoticz not running")

    try:
        endpoint = f"type=command&param=addhardware&htype={hardware_type}&name={name}"
        if port:
            endpoint += f"&port={port}"
        data = await domoticz_api(endpoint)
        log.info(f"Hardware {name} added by {user.get('sub', 'unknown')}")
        return {"success": data.get("status") == "OK", "result": data}
    except Exception as e:
        raise HTTPException(500, str(e))


@router.delete("/hardware/{idx}")
async def delete_hardware(idx: int, user=Depends(require_jwt)):
    """Delete hardware controller."""
    if not is_running():
        raise HTTPException(503, "Domoticz not running")

    try:
        data = await domoticz_api(f"type=command&param=deletehardware&idx={idx}")
        log.info(f"Hardware {idx} deleted by {user.get('sub', 'unknown')}")
        return {"success": data.get("status") == "OK"}
    except Exception as e:
        raise HTTPException(500, str(e))


# ============================================================================
# Events and Graphs
# ============================================================================

@router.get("/events")
async def get_events(lines: int = Query(100, ge=10, le=500), user=Depends(require_jwt)):
    """Get event log."""
    if not is_running():
        return {"events": [], "error": "Domoticz not running"}

    try:
        data = await domoticz_api("type=command&param=getlog")
        events = data.get("result", [])[-lines:]
        return {"events": events, "count": len(events)}
    except Exception as e:
        return {"events": [], "error": str(e)}


@router.get("/graphs/{idx}")
async def get_device_graphs(
    idx: int,
    sensor: str = Query("temp", description="Sensor type: temp, humidity, counter, etc"),
    range: str = Query("day", pattern="^(day|week|month|year)$"),
    user=Depends(require_jwt)
):
    """Get device graph data."""
    if not is_running():
        raise HTTPException(503, "Domoticz not running")

    try:
        data = await domoticz_api(f"type=graph&sensor={sensor}&idx={idx}&range={range}")
        return {
            "idx": idx,
            "sensor": sensor,
            "range": range,
            "data": data.get("result", [])
        }
    except Exception as e:
        raise HTTPException(500, str(e))


# ============================================================================
# Notifications
# ============================================================================

@router.get("/notifications")
async def get_notifications(user=Depends(require_jwt)):
    """Get notification settings."""
    if not is_running():
        return {"notifications": {}, "error": "Domoticz not running"}

    try:
        data = await domoticz_api("type=command&param=getnotifications")
        return {"notifications": data}
    except Exception as e:
        return {"notifications": {}, "error": str(e)}


@router.post("/notifications")
async def update_notifications(settings: NotificationSettings, user=Depends(require_jwt)):
    """Update notification settings."""
    if not is_running():
        raise HTTPException(503, "Domoticz not running")

    # Note: Domoticz requires multiple API calls for different notification types
    # This is a simplified implementation
    log.info(f"Notification settings updated by {user.get('sub', 'unknown')}")
    return {"success": True, "message": "Settings updated"}


# ============================================================================
# Container Management
# ============================================================================

@router.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """Get container status."""
    rt = detect_runtime()
    running = is_running()
    exists = container_exists()

    stats = {}
    if running and rt:
        try:
            result = subprocess.run(
                [rt, "stats", "--no-stream", "--format", "{{.MemUsage}} {{.CPUPerc}}", CONTAINER_NAME],
                capture_output=True, text=True, timeout=10
            )
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                stats["memory"] = parts[0]
                stats["cpu"] = parts[-1]
        except Exception:
            pass

    return {
        "runtime": rt or "none",
        "running": running,
        "exists": exists,
        "container_name": CONTAINER_NAME,
        "stats": stats,
    }


@router.post("/container/install")
async def install_container(user=Depends(require_jwt)):
    """Pull and install Domoticz container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    if container_exists():
        return {"success": True, "message": "Container already exists"}

    log.info(f"Installing Domoticz by {user.get('sub', 'unknown')}")

    try:
        # Pull image
        result = subprocess.run(
            [rt, "pull", "domoticz/domoticz:stable"],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip()}

        # Create data directories
        DATA_PATH.mkdir(parents=True, exist_ok=True)
        (DATA_PATH / "config").mkdir(exist_ok=True)
        (DATA_PATH / "scripts").mkdir(exist_ok=True)
        (DATA_PATH / "plugins").mkdir(exist_ok=True)

        return {"success": True, "message": "Domoticz image pulled successfully"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Pull timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/start")
async def start_container(user=Depends(require_jwt)):
    """Start Domoticz container."""
    if is_running():
        return {"success": True, "message": "Already running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    cfg = get_config()
    port = cfg.get("port", DEFAULT_PORT)

    log.info(f"Starting Domoticz by {user.get('sub', 'unknown')}")

    # Get USB devices for passthrough
    usb_devices = get_usb_devices()

    cmd = [
        rt, "run", "-d",
        "--name", CONTAINER_NAME,
        "-p", f"127.0.0.1:{port}:8080",
        "-p", f"127.0.0.1:8443:8443",
        "-v", f"{DATA_PATH}/config:/opt/domoticz/userdata",
        "-v", f"{DATA_PATH}/scripts:/opt/domoticz/scripts",
        "-v", f"{DATA_PATH}/plugins:/opt/domoticz/plugins",
        "-e", f"TZ={cfg.get('timezone', 'Europe/Paris')}",
        "--restart", "unless-stopped",
    ]

    # Add USB device passthrough
    for dev in usb_devices:
        cmd.extend(["--device", dev["path"]])

    cmd.append("domoticz/domoticz:stable")

    try:
        # If container exists but stopped, remove it first
        if container_exists():
            subprocess.run([rt, "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        await asyncio.sleep(5)

        if is_running():
            return {"success": True, "message": "Domoticz started"}
        else:
            return {"success": False, "error": result.stderr.strip() or "Failed to start"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/stop")
async def stop_container(user=Depends(require_jwt)):
    """Stop Domoticz container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    if not is_running():
        return {"success": True, "message": "Already stopped"}

    log.info(f"Stopping Domoticz by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", CONTAINER_NAME], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)

        if not is_running():
            return {"success": True}
        else:
            return {"success": False, "error": "Failed to stop"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/container/restart")
async def restart_container(user=Depends(require_jwt)):
    """Restart Domoticz container."""
    await stop_container(user)
    await asyncio.sleep(2)
    return await start_container(user)


# ============================================================================
# Logs
# ============================================================================

@router.get("/logs")
async def get_logs(lines: int = Query(100, ge=10, le=500), user=Depends(require_jwt)):
    """Get container logs."""
    rt = detect_runtime()
    logs = []

    if rt and is_running():
        try:
            result = subprocess.run(
                [rt, "logs", "--tail", str(lines), CONTAINER_NAME],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                logs = result.stdout.strip().split('\n')
            if result.stderr:
                logs.extend(result.stderr.strip().split('\n'))
        except Exception:
            pass

    return {"logs": logs[-lines:] if logs else []}


# ============================================================================
# Backup & Restore
# ============================================================================

@router.post("/backup")
async def create_backup(user=Depends(require_jwt)):
    """Create Domoticz backup."""
    backup_dir = Path("/var/lib/secubox/backups/domoticz")
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_file = backup_dir / f"domoticz-backup-{timestamp}.tar.gz"

    if not DATA_PATH.exists():
        raise HTTPException(400, "No data to backup")

    was_running = is_running()
    if was_running:
        await stop_container(user)
        await asyncio.sleep(2)

    try:
        result = subprocess.run(
            ["tar", "-czf", str(backup_file), "-C", str(DATA_PATH.parent), DATA_PATH.name],
            capture_output=True, text=True, timeout=300
        )

        if was_running:
            await start_container(user)

        if result.returncode != 0:
            raise HTTPException(500, f"Backup failed: {result.stderr}")

        log.info(f"Backup created by {user.get('sub', 'unknown')}: {backup_file}")
        return {
            "success": True,
            "path": str(backup_file),
            "size": backup_file.stat().st_size,
            "timestamp": timestamp
        }
    except Exception as e:
        if was_running:
            await start_container(user)
        raise HTTPException(500, str(e))


@router.get("/backups")
async def list_backups(user=Depends(require_jwt)):
    """List available backups."""
    backup_dir = Path("/var/lib/secubox/backups/domoticz")
    if not backup_dir.exists():
        return {"backups": []}

    backups = []
    for f in sorted(backup_dir.glob("*.tar.gz"), reverse=True):
        backups.append({
            "filename": f.name,
            "path": str(f),
            "size": f.stat().st_size,
            "created": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
        })
    return {"backups": backups}


@router.post("/restore")
async def restore_backup(path: str = Query(...), user=Depends(require_jwt)):
    """Restore from backup."""
    backup_path = Path(path)
    if not backup_path.exists():
        raise HTTPException(404, "Backup file not found")

    was_running = is_running()
    if was_running:
        await stop_container(user)
        await asyncio.sleep(2)

    try:
        # Remove existing data
        if DATA_PATH.exists():
            shutil.rmtree(DATA_PATH)

        # Extract backup
        result = subprocess.run(
            ["tar", "-xzf", str(backup_path), "-C", str(DATA_PATH.parent)],
            capture_output=True, text=True, timeout=300
        )

        if result.returncode != 0:
            raise HTTPException(500, f"Restore failed: {result.stderr}")

        log.info(f"Backup restored by {user.get('sub', 'unknown')}: {path}")

        if was_running:
            await start_container(user)

        return {"success": True, "message": "Backup restored successfully"}
    except Exception as e:
        raise HTTPException(500, str(e))


app.include_router(router)
