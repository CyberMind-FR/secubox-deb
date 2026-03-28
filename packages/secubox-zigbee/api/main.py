"""secubox-zigbee — FastAPI application for Zigbee2MQTT Gateway.

Ported from OpenWRT luci-app-zigbee2mqtt RPCD backend.
Provides Zigbee2MQTT container management and API proxy.
"""
import asyncio
import shutil
import subprocess
import glob
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
import httpx

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-zigbee", version="1.0.0", root_path="/api/v1/zigbee")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("zigbee")

# Configuration
CONFIG_FILE = Path("/etc/secubox/zigbee.toml")
DATA_PATH = Path("/srv/zigbee2mqtt")
DEFAULT_CONFIG = {
    "serial_port": "/dev/ttyUSB0",
    "mqtt_host": "mqtt://127.0.0.1:1883",
    "mqtt_username": "",
    "mqtt_password": "",
    "base_topic": "zigbee2mqtt",
    "frontend_port": 8099,
    "channel": 11,
    "permit_join": False,
}


# ============================================================================
# Models
# ============================================================================

class ZigbeeConfig(BaseModel):
    serial_port: str = "/dev/ttyUSB0"
    mqtt_host: str = "mqtt://127.0.0.1:1883"
    mqtt_username: Optional[str] = ""
    mqtt_password: Optional[str] = ""
    base_topic: str = "zigbee2mqtt"
    frontend_port: int = 8099
    channel: int = 11
    permit_join: bool = False


class PermitJoinRequest(BaseModel):
    permit: bool
    duration: int = 254  # seconds (254 = until disabled)


class DeviceRenameRequest(BaseModel):
    old_name: str
    new_name: str


class DeviceRemoveRequest(BaseModel):
    device: str
    force: bool = False


# ============================================================================
# Helpers
# ============================================================================

def get_config() -> dict:
    """Load zigbee configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def detect_runtime() -> Optional[str]:
    """Detect container runtime (podman or docker)."""
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return None


def is_running() -> bool:
    """Check if Zigbee2MQTT container is running."""
    rt = detect_runtime()
    if not rt:
        return False
    try:
        result = subprocess.run(
            [rt, "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        names = result.stdout.split()
        return "zigbee2mqtt" in names or "z2m" in names
    except Exception:
        return False


def get_container_name() -> str:
    """Get actual container name."""
    rt = detect_runtime()
    if not rt:
        return "zigbee2mqtt"
    try:
        result = subprocess.run(
            [rt, "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5
        )
        for name in result.stdout.split():
            if "zigbee" in name.lower() or "z2m" in name.lower():
                return name
    except Exception:
        pass
    return "zigbee2mqtt"


def detect_serial_devices() -> List[dict]:
    """Detect available USB serial devices."""
    devices = []

    # Check /dev/ttyUSB* and /dev/ttyACM*
    for pattern in ["/dev/ttyUSB*", "/dev/ttyACM*"]:
        for path in glob.glob(pattern):
            dev_info = {"path": path, "type": "unknown", "vendor": "", "product": ""}

            # Try to get USB device info
            try:
                # Get the sysfs path
                real_path = Path(path).resolve()
                dev_name = real_path.name

                # Find USB device info in sysfs
                for usb_path in Path("/sys/bus/usb/devices").glob("*"):
                    product_file = usb_path / "product"
                    if product_file.exists():
                        product = product_file.read_text().strip()
                        vendor_file = usb_path / "idVendor"
                        vendor_id = vendor_file.read_text().strip() if vendor_file.exists() else ""

                        # Check if this is a Zigbee dongle
                        if vendor_id in ["10c4", "1a86", "0451"]:  # CP210x, CH340, TI
                            dev_info["product"] = product
                            dev_info["vendor"] = vendor_id
                            if "10c4" in vendor_id:
                                dev_info["type"] = "cp210x"
                            elif "1a86" in vendor_id:
                                dev_info["type"] = "ch340"
                            break
            except Exception:
                pass

            devices.append(dev_info)

    return devices


def get_z2m_api_url() -> str:
    """Get Zigbee2MQTT API URL."""
    cfg = get_config()
    port = cfg.get("frontend_port", 8099)
    return f"http://127.0.0.1:{port}/api"


async def z2m_api_request(endpoint: str, method: str = "GET", json_data: dict = None) -> dict:
    """Make request to Zigbee2MQTT API."""
    url = f"{get_z2m_api_url()}/{endpoint}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        if method == "GET":
            resp = await client.get(url)
        else:
            resp = await client.post(url, json=json_data or {})
        resp.raise_for_status()
        return resp.json()


# ============================================================================
# Public Endpoints (no auth required)
# ============================================================================

@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "module": "zigbee"}


@router.get("/status")
async def status():
    """Get Zigbee2MQTT service status."""
    cfg = get_config()
    rt = detect_runtime()
    running = is_running()

    serial_port = cfg.get("serial_port", "/dev/ttyUSB0")
    serial_device_exists = Path(serial_port).exists()

    uptime = 0
    version = "unknown"
    coordinator = {}
    device_count = 0
    web_accessible = False

    if running:
        container = get_container_name()

        # Get uptime
        if rt:
            try:
                result = subprocess.run(
                    [rt, "ps", "--filter", f"name={container}", "--format", "{{.Status}}"],
                    capture_output=True, text=True, timeout=5
                )
                status_str = result.stdout.strip().split('\n')[0] if result.stdout else ""
                if "minute" in status_str:
                    uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 60
                elif "hour" in status_str:
                    uptime = int(''.join(filter(str.isdigit, status_str.split()[1]))) * 3600
            except Exception:
                pass

        # Check web accessibility and get stats
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"http://127.0.0.1:{cfg.get('frontend_port', 8099)}/")
                web_accessible = resp.status_code == 200

            if web_accessible:
                try:
                    bridge_info = await z2m_api_request("bridge")
                    version = bridge_info.get("version", "unknown")
                    coordinator = bridge_info.get("coordinator", {})
                except Exception:
                    pass

                try:
                    devices = await z2m_api_request("devices")
                    device_count = len(devices) if isinstance(devices, list) else 0
                except Exception:
                    pass
        except Exception:
            pass

    return {
        "running": running,
        "uptime": uptime,
        "version": version,
        "serial_port": serial_port,
        "serial_device_exists": serial_device_exists,
        "mqtt_host": cfg.get("mqtt_host", "mqtt://127.0.0.1:1883"),
        "base_topic": cfg.get("base_topic", "zigbee2mqtt"),
        "frontend_port": cfg.get("frontend_port", 8099),
        "channel": cfg.get("channel", 11),
        "permit_join": cfg.get("permit_join", False),
        "runtime": rt or "none",
        "web_accessible": web_accessible,
        "device_count": device_count,
        "coordinator": coordinator,
    }


# ============================================================================
# Protected Endpoints (JWT required)
# ============================================================================

@router.get("/config")
async def get_zigbee_config(user=Depends(require_jwt)):
    """Get Zigbee2MQTT configuration."""
    cfg = get_config()
    # Don't expose password
    cfg_safe = cfg.copy()
    if cfg_safe.get("mqtt_password"):
        cfg_safe["mqtt_password"] = "********"
    return cfg_safe


@router.post("/config")
async def set_zigbee_config(config: ZigbeeConfig, user=Depends(require_jwt)):
    """Update Zigbee2MQTT configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Get current config to preserve password if not changed
    current = get_config()
    password = config.mqtt_password
    if password == "********":
        password = current.get("mqtt_password", "")

    content = f"""# Zigbee2MQTT configuration
serial_port = "{config.serial_port}"
mqtt_host = "{config.mqtt_host}"
mqtt_username = "{config.mqtt_username or ''}"
mqtt_password = "{password}"
base_topic = "{config.base_topic}"
frontend_port = {config.frontend_port}
channel = {config.channel}
permit_join = {str(config.permit_join).lower()}
"""
    CONFIG_FILE.write_text(content)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")

    # Regenerate Z2M configuration.yaml
    await generate_z2m_config()

    return {"success": True}


async def generate_z2m_config():
    """Generate Zigbee2MQTT configuration.yaml file."""
    cfg = get_config()
    config_dir = DATA_PATH / "data"
    config_dir.mkdir(parents=True, exist_ok=True)

    serial_port = cfg.get("serial_port", "/dev/ttyUSB0")

    config_yaml = f"""# Zigbee2MQTT configuration - Auto-generated by SecuBox
homeassistant:
  enabled: false

permit_join: {str(cfg.get('permit_join', False)).lower()}

mqtt:
  base_topic: {cfg.get('base_topic', 'zigbee2mqtt')}
  server: {cfg.get('mqtt_host', 'mqtt://127.0.0.1:1883')}
"""

    if cfg.get("mqtt_username"):
        config_yaml += f"  user: {cfg['mqtt_username']}\n"
    if cfg.get("mqtt_password"):
        config_yaml += f"  password: {cfg['mqtt_password']}\n"

    config_yaml += f"""
serial:
  port: /dev/ttyUSB0

advanced:
  channel: {cfg.get('channel', 11)}
  log_level: info

frontend:
  enabled: true
  port: {cfg.get('frontend_port', 8099)}
  host: 0.0.0.0
"""

    config_file = config_dir / "configuration.yaml"
    config_file.write_text(config_yaml)
    config_file.chmod(0o600)


@router.get("/devices")
async def get_devices(user=Depends(require_jwt)):
    """Get list of paired Zigbee devices."""
    if not is_running():
        return {"devices": [], "error": "Zigbee2MQTT not running"}

    try:
        devices = await z2m_api_request("devices")
        return {"devices": devices if isinstance(devices, list) else []}
    except Exception as e:
        log.error(f"Failed to get devices: {e}")
        return {"devices": [], "error": str(e)}


@router.get("/devices/{device_id}")
async def get_device(device_id: str, user=Depends(require_jwt)):
    """Get device details."""
    if not is_running():
        raise HTTPException(503, "Zigbee2MQTT not running")

    try:
        devices = await z2m_api_request("devices")
        for dev in devices:
            if dev.get("ieee_address") == device_id or dev.get("friendly_name") == device_id:
                return dev
        raise HTTPException(404, "Device not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/devices/rename")
async def rename_device(req: DeviceRenameRequest, user=Depends(require_jwt)):
    """Rename a device."""
    if not is_running():
        raise HTTPException(503, "Zigbee2MQTT not running")

    try:
        await z2m_api_request(f"device/{req.old_name}/rename", "POST", {"new_name": req.new_name})
        log.info(f"Device {req.old_name} renamed to {req.new_name} by {user.get('sub', 'unknown')}")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.delete("/devices/{device_id}")
async def remove_device(device_id: str, force: bool = False, user=Depends(require_jwt)):
    """Remove a device from the network."""
    if not is_running():
        raise HTTPException(503, "Zigbee2MQTT not running")

    try:
        endpoint = f"device/{device_id}/remove"
        if force:
            endpoint += "?force=true"
        await z2m_api_request(endpoint, "POST")
        log.info(f"Device {device_id} removed by {user.get('sub', 'unknown')}")
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/network")
async def get_network(user=Depends(require_jwt)):
    """Get network map/topology."""
    if not is_running():
        return {"map": None, "error": "Zigbee2MQTT not running"}

    try:
        network = await z2m_api_request("networkmap")
        return {"map": network}
    except Exception as e:
        return {"map": None, "error": str(e)}


@router.post("/permit_join")
async def set_permit_join(req: PermitJoinRequest, user=Depends(require_jwt)):
    """Enable/disable device pairing."""
    if not is_running():
        raise HTTPException(503, "Zigbee2MQTT not running")

    try:
        await z2m_api_request("bridge/permit_join", "POST", {
            "value": req.permit,
            "time": req.duration if req.permit else 0
        })
        log.info(f"Permit join {'enabled' if req.permit else 'disabled'} by {user.get('sub', 'unknown')}")
        return {"success": True, "permit_join": req.permit}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/serial_devices")
async def list_serial_devices(user=Depends(require_jwt)):
    """List available USB serial devices."""
    devices = detect_serial_devices()
    return {"devices": devices}


@router.get("/diagnostics")
async def get_diagnostics(user=Depends(require_jwt)):
    """Get system diagnostics for Zigbee2MQTT."""
    cfg = get_config()
    serial_port = cfg.get("serial_port", "/dev/ttyUSB0")

    # Check kernel modules
    cp210x_loaded = False
    ch341_loaded = False
    try:
        with open("/proc/modules") as f:
            modules = f.read()
            cp210x_loaded = "cp210x" in modules
            ch341_loaded = "ch341" in modules
    except Exception:
        pass

    # Check serial device
    serial_exists = Path(serial_port).exists()
    serial_mode = ""
    if serial_exists:
        try:
            import stat
            mode = Path(serial_port).stat().st_mode
            serial_mode = oct(stat.S_IMODE(mode))
        except Exception:
            pass

    # Check container runtime
    rt = detect_runtime()

    # Check MQTT
    mqtt_available = False
    mqtt_host = cfg.get("mqtt_host", "mqtt://127.0.0.1:1883")
    try:
        # Extract host:port from mqtt://host:port
        import re
        match = re.match(r"mqtt://([^:]+):(\d+)", mqtt_host)
        if match:
            host, port = match.groups()
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, int(port)))
            mqtt_available = result == 0
            sock.close()
    except Exception:
        pass

    return {
        "serial": {
            "port": serial_port,
            "exists": serial_exists,
            "mode": serial_mode,
        },
        "kernel_modules": {
            "cp210x": cp210x_loaded,
            "ch341": ch341_loaded,
        },
        "runtime": rt or "none",
        "container_exists": is_running() or Path(DATA_PATH / "data").exists(),
        "mqtt_available": mqtt_available,
        "detected_devices": detect_serial_devices(),
    }


@router.get("/system")
async def system_info(user=Depends(require_jwt)):
    """Get system resource info."""
    cfg = get_config()
    rt = detect_runtime()

    mem_total = mem_used = mem_pct = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    mem_free = int(line.split()[1])
                    mem_used = mem_total - mem_free
                    mem_pct = (mem_used * 100) // mem_total if mem_total else 0
    except Exception:
        pass

    container_mem = "0"
    container_cpu = "0%"
    if is_running() and rt:
        container = get_container_name()
        try:
            result = subprocess.run(
                [rt, "stats", "--no-stream", "--format", "{{.MemUsage}} {{.CPUPerc}}", container],
                capture_output=True, text=True, timeout=5
            )
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                container_mem = parts[0]
                container_cpu = parts[-1]
        except Exception:
            pass

    return {
        "memory": {
            "total_kb": mem_total,
            "used_kb": mem_used,
            "percent": mem_pct,
        },
        "container": {
            "memory": container_mem,
            "cpu": container_cpu,
        },
    }


@router.get("/logs")
async def get_logs(lines: int = 100, user=Depends(require_jwt)):
    """Get recent logs."""
    rt = detect_runtime()
    logs = []

    # Try container logs first
    if rt and is_running():
        container = get_container_name()
        try:
            result = subprocess.run(
                [rt, "logs", "--tail", str(lines), container],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                logs = result.stdout.strip().split('\n')
            if result.stderr:
                logs.extend(result.stderr.strip().split('\n'))
        except Exception:
            pass

    # Fallback to log file
    if not logs:
        log_file = DATA_PATH / "data" / "log" / "zigbee2mqtt.log"
        if log_file.exists():
            try:
                with open(log_file) as f:
                    all_lines = f.readlines()
                    logs = [l.strip() for l in all_lines[-lines:]]
            except Exception:
                pass

    return {"logs": logs[-lines:] if logs else []}


# ============================================================================
# Service Control
# ============================================================================

@router.post("/install")
async def install_service(user=Depends(require_jwt)):
    """Pull Zigbee2MQTT container image."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    log.info(f"Installing Zigbee2MQTT by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "pull", "koenkk/zigbee2mqtt:latest"],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode == 0:
            # Generate initial config
            await generate_z2m_config()
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Pull timeout"}


@router.post("/start")
async def start_service(user=Depends(require_jwt)):
    """Start Zigbee2MQTT container."""
    if is_running():
        return {"success": False, "error": "Already running"}

    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime (docker/podman) found"}

    cfg = get_config()
    serial_port = cfg.get("serial_port", "/dev/ttyUSB0")

    # Check serial device
    if not Path(serial_port).exists():
        return {"success": False, "error": f"Serial device {serial_port} not found"}

    # Ensure data directory and config
    DATA_PATH.mkdir(parents=True, exist_ok=True)
    (DATA_PATH / "data").mkdir(exist_ok=True)
    await generate_z2m_config()

    cmd = [
        rt, "run", "-d",
        "--name", "zigbee2mqtt",
        "--device", f"{serial_port}:/dev/ttyUSB0",
        "-v", f"{DATA_PATH}/data:/app/data",
        "-p", f"127.0.0.1:{cfg.get('frontend_port', 8099)}:8080",
        "-e", "TZ=UTC",
        "--restart", "unless-stopped",
        "koenkk/zigbee2mqtt:latest",
    ]

    log.info(f"Starting Zigbee2MQTT by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        await asyncio.sleep(5)  # Z2M takes time to initialize

        if is_running():
            return {"success": True}
        else:
            return {"success": False, "error": result.stderr.strip() or "Failed to start"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Start timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/stop")
async def stop_service(user=Depends(require_jwt)):
    """Stop Zigbee2MQTT container."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    container = get_container_name()
    log.info(f"Stopping Zigbee2MQTT by {user.get('sub', 'unknown')}")

    try:
        subprocess.run([rt, "stop", container], capture_output=True, timeout=30)
        subprocess.run([rt, "rm", "-f", container], capture_output=True, timeout=10)

        if not is_running():
            return {"success": True}
        else:
            return {"success": False, "error": "Failed to stop"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/restart")
async def restart_service(user=Depends(require_jwt)):
    """Restart Zigbee2MQTT container."""
    await stop_service(user)
    await asyncio.sleep(2)
    return await start_service(user)


@router.post("/update")
async def update_service(user=Depends(require_jwt)):
    """Update Zigbee2MQTT to latest version."""
    rt = detect_runtime()
    if not rt:
        return {"success": False, "error": "No container runtime"}

    was_running = is_running()

    if was_running:
        await stop_service(user)
        await asyncio.sleep(2)

    log.info(f"Updating Zigbee2MQTT by {user.get('sub', 'unknown')}")

    try:
        result = subprocess.run(
            [rt, "pull", "koenkk/zigbee2mqtt:latest"],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode != 0:
            return {"success": False, "error": result.stderr.strip()}

        if was_running:
            await start_service(user)

        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


app.include_router(router)
