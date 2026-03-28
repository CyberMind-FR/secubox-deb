"""SecuBox Domoticz - Home Automation System
LXC container-based home automation with MQTT and Zigbee integration.

Features:
- LXC container management
- MQTT broker integration (Mosquitto)
- Zigbee2MQTT device bridge
- USB device passthrough
- Backup and restore
- HAProxy integration for external access
"""
import os
import json
import asyncio
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import require_jwt

# Configuration
CONFIG_FILE = Path("/etc/secubox/domoticz.json")
DATA_DIR = Path("/srv/domoticz")
LXC_NAME = "domoticz"
DEFAULT_PORT = 8084
LXC_ROOT = Path("/var/lib/lxc")

# Domoticz version to install
DOMOTICZ_VERSION = "2024.6"

app = FastAPI(title="SecuBox Domoticz", version="1.0.0")


class MQTTConfig(BaseModel):
    enabled: bool = False
    broker: str = "127.0.0.1"
    broker_port: int = 1883
    topic_prefix: str = "domoticz"
    z2m_topic: str = "zigbee2mqtt"
    username: Optional[str] = None
    password: Optional[str] = None


class ConfigUpdate(BaseModel):
    port: int = 8084
    timezone: str = "UTC"
    mqtt: Optional[MQTTConfig] = None


def load_config() -> dict:
    """Load configuration from file."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return {
        "port": DEFAULT_PORT,
        "timezone": "UTC",
        "mqtt": {
            "enabled": False,
            "broker": "127.0.0.1",
            "broker_port": 1883,
            "topic_prefix": "domoticz",
            "z2m_topic": "zigbee2mqtt"
        }
    }


def save_config(config: dict):
    """Save configuration to file."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def lxc_exists() -> bool:
    """Check if LXC container exists."""
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def lxc_running() -> bool:
    """Check if LXC container is running."""
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME, "-s"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return "RUNNING" in result.stdout
    except Exception:
        return False


def lxc_get_ip() -> Optional[str]:
    """Get LXC container IP address."""
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME, "-iH"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            ips = result.stdout.strip().split("\n")
            for ip in ips:
                if ip and not ip.startswith("127."):
                    return ip.strip()
        return None
    except Exception:
        return None


def lxc_exec(cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """Execute command inside LXC container."""
    return subprocess.run(
        ["lxc-attach", "-n", LXC_NAME, "--"] + cmd,
        capture_output=True,
        text=True,
        timeout=timeout
    )


def get_usb_devices() -> List[Dict[str, str]]:
    """Get list of USB serial devices."""
    devices = []
    for pattern in ["/dev/ttyUSB*", "/dev/ttyACM*"]:
        import glob
        for path in glob.glob(pattern):
            try:
                info = {"path": path, "type": "serial"}
                dev_name = os.path.basename(path)
                product_path = f"/sys/class/tty/{dev_name}/device/product"
                if os.path.exists(product_path):
                    info["product"] = Path(product_path).read_text().strip()
                devices.append(info)
            except Exception:
                devices.append({"path": path, "type": "serial"})
    return devices


def check_mosquitto_status() -> str:
    """Check Mosquitto MQTT broker status."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "mosquitto"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.stdout.strip() == "active":
            return "running"
        return "stopped"
    except Exception:
        try:
            result = subprocess.run(["pgrep", "mosquitto"], capture_output=True, timeout=5)
            return "running" if result.returncode == 0 else "stopped"
        except Exception:
            return "unknown"


async def domoticz_api(endpoint: str, timeout: float = 10.0) -> dict:
    """Make request to Domoticz API."""
    ip = lxc_get_ip()
    if not ip:
        raise HTTPException(status_code=502, detail="Container IP not available")

    url = f"http://{ip}:8080/json.htm?{endpoint}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.get(url)
            return response.json()
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Domoticz API error: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "module": "domoticz"}


@app.get("/status", dependencies=[Depends(require_jwt)])
async def get_status():
    """Get Domoticz service status."""
    config = load_config()
    running = lxc_running()
    exists = lxc_exists()
    ip = lxc_get_ip() if running else None

    # Check web accessibility
    web_accessible = False
    version = "unknown"
    if running and ip:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"http://{ip}:8080/json.htm?type=command&param=getversion")
                if resp.status_code == 200:
                    data = resp.json()
                    web_accessible = True
                    version = data.get("version", "unknown")
        except Exception:
            pass

    # Get disk usage
    disk_usage = "0"
    lxc_path = LXC_ROOT / LXC_NAME
    if lxc_path.exists():
        try:
            result = subprocess.run(
                ["du", "-sh", str(lxc_path)],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                disk_usage = result.stdout.split()[0]
        except Exception:
            pass

    return {
        "running": running,
        "version": version,
        "port": config.get("port", DEFAULT_PORT),
        "timezone": config.get("timezone", "UTC"),
        "runtime": "lxc",
        "web_accessible": web_accessible,
        "container_exists": exists,
        "container_ip": ip,
        "data_path": str(LXC_ROOT / LXC_NAME),
        "disk_usage": disk_usage,
        "usb_devices": get_usb_devices(),
        "mosquitto_status": check_mosquitto_status(),
        "mqtt": config.get("mqtt", {})
    }


@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config():
    """Get Domoticz configuration."""
    return load_config()


@app.post("/config", dependencies=[Depends(require_jwt)])
async def update_config(config: ConfigUpdate):
    """Update Domoticz configuration."""
    current = load_config()
    current["port"] = config.port
    current["timezone"] = config.timezone
    if config.mqtt:
        current["mqtt"] = config.mqtt.dict()
    save_config(current)
    return {"success": True, "config": current}


@app.post("/start", dependencies=[Depends(require_jwt)])
async def start_service():
    """Start Domoticz LXC container."""
    if not lxc_exists():
        raise HTTPException(status_code=400, detail="Container not created. Run /install first.")

    if lxc_running():
        return {"success": True, "message": "Already running"}

    try:
        result = subprocess.run(
            ["lxc-start", "-n", LXC_NAME],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Failed to start: {result.stderr}")

        # Wait for container to get IP
        for _ in range(30):
            await asyncio.sleep(1)
            if lxc_get_ip():
                break

        return {"success": True, "message": "Domoticz started", "ip": lxc_get_ip()}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Start timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop_service():
    """Stop Domoticz LXC container."""
    if not lxc_running():
        return {"success": True, "message": "Already stopped"}

    try:
        subprocess.run(["lxc-stop", "-n", LXC_NAME], capture_output=True, timeout=30)
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart_service():
    """Restart Domoticz container."""
    await stop_service()
    await asyncio.sleep(2)
    return await start_service()


@app.post("/install", dependencies=[Depends(require_jwt)])
async def install_domoticz():
    """Create and setup Domoticz LXC container."""
    if lxc_exists():
        return {"success": True, "message": "Container already exists"}

    config = load_config()

    try:
        # Create Debian bookworm container
        result = subprocess.run(
            [
                "lxc-create", "-n", LXC_NAME,
                "-t", "download",
                "--",
                "-d", "debian",
                "-r", "bookworm",
                "-a", "amd64"
            ],
            capture_output=True,
            text=True,
            timeout=600
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Create failed: {result.stderr}")

        # Configure container for autostart
        lxc_config = LXC_ROOT / LXC_NAME / "config"
        with open(lxc_config, "a") as f:
            f.write("\n# SecuBox Domoticz config\n")
            f.write("lxc.start.auto = 1\n")
            # USB passthrough for Zigbee/Z-Wave
            for dev in get_usb_devices():
                f.write(f"lxc.mount.entry = {dev['path']} {dev['path'][1:]} none bind,create=file 0 0\n")
            f.write(f"lxc.cgroup2.devices.allow = c 188:* rwm\n")  # ttyUSB
            f.write(f"lxc.cgroup2.devices.allow = c 166:* rwm\n")  # ttyACM

        # Start container
        subprocess.run(["lxc-start", "-n", LXC_NAME], capture_output=True, timeout=60)
        await asyncio.sleep(5)

        # Wait for network
        for _ in range(30):
            if lxc_get_ip():
                break
            await asyncio.sleep(1)

        # Install Domoticz
        install_script = """
apt-get update && apt-get install -y curl gnupg ca-certificates
curl -sSL https://releases.domoticz.com/gpg.key | apt-key add -
echo 'deb https://releases.domoticz.com/releases/ stable main' > /etc/apt/sources.list.d/domoticz.list
apt-get update && apt-get install -y domoticz
systemctl enable domoticz
systemctl start domoticz
"""
        result = lxc_exec(["bash", "-c", install_script], timeout=600)
        if result.returncode != 0:
            # Fallback: install from beta script
            fallback_script = """
apt-get update && apt-get install -y curl sudo
curl -sSL install.domoticz.com | sudo bash
"""
            result = lxc_exec(["bash", "-c", fallback_script], timeout=600)

        return {"success": True, "message": "Domoticz installed", "ip": lxc_get_ip()}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Install timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/uninstall", dependencies=[Depends(require_jwt)])
async def uninstall_domoticz():
    """Remove Domoticz LXC container."""
    if lxc_running():
        subprocess.run(["lxc-stop", "-n", LXC_NAME], capture_output=True, timeout=30)

    if lxc_exists():
        result = subprocess.run(
            ["lxc-destroy", "-n", LXC_NAME],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Destroy failed: {result.stderr}")

    return {"success": True, "message": "Container removed"}


@app.get("/devices", dependencies=[Depends(require_jwt)])
async def list_devices():
    """List Domoticz devices."""
    if not lxc_running():
        return {"devices": [], "error": "Service not running"}

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
                "last_update": dev.get("LastUpdate"),
                "battery_level": dev.get("BatteryLevel"),
                "signal_level": dev.get("SignalLevel")
            })
        return {"devices": devices, "count": len(devices)}
    except Exception as e:
        return {"devices": [], "error": str(e)}


@app.get("/scenes", dependencies=[Depends(require_jwt)])
async def list_scenes():
    """List Domoticz scenes and groups."""
    if not lxc_running():
        return {"scenes": [], "error": "Service not running"}

    try:
        data = await domoticz_api("type=scenes")
        scenes = []
        for scene in data.get("result", []):
            scenes.append({
                "idx": scene.get("idx"),
                "name": scene.get("Name"),
                "type": scene.get("Type"),
                "status": scene.get("Status"),
                "last_update": scene.get("LastUpdate")
            })
        return {"scenes": scenes, "count": len(scenes)}
    except Exception as e:
        return {"scenes": [], "error": str(e)}


@app.post("/devices/{idx}/switch", dependencies=[Depends(require_jwt)])
async def switch_device(idx: int, command: str = Query(..., pattern="^(On|Off|Toggle)$")):
    """Switch a device on/off/toggle."""
    if not lxc_running():
        raise HTTPException(status_code=400, detail="Service not running")

    try:
        data = await domoticz_api(f"type=command&param=switchlight&idx={idx}&switchcmd={command}")
        return {"success": data.get("status") == "OK", "result": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scenes/{idx}/activate", dependencies=[Depends(require_jwt)])
async def activate_scene(idx: int, command: str = Query("On", pattern="^(On|Off)$")):
    """Activate or deactivate a scene."""
    if not lxc_running():
        raise HTTPException(status_code=400, detail="Service not running")

    try:
        data = await domoticz_api(f"type=command&param=switchscene&idx={idx}&switchcmd={command}")
        return {"success": data.get("status") == "OK", "result": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/hardware", dependencies=[Depends(require_jwt)])
async def list_hardware():
    """List configured hardware."""
    if not lxc_running():
        return {"hardware": [], "error": "Service not running"}

    try:
        data = await domoticz_api("type=hardware")
        hardware = []
        for hw in data.get("result", []):
            hardware.append({
                "idx": hw.get("idx"),
                "name": hw.get("Name"),
                "type": hw.get("Type"),
                "enabled": hw.get("Enabled") == "true",
                "data_timeout": hw.get("DataTimeout")
            })
        return {"hardware": hardware, "count": len(hardware)}
    except Exception as e:
        return {"hardware": [], "error": str(e)}


@app.post("/backup", dependencies=[Depends(require_jwt)])
async def create_backup():
    """Create Domoticz backup."""
    if not lxc_exists():
        raise HTTPException(status_code=400, detail="Container not found")

    backup_dir = Path("/var/lib/secubox/backups/domoticz")
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_file = backup_dir / f"domoticz-backup-{timestamp}.tar.gz"

    lxc_path = LXC_ROOT / LXC_NAME

    try:
        # Stop container for consistent backup
        was_running = lxc_running()
        if was_running:
            subprocess.run(["lxc-stop", "-n", LXC_NAME], capture_output=True, timeout=30)
            await asyncio.sleep(2)

        result = subprocess.run(
            ["tar", "-czf", str(backup_file), "-C", str(LXC_ROOT), LXC_NAME],
            capture_output=True,
            text=True,
            timeout=600
        )

        # Restart if was running
        if was_running:
            subprocess.run(["lxc-start", "-n", LXC_NAME], capture_output=True, timeout=60)

        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Backup failed: {result.stderr}")

        size = backup_file.stat().st_size
        return {
            "success": True,
            "path": str(backup_file),
            "size": size,
            "timestamp": timestamp
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/backups", dependencies=[Depends(require_jwt)])
async def list_backups():
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


@app.post("/restore", dependencies=[Depends(require_jwt)])
async def restore_backup(path: str = Query(...)):
    """Restore from backup."""
    backup_path = Path(path)
    if not backup_path.exists():
        raise HTTPException(status_code=404, detail="Backup file not found")

    # Stop and remove existing container
    if lxc_running():
        subprocess.run(["lxc-stop", "-n", LXC_NAME], capture_output=True, timeout=30)
        await asyncio.sleep(2)

    if lxc_exists():
        subprocess.run(["lxc-destroy", "-n", LXC_NAME], capture_output=True, timeout=60)

    try:
        # Extract backup
        result = subprocess.run(
            ["tar", "-xzf", str(backup_path), "-C", str(LXC_ROOT)],
            capture_output=True,
            text=True,
            timeout=600
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Restore failed: {result.stderr}")

        # Start container
        subprocess.run(["lxc-start", "-n", LXC_NAME], capture_output=True, timeout=60)
        await asyncio.sleep(5)

        return {"success": True, "message": "Backup restored successfully", "ip": lxc_get_ip()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = Query(100, ge=10, le=1000)):
    """Get container logs."""
    if not lxc_exists():
        return {"logs": [], "error": "Container not found"}

    try:
        # Get systemd journal from inside container
        result = lxc_exec(
            ["journalctl", "-u", "domoticz", "-n", str(lines), "--no-pager"],
            timeout=30
        )
        logs = result.stdout.strip().split("\n") if result.stdout else []
        return {"logs": logs[-lines:]}
    except Exception as e:
        return {"logs": [], "error": str(e)}


@app.get("/usb_devices", dependencies=[Depends(require_jwt)])
async def get_usb_devices_list():
    """Get list of USB serial devices."""
    return {"devices": get_usb_devices()}


@app.post("/usb_passthrough", dependencies=[Depends(require_jwt)])
async def add_usb_passthrough(device_path: str = Query(...)):
    """Add USB device passthrough to container."""
    if not os.path.exists(device_path):
        raise HTTPException(status_code=404, detail="Device not found")

    if not lxc_exists():
        raise HTTPException(status_code=400, detail="Container not created")

    lxc_config = LXC_ROOT / LXC_NAME / "config"
    entry = f"lxc.mount.entry = {device_path} {device_path[1:]} none bind,create=file 0 0\n"

    with open(lxc_config, "a") as f:
        f.write(entry)

    # Restart if running to apply changes
    if lxc_running():
        await restart_service()

    return {"success": True, "message": f"Added passthrough for {device_path}"}


@app.post("/reset_password", dependencies=[Depends(require_jwt)])
async def reset_admin_password(password: str = Query("admin", min_length=4)):
    """Reset Domoticz admin password."""
    if not lxc_running():
        raise HTTPException(status_code=400, detail="Service not running")

    try:
        import hashlib
        md5hash = hashlib.md5(password.encode()).hexdigest()

        # admin in base64 is YWRtaW4=
        result = lxc_exec([
            "sqlite3", "/opt/domoticz/domoticz.db",
            f"UPDATE Users SET Password='{md5hash}' WHERE Username='YWRtaW4=';"
        ])
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Failed: {result.stderr}")

        return {"success": True, "message": "Password reset successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
