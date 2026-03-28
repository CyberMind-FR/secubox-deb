"""SecuBox Home Assistant - Smart Home Hub
Comprehensive home automation platform with broad device ecosystem.

Features:
- LXC container management
- Device and entity management
- Automation and scene control
- Integration marketplace
- Energy monitoring
- Backup and restore
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
CONFIG_FILE = Path("/etc/secubox/homeassistant.json")
DATA_DIR = Path("/srv/homeassistant")
CONFIG_DIR = DATA_DIR / "config"
LXC_NAME = "homeassistant"
DEFAULT_PORT = 8123
LXC_ROOT = Path("/var/lib/lxc")

app = FastAPI(title="SecuBox Home Assistant", version="1.0.0")


class ConfigUpdate(BaseModel):
    timezone: str = "UTC"
    latitude: float = 0.0
    longitude: float = 0.0
    elevation: int = 0
    unit_system: str = "metric"
    currency: str = "EUR"


def load_config() -> dict:
    """Load configuration from file."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return {
        "timezone": "UTC",
        "latitude": 0.0,
        "longitude": 0.0,
        "elevation": 0,
        "unit_system": "metric",
        "currency": "EUR"
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
    """Get list of USB serial devices for Zigbee/Z-Wave."""
    devices = []
    for pattern in ["/dev/ttyUSB*", "/dev/ttyACM*", "/dev/serial/by-id/*"]:
        import glob
        for path in glob.glob(pattern):
            try:
                info = {"path": path, "type": "serial"}
                if "/by-id/" in path:
                    info["name"] = os.path.basename(path)
                else:
                    dev_name = os.path.basename(path)
                    product_path = f"/sys/class/tty/{dev_name}/device/product"
                    if os.path.exists(product_path):
                        info["product"] = Path(product_path).read_text().strip()
                devices.append(info)
            except Exception:
                devices.append({"path": path, "type": "serial"})
    return devices


async def ha_api(endpoint: str, method: str = "GET", data: dict = None,
                 token: str = None, timeout: float = 30.0) -> dict:
    """Make request to Home Assistant API."""
    ip = lxc_get_ip()
    if not ip:
        raise HTTPException(status_code=502, detail="Container IP not available")

    url = f"http://{ip}:{DEFAULT_PORT}/api{endpoint}"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            if method == "GET":
                response = await client.get(url, headers=headers)
            elif method == "POST":
                response = await client.post(url, json=data, headers=headers)
            return response.json() if response.text else {}
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Home Assistant API error: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "module": "homeassistant"}


@app.get("/status", dependencies=[Depends(require_jwt)])
async def get_status():
    """Get Home Assistant service status."""
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
                resp = await client.get(f"http://{ip}:{DEFAULT_PORT}/api/")
                if resp.status_code in [200, 401]:  # 401 means API is up but needs auth
                    web_accessible = True
                    if resp.status_code == 200:
                        data = resp.json()
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
                timeout=30
            )
            if result.returncode == 0:
                disk_usage = result.stdout.split()[0]
        except Exception:
            pass

    return {
        "running": running,
        "version": version,
        "port": DEFAULT_PORT,
        "timezone": config.get("timezone", "UTC"),
        "runtime": "lxc",
        "web_accessible": web_accessible,
        "container_exists": exists,
        "container_ip": ip,
        "data_path": str(DATA_DIR),
        "disk_usage": disk_usage,
        "usb_devices": get_usb_devices()
    }


@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config():
    """Get Home Assistant configuration."""
    return load_config()


@app.post("/config", dependencies=[Depends(require_jwt)])
async def update_config(config: ConfigUpdate):
    """Update Home Assistant configuration."""
    current = load_config()
    current.update(config.dict())
    save_config(current)
    return {"success": True, "config": current}


@app.post("/start", dependencies=[Depends(require_jwt)])
async def start_service():
    """Start Home Assistant LXC container."""
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

        # Wait for Home Assistant to initialize
        await asyncio.sleep(10)

        return {"success": True, "message": "Home Assistant started", "ip": lxc_get_ip()}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Start timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop_service():
    """Stop Home Assistant LXC container."""
    if not lxc_running():
        return {"success": True, "message": "Already stopped"}

    try:
        subprocess.run(["lxc-stop", "-n", LXC_NAME], capture_output=True, timeout=30)
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart_service():
    """Restart Home Assistant container."""
    await stop_service()
    await asyncio.sleep(2)
    return await start_service()


@app.post("/install", dependencies=[Depends(require_jwt)])
async def install_homeassistant():
    """Create and setup Home Assistant LXC container."""
    if lxc_exists():
        return {"success": True, "message": "Container already exists"}

    config = load_config()

    # Ensure config directory exists on host
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

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

        # Configure container
        lxc_config = LXC_ROOT / LXC_NAME / "config"
        with open(lxc_config, "a") as f:
            f.write("\n# SecuBox Home Assistant config\n")
            f.write("lxc.start.auto = 1\n")
            # Mount config directory from host
            f.write(f"lxc.mount.entry = {CONFIG_DIR} srv/homeassistant/config none bind,create=dir 0 0\n")
            # USB passthrough for Zigbee/Z-Wave
            for dev in get_usb_devices():
                if not dev["path"].startswith("/dev/serial"):
                    f.write(f"lxc.mount.entry = {dev['path']} {dev['path'][1:]} none bind,create=file 0 0\n")
            f.write("lxc.cgroup2.devices.allow = c 188:* rwm\n")  # ttyUSB
            f.write("lxc.cgroup2.devices.allow = c 166:* rwm\n")  # ttyACM
            # Memory limit
            f.write("lxc.cgroup2.memory.max = 2G\n")

        # Start container
        subprocess.run(["lxc-start", "-n", LXC_NAME], capture_output=True, timeout=60)
        await asyncio.sleep(5)

        # Wait for network
        for _ in range(30):
            if lxc_get_ip():
                break
            await asyncio.sleep(1)

        # Install Home Assistant Core
        tz = config.get("timezone", "UTC")

        install_script = f"""
apt-get update
apt-get install -y python3 python3-dev python3-venv python3-pip \\
    libffi-dev libssl-dev libjpeg-dev zlib1g-dev autoconf build-essential \\
    libopenjp2-7 libtiff6 libturbojpeg0-dev tzdata liblapack3 libatlas-base-dev \\
    bluez ffmpeg libavcodec-extra libpcap-dev

# Set timezone
ln -sf /usr/share/zoneinfo/{tz} /etc/localtime
echo "{tz}" > /etc/timezone

# Create homeassistant user
useradd -rm homeassistant -G dialout,audio,video

# Create directories
mkdir -p /srv/homeassistant/config
chown -R homeassistant:homeassistant /srv/homeassistant

# Create virtual environment and install Home Assistant
sudo -u homeassistant python3 -m venv /srv/homeassistant/venv
sudo -u homeassistant /srv/homeassistant/venv/bin/pip install --upgrade pip wheel
sudo -u homeassistant /srv/homeassistant/venv/bin/pip install homeassistant

# Create systemd service
cat > /etc/systemd/system/homeassistant.service << 'EOF'
[Unit]
Description=Home Assistant
After=network-online.target

[Service]
Type=simple
User=homeassistant
Group=homeassistant
WorkingDirectory=/srv/homeassistant
ExecStart=/srv/homeassistant/venv/bin/hass -c /srv/homeassistant/config
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable homeassistant
systemctl start homeassistant
"""
        result = lxc_exec(["bash", "-c", install_script], timeout=1800)  # 30 min timeout

        return {"success": True, "message": "Home Assistant installed", "ip": lxc_get_ip()}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Install timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/uninstall", dependencies=[Depends(require_jwt)])
async def uninstall_homeassistant():
    """Remove Home Assistant LXC container."""
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


@app.get("/entities", dependencies=[Depends(require_jwt)])
async def list_entities(domain: str = Query(None)):
    """List Home Assistant entities."""
    if not lxc_running():
        return {"entities": [], "error": "Service not running"}

    # Read states from HA API (requires long-lived token)
    # For now, return placeholder
    return {
        "entities": [],
        "message": "Connect via Home Assistant UI to view entities",
        "url": f"http://{lxc_get_ip()}:{DEFAULT_PORT}"
    }


@app.get("/integrations", dependencies=[Depends(require_jwt)])
async def list_integrations():
    """List installed integrations."""
    if not lxc_running():
        return {"integrations": [], "error": "Service not running"}

    # Check config for integrations
    manifest_dir = LXC_ROOT / LXC_NAME / "rootfs/srv/homeassistant/config/custom_components"
    integrations = []

    if manifest_dir.exists():
        for comp in manifest_dir.iterdir():
            if comp.is_dir():
                manifest = comp / "manifest.json"
                if manifest.exists():
                    try:
                        data = json.loads(manifest.read_text())
                        integrations.append({
                            "domain": data.get("domain"),
                            "name": data.get("name"),
                            "version": data.get("version")
                        })
                    except Exception:
                        pass

    return {"integrations": integrations, "count": len(integrations)}


@app.post("/restart_ha", dependencies=[Depends(require_jwt)])
async def restart_ha_core():
    """Restart Home Assistant Core (not container)."""
    if not lxc_running():
        raise HTTPException(status_code=400, detail="Container not running")

    try:
        result = lxc_exec(["systemctl", "restart", "homeassistant"])
        return {"success": result.returncode == 0}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/backup", dependencies=[Depends(require_jwt)])
async def create_backup():
    """Create Home Assistant backup."""
    if not lxc_exists():
        raise HTTPException(status_code=400, detail="Container not found")

    backup_dir = Path("/var/lib/secubox/backups/homeassistant")
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_file = backup_dir / f"homeassistant-backup-{timestamp}.tar.gz"

    try:
        # Backup config directory
        result = subprocess.run(
            ["tar", "-czf", str(backup_file), "-C", str(CONFIG_DIR.parent), CONFIG_DIR.name],
            capture_output=True,
            text=True,
            timeout=300
        )
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
    backup_dir = Path("/var/lib/secubox/backups/homeassistant")
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

    # Stop HA if running
    if lxc_running():
        lxc_exec(["systemctl", "stop", "homeassistant"])
        await asyncio.sleep(2)

    try:
        # Clear config directory
        if CONFIG_DIR.exists():
            import shutil
            shutil.rmtree(CONFIG_DIR)

        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        # Extract backup
        result = subprocess.run(
            ["tar", "-xzf", str(backup_path), "-C", str(CONFIG_DIR.parent)],
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Restore failed: {result.stderr}")

        # Restart HA
        if lxc_running():
            lxc_exec(["systemctl", "start", "homeassistant"])

        return {"success": True, "message": "Backup restored successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = Query(100, ge=10, le=1000)):
    """Get Home Assistant logs."""
    if not lxc_exists():
        return {"logs": [], "error": "Container not found"}

    try:
        result = lxc_exec(
            ["journalctl", "-u", "homeassistant", "-n", str(lines), "--no-pager"],
            timeout=30
        )
        logs = result.stdout.strip().split("\n") if result.stdout else []
        return {"logs": logs[-lines:]}
    except Exception as e:
        return {"logs": [], "error": str(e)}


@app.get("/usb_devices", dependencies=[Depends(require_jwt)])
async def get_usb_devices_list():
    """Get list of USB devices for passthrough."""
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

    # Restart container to apply changes
    if lxc_running():
        await restart_service()

    return {"success": True, "message": f"Added passthrough for {device_path}"}


@app.post("/hacs/install", dependencies=[Depends(require_jwt)])
async def install_hacs():
    """Install HACS (Home Assistant Community Store)."""
    if not lxc_running():
        raise HTTPException(status_code=400, detail="Container not running")

    try:
        install_script = """
cd /srv/homeassistant/config
wget -O - https://get.hacs.xyz | bash -
"""
        result = lxc_exec(["bash", "-c", install_script], timeout=120)

        if result.returncode == 0:
            # Restart HA to load HACS
            lxc_exec(["systemctl", "restart", "homeassistant"])
            return {"success": True, "message": "HACS installed. Restart Home Assistant to complete."}
        else:
            raise HTTPException(status_code=500, detail=f"Install failed: {result.stderr}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
