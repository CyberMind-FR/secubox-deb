"""SecuBox PhotoPrism - AI-Powered Photo Management
Self-hosted photo library with face recognition and search.

Features:
- LXC container management
- Photo library organization
- AI-powered face/object recognition
- Full-text search
- Album management
- Import from various sources
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
CONFIG_FILE = Path("/etc/secubox/photoprism.json")
DATA_DIR = Path("/srv/photoprism")
PHOTOS_DIR = DATA_DIR / "photos"
ORIGINALS_DIR = DATA_DIR / "originals"
IMPORT_DIR = DATA_DIR / "import"
LXC_NAME = "photoprism"
DEFAULT_PORT = 2342
LXC_ROOT = Path("/var/lib/lxc")

app = FastAPI(title="SecuBox PhotoPrism", version="1.0.0")


class ConfigUpdate(BaseModel):
    site_url: str = "https://photos.local"
    site_title: str = "SecuBox Photos"
    admin_password: Optional[str] = None
    readonly: bool = False
    public: bool = False
    experimental: bool = False
    disable_tensorflow: bool = False
    detect_nsfw: bool = False
    upload_nsfw: bool = True


def load_config() -> dict:
    """Load configuration from file."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return {
        "site_url": "https://photos.local",
        "site_title": "SecuBox Photos",
        "readonly": False,
        "public": False,
        "experimental": False,
        "disable_tensorflow": False,
        "detect_nsfw": False,
        "upload_nsfw": True
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


def get_library_stats() -> dict:
    """Get photo library statistics."""
    stats = {
        "photos": 0,
        "videos": 0,
        "albums": 0,
        "size_bytes": 0
    }

    if ORIGINALS_DIR.exists():
        photo_exts = {".jpg", ".jpeg", ".png", ".gif", ".heic", ".webp", ".raw", ".cr2", ".nef"}
        video_exts = {".mp4", ".mov", ".avi", ".mkv", ".webm"}

        for f in ORIGINALS_DIR.rglob("*"):
            if f.is_file():
                ext = f.suffix.lower()
                if ext in photo_exts:
                    stats["photos"] += 1
                elif ext in video_exts:
                    stats["videos"] += 1
                stats["size_bytes"] += f.stat().st_size

    return stats


async def photoprism_api(endpoint: str, method: str = "GET", data: dict = None, timeout: float = 30.0) -> dict:
    """Make request to PhotoPrism API."""
    ip = lxc_get_ip()
    if not ip:
        raise HTTPException(status_code=502, detail="Container IP not available")

    url = f"http://{ip}:{DEFAULT_PORT}/api/v1{endpoint}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            if method == "GET":
                response = await client.get(url)
            elif method == "POST":
                response = await client.post(url, json=data)
            elif method == "PUT":
                response = await client.put(url, json=data)
            elif method == "DELETE":
                response = await client.delete(url)
            return response.json() if response.text else {}
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"PhotoPrism API error: {str(e)}")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "module": "photoprism"}


@app.get("/status", dependencies=[Depends(require_jwt)])
async def get_status():
    """Get PhotoPrism service status."""
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
                resp = await client.get(f"http://{ip}:{DEFAULT_PORT}/api/v1/status")
                if resp.status_code == 200:
                    data = resp.json()
                    web_accessible = True
                    version = data.get("version", "unknown")
        except Exception:
            pass

    # Get disk usage
    disk_usage = "0"
    if DATA_DIR.exists():
        try:
            result = subprocess.run(
                ["du", "-sh", str(DATA_DIR)],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                disk_usage = result.stdout.split()[0]
        except Exception:
            pass

    stats = get_library_stats()

    return {
        "running": running,
        "version": version,
        "port": DEFAULT_PORT,
        "site_url": config.get("site_url", ""),
        "site_title": config.get("site_title", "SecuBox Photos"),
        "runtime": "lxc",
        "web_accessible": web_accessible,
        "container_exists": exists,
        "container_ip": ip,
        "data_path": str(DATA_DIR),
        "disk_usage": disk_usage,
        "photos": stats["photos"],
        "videos": stats["videos"],
        "library_size": stats["size_bytes"]
    }


@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config():
    """Get PhotoPrism configuration."""
    return load_config()


@app.post("/config", dependencies=[Depends(require_jwt)])
async def update_config(config: ConfigUpdate):
    """Update PhotoPrism configuration."""
    current = load_config()
    update_dict = config.dict(exclude_none=True)
    current.update(update_dict)
    save_config(current)
    return {"success": True, "config": current}


@app.post("/start", dependencies=[Depends(require_jwt)])
async def start_service():
    """Start PhotoPrism LXC container."""
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

        # Wait for PhotoPrism service
        await asyncio.sleep(5)

        return {"success": True, "message": "PhotoPrism started", "ip": lxc_get_ip()}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Start timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop_service():
    """Stop PhotoPrism LXC container."""
    if not lxc_running():
        return {"success": True, "message": "Already stopped"}

    try:
        subprocess.run(["lxc-stop", "-n", LXC_NAME], capture_output=True, timeout=30)
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart_service():
    """Restart PhotoPrism container."""
    await stop_service()
    await asyncio.sleep(2)
    return await start_service()


@app.post("/install", dependencies=[Depends(require_jwt)])
async def install_photoprism():
    """Create and setup PhotoPrism LXC container."""
    if lxc_exists():
        return {"success": True, "message": "Container already exists"}

    config = load_config()

    # Ensure directories exist on host
    for d in [DATA_DIR, PHOTOS_DIR, ORIGINALS_DIR, IMPORT_DIR]:
        d.mkdir(parents=True, exist_ok=True)

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
            f.write("\n# SecuBox PhotoPrism config\n")
            f.write("lxc.start.auto = 1\n")
            # Mount data directories from host
            f.write(f"lxc.mount.entry = {ORIGINALS_DIR} srv/photoprism/originals none bind,create=dir 0 0\n")
            f.write(f"lxc.mount.entry = {IMPORT_DIR} srv/photoprism/import none bind,create=dir 0 0\n")
            # Memory limit for AI processing
            f.write("lxc.cgroup2.memory.max = 4G\n")

        # Start container
        subprocess.run(["lxc-start", "-n", LXC_NAME], capture_output=True, timeout=60)
        await asyncio.sleep(5)

        # Wait for network
        for _ in range(30):
            if lxc_get_ip():
                break
            await asyncio.sleep(1)

        # Install PhotoPrism
        site_url = config.get("site_url", "https://photos.local")
        site_title = config.get("site_title", "SecuBox Photos")

        install_script = f"""
apt-get update && apt-get install -y wget curl ca-certificates gnupg

# Create photoprism user
useradd -r -s /bin/false -m -d /opt/photoprism photoprism

# Create directories
mkdir -p /srv/photoprism/{{originals,import,storage,cache}}
chown -R photoprism:photoprism /srv/photoprism

# Download PhotoPrism
cd /tmp
wget -q https://dl.photoprism.app/pkg/linux/amd64.tar.gz -O photoprism.tar.gz
tar -xzf photoprism.tar.gz
mv photoprism /opt/photoprism/bin
chown -R photoprism:photoprism /opt/photoprism

# Create config
cat > /opt/photoprism/.env << 'EOF'
PHOTOPRISM_SITE_URL="{site_url}"
PHOTOPRISM_SITE_TITLE="{site_title}"
PHOTOPRISM_ORIGINALS_PATH="/srv/photoprism/originals"
PHOTOPRISM_IMPORT_PATH="/srv/photoprism/import"
PHOTOPRISM_STORAGE_PATH="/srv/photoprism/storage"
PHOTOPRISM_CACHE_PATH="/srv/photoprism/cache"
PHOTOPRISM_DATABASE_DRIVER="sqlite"
PHOTOPRISM_HTTP_PORT={DEFAULT_PORT}
PHOTOPRISM_ADMIN_PASSWORD="secubox"
PHOTOPRISM_PUBLIC="false"
PHOTOPRISM_READONLY="false"
EOF
chown photoprism:photoprism /opt/photoprism/.env

# Create systemd service
cat > /etc/systemd/system/photoprism.service << 'EOF'
[Unit]
Description=PhotoPrism Photo Management
After=network.target

[Service]
Type=simple
User=photoprism
Group=photoprism
WorkingDirectory=/opt/photoprism
EnvironmentFile=/opt/photoprism/.env
ExecStart=/opt/photoprism/bin/photoprism start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable photoprism
systemctl start photoprism
"""
        result = lxc_exec(["bash", "-c", install_script], timeout=600)

        return {"success": True, "message": "PhotoPrism installed", "ip": lxc_get_ip()}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Install timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/uninstall", dependencies=[Depends(require_jwt)])
async def uninstall_photoprism():
    """Remove PhotoPrism LXC container."""
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


@app.get("/photos", dependencies=[Depends(require_jwt)])
async def list_photos(
    count: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    order: str = Query("newest", pattern="^(newest|oldest|name)$")
):
    """List photos in library."""
    if not lxc_running():
        return {"photos": [], "error": "Service not running"}

    try:
        data = await photoprism_api(f"/photos?count={count}&offset={offset}&order={order}")
        return {"photos": data, "count": len(data)}
    except Exception as e:
        return {"photos": [], "error": str(e)}


@app.get("/albums", dependencies=[Depends(require_jwt)])
async def list_albums():
    """List photo albums."""
    if not lxc_running():
        return {"albums": [], "error": "Service not running"}

    try:
        data = await photoprism_api("/albums?count=100")
        return {"albums": data, "count": len(data)}
    except Exception as e:
        return {"albums": [], "error": str(e)}


@app.post("/albums", dependencies=[Depends(require_jwt)])
async def create_album(title: str = Query(...), description: str = Query("")):
    """Create a new album."""
    if not lxc_running():
        raise HTTPException(status_code=400, detail="Service not running")

    try:
        data = await photoprism_api(
            "/albums",
            method="POST",
            data={"Title": title, "Description": description}
        )
        return {"success": True, "album": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/index", dependencies=[Depends(require_jwt)])
async def start_indexing(rescan: bool = Query(False)):
    """Start photo indexing."""
    if not lxc_running():
        raise HTTPException(status_code=400, detail="Service not running")

    try:
        # Run indexing command inside container
        cmd = ["photoprism", "index"]
        if rescan:
            cmd.append("--force")

        result = lxc_exec(["/opt/photoprism/bin/photoprism", "index"], timeout=3600)
        return {"success": result.returncode == 0, "output": result.stdout[:1000]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/import", dependencies=[Depends(require_jwt)])
async def start_import():
    """Import photos from import directory."""
    if not lxc_running():
        raise HTTPException(status_code=400, detail="Service not running")

    try:
        result = lxc_exec(["/opt/photoprism/bin/photoprism", "import"], timeout=3600)
        return {"success": result.returncode == 0, "output": result.stdout[:1000]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/faces", dependencies=[Depends(require_jwt)])
async def list_faces():
    """List recognized faces."""
    if not lxc_running():
        return {"faces": [], "error": "Service not running"}

    try:
        data = await photoprism_api("/faces?count=100")
        return {"faces": data, "count": len(data)}
    except Exception as e:
        return {"faces": [], "error": str(e)}


@app.get("/labels", dependencies=[Depends(require_jwt)])
async def list_labels():
    """List photo labels/tags."""
    if not lxc_running():
        return {"labels": [], "error": "Service not running"}

    try:
        data = await photoprism_api("/labels?count=100")
        return {"labels": data, "count": len(data)}
    except Exception as e:
        return {"labels": [], "error": str(e)}


@app.post("/backup", dependencies=[Depends(require_jwt)])
async def create_backup():
    """Create PhotoPrism backup."""
    if not lxc_exists():
        raise HTTPException(status_code=400, detail="Container not found")

    backup_dir = Path("/var/lib/secubox/backups/photoprism")
    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_file = backup_dir / f"photoprism-backup-{timestamp}.tar.gz"

    try:
        # Backup storage directory (contains database and cache)
        result = lxc_exec(["tar", "-czf", "/tmp/backup.tar.gz", "-C", "/srv/photoprism", "storage"], timeout=600)
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail="Backup creation failed")

        # Copy backup from container
        lxc_path = LXC_ROOT / LXC_NAME / "rootfs" / "tmp" / "backup.tar.gz"
        if lxc_path.exists():
            import shutil
            shutil.copy(lxc_path, backup_file)
            lxc_path.unlink()

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
    backup_dir = Path("/var/lib/secubox/backups/photoprism")
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


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = Query(100, ge=10, le=1000)):
    """Get PhotoPrism logs."""
    if not lxc_exists():
        return {"logs": [], "error": "Container not found"}

    try:
        result = lxc_exec(
            ["journalctl", "-u", "photoprism", "-n", str(lines), "--no-pager"],
            timeout=30
        )
        logs = result.stdout.strip().split("\n") if result.stdout else []
        return {"logs": logs[-lines:]}
    except Exception as e:
        return {"logs": [], "error": str(e)}


@app.post("/reset_password", dependencies=[Depends(require_jwt)])
async def reset_admin_password(password: str = Query("secubox", min_length=6)):
    """Reset admin password."""
    if not lxc_running():
        raise HTTPException(status_code=400, detail="Service not running")

    try:
        result = lxc_exec([
            "/opt/photoprism/bin/photoprism",
            "passwd", "--password", password
        ], timeout=30)

        return {"success": result.returncode == 0, "message": "Password reset"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
