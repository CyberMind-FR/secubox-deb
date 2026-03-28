"""
SecuBox GoToSocial API
LXC-based Fediverse/ActivityPub server management
"""
from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List
from pathlib import Path
import subprocess
import json
import os

try:
    from secubox_core.auth import require_jwt
    from secubox_core.logger import get_logger
except ImportError:
    def require_jwt():
        return {"sub": "admin"}
    class Logger:
        def info(self, msg): print(f"INFO: {msg}")
        def error(self, msg): print(f"ERROR: {msg}")
    def get_logger(name): return Logger()

app = FastAPI(
    title="secubox-gotosocial",
    root_path="/api/v1/gotosocial",
)

log = get_logger("gotosocial")

# Configuration
LXC_NAME = "secubox-gotosocial"
CONFIG_DIR = Path("/var/lib/secubox/gotosocial")
DATA_DIR = Path("/var/lib/secubox/gotosocial/data")
GTS_PORT = 8080
GTS_VERSION = "0.17.3"


# ══════════════════════════════════════════════════════════════════
# LXC Helpers
# ══════════════════════════════════════════════════════════════════

def lxc_exists() -> bool:
    result = subprocess.run(["lxc-info", "-n", LXC_NAME], capture_output=True)
    return result.returncode == 0

def lxc_running() -> bool:
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME, "-s"],
            capture_output=True, text=True, timeout=10
        )
        return "RUNNING" in result.stdout
    except:
        return False

def lxc_get_ip() -> Optional[str]:
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME, "-iH"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n")[0]
    except:
        pass
    return None

def lxc_exec(cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["lxc-attach", "-n", LXC_NAME, "--"] + cmd,
        capture_output=True, text=True, timeout=timeout
    )

def lxc_start() -> bool:
    return subprocess.run(["lxc-start", "-n", LXC_NAME], capture_output=True).returncode == 0

def lxc_stop() -> bool:
    return subprocess.run(["lxc-stop", "-n", LXC_NAME], capture_output=True).returncode == 0


# ══════════════════════════════════════════════════════════════════
# Models
# ══════════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    email: str
    password: str = Field(..., min_length=8)
    admin: bool = False

class ConfigUpdate(BaseModel):
    instance_title: Optional[str] = None
    instance_description: Optional[str] = None
    accounts_registration_open: Optional[bool] = None
    accounts_approval_required: Optional[bool] = None
    media_max_image_size: Optional[int] = None
    media_max_video_size: Optional[int] = None


# ══════════════════════════════════════════════════════════════════
# Status
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok", "module": "gotosocial"}

@app.get("/status")
async def status(user=Depends(require_jwt)):
    container_exists = lxc_exists()
    running = lxc_running() if container_exists else False
    container_ip = lxc_get_ip() if running else None

    version = None
    domain = None
    users_count = 0
    statuses_count = 0

    if running:
        # Get version
        result = lxc_exec(["gotosocial", "--version"])
        if result.returncode == 0:
            version = result.stdout.strip()

        # Get domain from config
        result = lxc_exec(["cat", "/data/config.yaml"])
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "host:" in line:
                    domain = line.split(":")[-1].strip().strip('"')
                    break

        # Get stats from database
        result = lxc_exec([
            "sqlite3", "/data/sqlite.db",
            "SELECT COUNT(*) FROM accounts WHERE local = 1;"
        ])
        if result.returncode == 0:
            try:
                users_count = int(result.stdout.strip())
            except:
                pass

        result = lxc_exec([
            "sqlite3", "/data/sqlite.db",
            "SELECT COUNT(*) FROM statuses WHERE local = 1;"
        ])
        if result.returncode == 0:
            try:
                statuses_count = int(result.stdout.strip())
            except:
                pass

    disk_usage = None
    if DATA_DIR.exists():
        try:
            result = subprocess.run(["du", "-sh", str(DATA_DIR)], capture_output=True, text=True)
            if result.returncode == 0:
                disk_usage = result.stdout.split()[0]
        except:
            pass

    return {
        "container_exists": container_exists,
        "running": running,
        "container_ip": container_ip,
        "version": version,
        "domain": domain,
        "users_count": users_count,
        "statuses_count": statuses_count,
        "disk_usage": disk_usage,
        "port": GTS_PORT,
    }


# ══════════════════════════════════════════════════════════════════
# Lifecycle
# ══════════════════════════════════════════════════════════════════

@app.post("/install")
async def install(
    domain: str = Query(..., description="Instance domain (e.g., social.example.com)"),
    user=Depends(require_jwt)
):
    if lxc_exists():
        raise HTTPException(400, "Container already exists")

    log.info(f"Installing GoToSocial for {domain}")
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Create container
    result = subprocess.run([
        "lxc-create", "-n", LXC_NAME,
        "-t", "download", "--",
        "-d", "debian", "-r", "bookworm", "-a", "amd64"
    ], capture_output=True, text=True, timeout=600)

    if result.returncode != 0:
        raise HTTPException(500, f"Failed to create container: {result.stderr}")

    # Configure
    lxc_config = f"/var/lib/lxc/{LXC_NAME}/config"
    with open(lxc_config, "a") as f:
        f.write(f"\n# SecuBox GoToSocial\n")
        f.write(f"lxc.mount.entry = {DATA_DIR} data none bind,create=dir 0 0\n")
        f.write("lxc.start.auto = 1\n")

    if not lxc_start():
        raise HTTPException(500, "Failed to start container")

    import time
    for _ in range(30):
        if lxc_get_ip():
            break
        time.sleep(1)

    install_script = f'''#!/bin/bash
set -e

apt-get update
apt-get install -y wget sqlite3 ca-certificates

# Download GoToSocial
cd /tmp
wget -q https://github.com/superseriousbusiness/gotosocial/releases/download/v{GTS_VERSION}/gotosocial_{GTS_VERSION}_linux_amd64.tar.gz
tar -xzf gotosocial_{GTS_VERSION}_linux_amd64.tar.gz -C /usr/local/bin gotosocial
chmod +x /usr/local/bin/gotosocial

# Create config
mkdir -p /data
cat > /data/config.yaml << 'EOFCONFIG'
host: "{domain}"
account-domain: "{domain}"
protocol: "https"
bind-address: "0.0.0.0"
port: {GTS_PORT}
db-type: "sqlite"
db-address: "/data/sqlite.db"
storage-local-base-path: "/data/storage"
accounts-registration-open: false
accounts-approval-required: true
instance-expose-public-timeline: true
EOFCONFIG

mkdir -p /data/storage

# Create systemd service
cat > /etc/systemd/system/gotosocial.service << 'EOFSVC'
[Unit]
Description=GoToSocial Fediverse Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/data
ExecStart=/usr/local/bin/gotosocial --config-path /data/config.yaml server start
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOFSVC

systemctl daemon-reload
systemctl enable gotosocial
systemctl start gotosocial
'''

    result = lxc_exec(["bash", "-c", install_script], timeout=300)

    if result.returncode != 0:
        raise HTTPException(500, f"Installation failed: {result.stderr[:500]}")

    return {"success": True, "message": f"GoToSocial installed for {domain}"}

@app.post("/start")
async def start(user=Depends(require_jwt)):
    if not lxc_exists():
        raise HTTPException(400, "Container not installed")
    if lxc_running():
        return {"success": True, "message": "Already running"}
    if lxc_start():
        lxc_exec(["systemctl", "start", "gotosocial"])
        return {"success": True}
    raise HTTPException(500, "Failed to start")

@app.post("/stop")
async def stop(user=Depends(require_jwt)):
    if not lxc_running():
        return {"success": True, "message": "Already stopped"}
    lxc_exec(["systemctl", "stop", "gotosocial"])
    if lxc_stop():
        return {"success": True}
    raise HTTPException(500, "Failed to stop")

@app.post("/restart")
async def restart(user=Depends(require_jwt)):
    if not lxc_running():
        raise HTTPException(400, "Container not running")
    lxc_exec(["systemctl", "restart", "gotosocial"])
    return {"success": True}

@app.delete("/uninstall")
async def uninstall(user=Depends(require_jwt)):
    if lxc_running():
        lxc_stop()
    if lxc_exists():
        subprocess.run(["lxc-destroy", "-n", LXC_NAME], capture_output=True)
    return {"success": True, "message": "Container removed, data preserved"}


# ══════════════════════════════════════════════════════════════════
# User Management
# ══════════════════════════════════════════════════════════════════

@app.get("/users")
async def list_users(user=Depends(require_jwt)):
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec([
        "sqlite3", "-json", "/data/sqlite.db",
        "SELECT username, display_name, created_at, suspended_at FROM accounts WHERE local = 1;"
    ])

    users = []
    if result.returncode == 0 and result.stdout.strip():
        try:
            users = json.loads(result.stdout)
        except:
            pass

    return {"users": users}

@app.post("/users")
async def create_user(req: UserCreate, user=Depends(require_jwt)):
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    cmd = [
        "gotosocial", "--config-path", "/data/config.yaml",
        "admin", "account", "create",
        "--username", req.username,
        "--email", req.email,
        "--password", req.password
    ]

    result = lxc_exec(cmd)

    if result.returncode != 0:
        raise HTTPException(500, f"Failed: {result.stderr}")

    # Make admin if requested
    if req.admin:
        lxc_exec([
            "gotosocial", "--config-path", "/data/config.yaml",
            "admin", "account", "promote", "--username", req.username
        ])

    # Confirm the account
    lxc_exec([
        "gotosocial", "--config-path", "/data/config.yaml",
        "admin", "account", "confirm", "--username", req.username
    ])

    return {"success": True, "username": req.username}

@app.delete("/users/{username}")
async def delete_user(username: str, user=Depends(require_jwt)):
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec([
        "gotosocial", "--config-path", "/data/config.yaml",
        "admin", "account", "suspend", "--username", username
    ])

    return {"success": result.returncode == 0}

@app.post("/users/{username}/promote")
async def promote_user(username: str, user=Depends(require_jwt)):
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec([
        "gotosocial", "--config-path", "/data/config.yaml",
        "admin", "account", "promote", "--username", username
    ])

    return {"success": result.returncode == 0}


# ══════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════

@app.get("/config")
async def get_config(user=Depends(require_jwt)):
    if not lxc_running():
        return {"error": "Container not running"}

    result = lxc_exec(["cat", "/data/config.yaml"])
    if result.returncode != 0:
        raise HTTPException(500, "Failed to read config")

    config = {}
    for line in result.stdout.splitlines():
        if ":" in line and not line.strip().startswith("#"):
            key, value = line.split(":", 1)
            config[key.strip()] = value.strip().strip('"')

    return config

@app.post("/config")
async def update_config(req: ConfigUpdate, user=Depends(require_jwt)):
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec(["cat", "/data/config.yaml"])
    if result.returncode != 0:
        raise HTTPException(500, "Failed to read config")

    lines = result.stdout.splitlines()
    updated = []

    for line in lines:
        if req.instance_title and line.strip().startswith("instance-title:"):
            line = f'instance-title: "{req.instance_title}"'
        elif req.instance_description and line.strip().startswith("instance-short-description:"):
            line = f'instance-short-description: "{req.instance_description}"'
        elif req.accounts_registration_open is not None and "accounts-registration-open:" in line:
            line = f"accounts-registration-open: {str(req.accounts_registration_open).lower()}"
        elif req.accounts_approval_required is not None and "accounts-approval-required:" in line:
            line = f"accounts-approval-required: {str(req.accounts_approval_required).lower()}"
        updated.append(line)

    config_content = "\n".join(updated)
    result = lxc_exec(["bash", "-c", f"cat > /data/config.yaml << 'EOF'\n{config_content}\nEOF"])

    lxc_exec(["systemctl", "restart", "gotosocial"])

    return {"success": True}


# ══════════════════════════════════════════════════════════════════
# Federation
# ══════════════════════════════════════════════════════════════════

@app.get("/federation/blocks")
async def list_blocks(user=Depends(require_jwt)):
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec([
        "sqlite3", "-json", "/data/sqlite.db",
        "SELECT domain, created_at FROM domain_blocks;"
    ])

    blocks = []
    if result.returncode == 0 and result.stdout.strip():
        try:
            blocks = json.loads(result.stdout)
        except:
            pass

    return {"blocks": blocks}

@app.post("/federation/blocks")
async def add_block(
    domain: str = Query(...),
    user=Depends(require_jwt)
):
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec([
        "gotosocial", "--config-path", "/data/config.yaml",
        "admin", "domain", "block", "--domain", domain
    ])

    return {"success": result.returncode == 0, "domain": domain}

@app.delete("/federation/blocks/{domain}")
async def remove_block(domain: str, user=Depends(require_jwt)):
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec([
        "gotosocial", "--config-path", "/data/config.yaml",
        "admin", "domain", "unblock", "--domain", domain
    ])

    return {"success": result.returncode == 0}


# ══════════════════════════════════════════════════════════════════
# Media & Storage
# ══════════════════════════════════════════════════════════════════

@app.get("/media/stats")
async def media_stats(user=Depends(require_jwt)):
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec(["du", "-sh", "/data/storage"])
    storage_size = result.stdout.split()[0] if result.returncode == 0 else "0"

    result = lxc_exec([
        "sqlite3", "/data/sqlite.db",
        "SELECT COUNT(*) FROM media_attachments;"
    ])
    media_count = int(result.stdout.strip()) if result.returncode == 0 else 0

    return {
        "storage_size": storage_size,
        "media_count": media_count,
    }

@app.post("/media/prune")
async def prune_media(
    days: int = Query(30, ge=7),
    user=Depends(require_jwt)
):
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec([
        "gotosocial", "--config-path", "/data/config.yaml",
        "admin", "media", "prune", "--remote-cache-days", str(days)
    ], timeout=300)

    return {"success": result.returncode == 0, "output": result.stdout}


# ══════════════════════════════════════════════════════════════════
# Logs
# ══════════════════════════════════════════════════════════════════

@app.get("/logs")
async def get_logs(
    lines: int = Query(100, ge=10, le=1000),
    user=Depends(require_jwt)
):
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec(["journalctl", "-u", "gotosocial", "-n", str(lines), "--no-pager"])

    return {"logs": result.stdout.splitlines() if result.returncode == 0 else []}


# ══════════════════════════════════════════════════════════════════
# Backup
# ══════════════════════════════════════════════════════════════════

@app.post("/backup")
async def create_backup(user=Depends(require_jwt)):
    backup_dir = Path("/var/lib/secubox/backups/gotosocial")
    backup_dir.mkdir(parents=True, exist_ok=True)

    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"gotosocial-backup-{timestamp}.tar.gz"

    was_running = lxc_running()
    if was_running:
        lxc_exec(["systemctl", "stop", "gotosocial"])

    try:
        result = subprocess.run([
            "tar", "-czf", str(backup_file),
            "-C", str(DATA_DIR.parent), DATA_DIR.name
        ], capture_output=True, text=True, timeout=600)

        if result.returncode != 0:
            raise HTTPException(500, f"Backup failed: {result.stderr}")

        return {
            "success": True,
            "file": str(backup_file),
            "size": f"{backup_file.stat().st_size / 1024 / 1024:.1f} MB"
        }
    finally:
        if was_running:
            lxc_exec(["systemctl", "start", "gotosocial"])
