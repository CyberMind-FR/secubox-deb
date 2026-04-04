"""
SecuBox-Deb :: Matrix
CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Matrix Synapse homeserver management API for SecuBox.
Supports both LXC containers and Docker/Podman deployments.
"""
from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from pathlib import Path
import subprocess
import json
import os
import shutil
import secrets
import time

# Core imports
try:
    from secubox_core.auth import require_jwt
    from secubox_core.logger import get_logger
except ImportError:
    # Development fallback
    def require_jwt():
        return {"sub": "admin"}
    class Logger:
        def info(self, msg): print(f"INFO: {msg}")
        def error(self, msg): print(f"ERROR: {msg}")
        def warning(self, msg): print(f"WARN: {msg}")
    def get_logger(name): return Logger()

app = FastAPI(
    title="SecuBox Matrix API",
    version="1.0.0",
    root_path="/api/v1/matrix",
)

log = get_logger("matrix")

# ══════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════

LXC_NAME = "secubox-matrix"
CONFIG_DIR = Path("/var/lib/secubox/matrix")
DATA_DIR = Path("/var/lib/secubox/matrix/data")
MEDIA_DIR = DATA_DIR / "media_store"
COMPOSE_DIR = Path("/opt/secubox/matrix")
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.yml"
SYNAPSE_PORT = 8008
FEDERATION_PORT = 8448
ADMIN_TOKEN_FILE = Path("/etc/secubox/matrix/admin_token")


# ══════════════════════════════════════════════════════════════════
# Helper Functions
# ══════════════════════════════════════════════════════════════════

def run_cmd(cmd: list, timeout: int = 60) -> dict:
    """Run command and return result."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_container_runtime() -> Optional[str]:
    """Detect available container runtime (Docker or Podman)."""
    for runtime in ["docker", "podman"]:
        result = run_cmd(["which", runtime])
        if result["success"]:
            return runtime
    return None


def is_container_install() -> bool:
    """Check if Synapse is running in Docker/Podman container."""
    if COMPOSE_FILE.exists():
        runtime = get_container_runtime()
        if runtime:
            result = run_cmd([runtime, "compose", "-f", str(COMPOSE_FILE), "ps", "-q"])
            return result["success"] and bool(result.get("stdout", "").strip())
    return False


def get_admin_token() -> Optional[str]:
    """Read admin API token."""
    if ADMIN_TOKEN_FILE.exists():
        return ADMIN_TOKEN_FILE.read_text().strip()
    return None


def synapse_admin_api(endpoint: str, method: str = "GET", data: dict = None, container_ip: str = None) -> dict:
    """Call Synapse Admin API."""
    import urllib.request
    import urllib.error

    admin_token = get_admin_token()
    if not admin_token:
        return {"success": False, "error": "Admin token not configured"}

    # Determine base URL
    if container_ip:
        base_url = f"http://{container_ip}:{SYNAPSE_PORT}"
    else:
        base_url = f"http://localhost:{SYNAPSE_PORT}"

    url = f"{base_url}/_synapse/admin/v1{endpoint}"
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }

    try:
        req_data = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as response:
            return {"success": True, "data": json.loads(response.read())}
    except urllib.error.HTTPError as e:
        try:
            error_body = e.read().decode()
            return {"success": False, "error": f"HTTP {e.code}: {error_body}"}
        except:
            return {"success": False, "error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════════
# LXC Helper Functions
# ══════════════════════════════════════════════════════════════════

def lxc_exists() -> bool:
    """Check if LXC container exists."""
    result = subprocess.run(
        ["lxc-info", "-n", LXC_NAME],
        capture_output=True, text=True
    )
    return result.returncode == 0


def lxc_running() -> bool:
    """Check if LXC container is running."""
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME, "-s"],
            capture_output=True, text=True, timeout=10
        )
        return "RUNNING" in result.stdout
    except Exception:
        return False


def lxc_get_ip() -> Optional[str]:
    """Get LXC container IP address."""
    try:
        result = subprocess.run(
            ["lxc-info", "-n", LXC_NAME, "-iH"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n")[0]
    except Exception:
        pass
    return None


def lxc_exec(cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """Execute command inside LXC container."""
    return subprocess.run(
        ["lxc-attach", "-n", LXC_NAME, "--"] + cmd,
        capture_output=True, text=True, timeout=timeout
    )


def lxc_start() -> bool:
    """Start the LXC container."""
    result = subprocess.run(
        ["lxc-start", "-n", LXC_NAME],
        capture_output=True, text=True
    )
    return result.returncode == 0


def lxc_stop() -> bool:
    """Stop the LXC container."""
    result = subprocess.run(
        ["lxc-stop", "-n", LXC_NAME],
        capture_output=True, text=True
    )
    return result.returncode == 0


# ══════════════════════════════════════════════════════════════════
# Request/Response Models
# ══════════════════════════════════════════════════════════════════

class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=8)
    admin: bool = False
    displayname: Optional[str] = None


class RoomCreate(BaseModel):
    name: str
    topic: Optional[str] = None
    public: bool = False
    invite: List[str] = []


class ConfigUpdate(BaseModel):
    server_name: Optional[str] = None
    enable_registration: Optional[bool] = None
    registration_requires_token: Optional[bool] = None
    allow_guest_access: Optional[bool] = None
    federation_enabled: Optional[bool] = None
    max_upload_size: Optional[str] = None
    url_preview_enabled: Optional[bool] = None
    enable_metrics: Optional[bool] = None


class FederationBlock(BaseModel):
    server_name: str
    reason: Optional[str] = ""


class RegistrationToken(BaseModel):
    uses_allowed: Optional[int] = 1
    expiry_time: Optional[int] = None  # Unix timestamp


# ══════════════════════════════════════════════════════════════════
# Status Endpoints
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok", "module": "matrix"}


@app.get("/status")
async def status(user=Depends(require_jwt)):
    """Get Matrix/Synapse status."""
    container_exists = lxc_exists()
    running = lxc_running() if container_exists else False
    container_ip = lxc_get_ip() if running else None

    version = None
    server_name = None
    users_count = 0
    rooms_count = 0

    if running and container_ip:
        # Get Synapse version
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"http://{container_ip}:{SYNAPSE_PORT}/_synapse/admin/v1/server_version")
                if r.status_code == 200:
                    data = r.json()
                    version = data.get("server_version")
        except Exception:
            pass

        # Try to get stats from admin API
        try:
            result = lxc_exec(["cat", "/data/homeserver.yaml"])
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip().startswith("server_name:"):
                        server_name = line.split(":", 1)[1].strip().strip('"')
                        break
        except Exception:
            pass

    # Get disk usage
    disk_usage = None
    if DATA_DIR.exists():
        try:
            result = subprocess.run(
                ["du", "-sh", str(DATA_DIR)],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                disk_usage = result.stdout.split()[0]
        except Exception:
            pass

    return {
        "container_exists": container_exists,
        "running": running,
        "container_ip": container_ip,
        "version": version,
        "server_name": server_name,
        "synapse_port": SYNAPSE_PORT,
        "federation_port": FEDERATION_PORT,
        "users_count": users_count,
        "rooms_count": rooms_count,
        "disk_usage": disk_usage,
    }


# ══════════════════════════════════════════════════════════════════
# Lifecycle Endpoints
# ══════════════════════════════════════════════════════════════════

@app.post("/install")
async def install(
    server_name: str = Query(..., description="Matrix server domain"),
    user=Depends(require_jwt)
):
    """Install Matrix Synapse in LXC container."""
    if lxc_exists():
        raise HTTPException(400, "Container already exists")

    log.info(f"Installing Matrix Synapse for {server_name}")

    # Create data directories
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Create LXC container
    result = subprocess.run([
        "lxc-create", "-n", LXC_NAME,
        "-t", "download",
        "--",
        "-d", "debian",
        "-r", "bookworm",
        "-a", "amd64"
    ], capture_output=True, text=True, timeout=600)

    if result.returncode != 0:
        raise HTTPException(500, f"Failed to create container: {result.stderr}")

    # Configure container
    lxc_config = f"/var/lib/lxc/{LXC_NAME}/config"
    with open(lxc_config, "a") as f:
        f.write(f"\n# SecuBox Matrix config\n")
        f.write(f"lxc.mount.entry = {DATA_DIR} data none bind,create=dir 0 0\n")
        f.write("lxc.start.auto = 1\n")

    # Start container
    if not lxc_start():
        raise HTTPException(500, "Failed to start container")

    # Wait for network
    import time
    for _ in range(30):
        if lxc_get_ip():
            break
        time.sleep(1)

    # Install Synapse
    install_script = f'''
#!/bin/bash
set -e

# Update and install dependencies
apt-get update
apt-get install -y wget gnupg apt-transport-https

# Add Matrix repo
wget -qO /usr/share/keyrings/matrix-org-archive-keyring.gpg https://packages.matrix.org/debian/matrix-org-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/matrix-org-archive-keyring.gpg] https://packages.matrix.org/debian/ bookworm main" > /etc/apt/sources.list.d/matrix-org.list

# Install Synapse
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y matrix-synapse-py3

# Generate config if not exists
if [ ! -f /data/homeserver.yaml ]; then
    cd /data
    python3 -m synapse.app.homeserver \\
        --server-name {server_name} \\
        --config-path /data/homeserver.yaml \\
        --generate-config \\
        --report-stats=no

    # Symlink data directory
    rm -rf /var/lib/matrix-synapse
    ln -s /data /var/lib/matrix-synapse
fi

# Configure systemd override
mkdir -p /etc/systemd/system/matrix-synapse.service.d
cat > /etc/systemd/system/matrix-synapse.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/usr/bin/python3 -m synapse.app.homeserver --config-path /data/homeserver.yaml
EOF

systemctl daemon-reload
systemctl enable matrix-synapse
systemctl start matrix-synapse
'''

    result = lxc_exec(["bash", "-c", install_script], timeout=600)

    if result.returncode != 0:
        log.error(f"Install failed: {result.stderr}")
        raise HTTPException(500, f"Installation failed: {result.stderr[:500]}")

    log.info("Matrix Synapse installed successfully")
    return {"success": True, "message": f"Matrix installed for {server_name}"}


@app.post("/start")
async def start(user=Depends(require_jwt)):
    """Start Matrix container."""
    if not lxc_exists():
        raise HTTPException(400, "Container not installed")

    if lxc_running():
        return {"success": True, "message": "Already running"}

    if lxc_start():
        # Start Synapse inside container
        lxc_exec(["systemctl", "start", "matrix-synapse"])
        return {"success": True}

    raise HTTPException(500, "Failed to start container")


@app.post("/stop")
async def stop(user=Depends(require_jwt)):
    """Stop Matrix container."""
    if not lxc_running():
        return {"success": True, "message": "Already stopped"}

    # Stop Synapse gracefully
    lxc_exec(["systemctl", "stop", "matrix-synapse"])

    if lxc_stop():
        return {"success": True}

    raise HTTPException(500, "Failed to stop container")


@app.post("/restart")
async def restart(user=Depends(require_jwt)):
    """Restart Matrix services."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec(["systemctl", "restart", "matrix-synapse"])
    return {"success": result.returncode == 0}


@app.delete("/uninstall")
async def uninstall(user=Depends(require_jwt)):
    """Remove Matrix container (keeps data)."""
    if lxc_running():
        lxc_stop()

    if lxc_exists():
        result = subprocess.run(
            ["lxc-destroy", "-n", LXC_NAME],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise HTTPException(500, f"Failed to destroy: {result.stderr}")

    return {"success": True, "message": "Container removed, data preserved in /var/lib/secubox/matrix"}


# ══════════════════════════════════════════════════════════════════
# User Management
# ══════════════════════════════════════════════════════════════════

@app.get("/users")
async def list_users(user=Depends(require_jwt)):
    """List Matrix users."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    container_ip = lxc_get_ip()
    if not container_ip:
        raise HTTPException(500, "Cannot get container IP")

    # Use register_new_matrix_user to list or sqlite query
    result = lxc_exec([
        "sqlite3", "/data/homeserver.db",
        "SELECT name, admin, creation_ts FROM users ORDER BY creation_ts DESC LIMIT 100;"
    ])

    users = []
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 2:
                users.append({
                    "username": parts[0],
                    "admin": parts[1] == "1" if len(parts) > 1 else False,
                    "created": parts[2] if len(parts) > 2 else None,
                })

    return {"users": users}


@app.post("/users")
async def create_user(req: UserCreate, user=Depends(require_jwt)):
    """Create a new Matrix user."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    admin_flag = "-a" if req.admin else "-c"

    result = lxc_exec([
        "register_new_matrix_user",
        "-u", req.username,
        "-p", req.password,
        admin_flag,
        "-c", "/data/homeserver.yaml",
        "http://localhost:8008"
    ])

    if result.returncode != 0:
        raise HTTPException(500, f"Failed to create user: {result.stderr}")

    return {"success": True, "username": req.username}


@app.delete("/users/{username}")
async def delete_user(username: str, user=Depends(require_jwt)):
    """Deactivate a Matrix user."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    # Deactivate user via database
    result = lxc_exec([
        "sqlite3", "/data/homeserver.db",
        f"UPDATE users SET deactivated = 1 WHERE name = '@{username}:' || (SELECT server_name FROM homeserver);"
    ])

    return {"success": True, "message": f"User {username} deactivated"}


@app.post("/users/{username}/reset-password")
async def reset_password(
    username: str,
    password: str = Query(..., min_length=8),
    user=Depends(require_jwt)
):
    """Reset user password."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    # Use hash_password utility
    result = lxc_exec([
        "python3", "-c",
        f"from synapse.config.hashers import hash_provider; print(hash_provider.hash('{password}'))"
    ])

    if result.returncode != 0:
        raise HTTPException(500, "Failed to hash password")

    password_hash = result.stdout.strip()

    result = lxc_exec([
        "sqlite3", "/data/homeserver.db",
        f"UPDATE users SET password_hash = '{password_hash}' WHERE name LIKE '%{username}%';"
    ])

    return {"success": result.returncode == 0}


# ══════════════════════════════════════════════════════════════════
# Room Management
# ══════════════════════════════════════════════════════════════════

@app.get("/rooms")
async def list_rooms(user=Depends(require_jwt)):
    """List Matrix rooms."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec([
        "sqlite3", "/data/homeserver.db",
        "SELECT room_id, creator, is_public FROM rooms ORDER BY room_id LIMIT 100;"
    ])

    rooms = []
    if result.returncode == 0 and result.stdout.strip():
        for line in result.stdout.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 1:
                rooms.append({
                    "room_id": parts[0],
                    "creator": parts[1] if len(parts) > 1 else None,
                    "public": parts[2] == "1" if len(parts) > 2 else False,
                })

    return {"rooms": rooms}


# ══════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════

@app.get("/config")
async def get_config(user=Depends(require_jwt)):
    """Get Matrix Synapse configuration."""
    if not lxc_running():
        return {"error": "Container not running"}

    result = lxc_exec(["cat", "/data/homeserver.yaml"])
    if result.returncode != 0:
        raise HTTPException(500, "Failed to read config")

    # Parse key settings
    config = {
        "server_name": None,
        "enable_registration": False,
        "allow_guest_access": False,
        "federation_enabled": True,
        "max_upload_size": "50M",
    }

    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("server_name:"):
            config["server_name"] = line.split(":", 1)[1].strip().strip('"')
        elif line.startswith("enable_registration:"):
            config["enable_registration"] = "true" in line.lower()
        elif line.startswith("allow_guest_access:"):
            config["allow_guest_access"] = "true" in line.lower()
        elif line.startswith("max_upload_size:"):
            config["max_upload_size"] = line.split(":", 1)[1].strip().strip('"')

    return config


@app.post("/config")
async def update_config(req: ConfigUpdate, user=Depends(require_jwt)):
    """Update Matrix Synapse configuration."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    # Read current config
    result = lxc_exec(["cat", "/data/homeserver.yaml"])
    if result.returncode != 0:
        raise HTTPException(500, "Failed to read config")

    lines = result.stdout.splitlines()
    updated = []

    for line in lines:
        stripped = line.strip()

        if req.enable_registration is not None and stripped.startswith("enable_registration:"):
            line = f"enable_registration: {str(req.enable_registration).lower()}"
        elif req.allow_guest_access is not None and stripped.startswith("allow_guest_access:"):
            line = f"allow_guest_access: {str(req.allow_guest_access).lower()}"
        elif req.max_upload_size is not None and stripped.startswith("max_upload_size:"):
            line = f"max_upload_size: \"{req.max_upload_size}\""

        updated.append(line)

    # Write back
    config_content = "\n".join(updated)
    result = lxc_exec(["bash", "-c", f"cat > /data/homeserver.yaml << 'EOFCONFIG'\n{config_content}\nEOFCONFIG"])

    if result.returncode != 0:
        raise HTTPException(500, "Failed to write config")

    # Restart to apply
    lxc_exec(["systemctl", "restart", "matrix-synapse"])

    return {"success": True, "message": "Configuration updated"}


# ══════════════════════════════════════════════════════════════════
# Federation
# ══════════════════════════════════════════════════════════════════

@app.get("/federation")
async def federation_status(user=Depends(require_jwt)):
    """Get federation status."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    container_ip = lxc_get_ip()
    if not container_ip:
        return {"enabled": False, "error": "No IP"}

    # Check if federation port is listening
    result = lxc_exec(["ss", "-tlnp"])
    federation_listening = f":{FEDERATION_PORT}" in result.stdout

    return {
        "enabled": True,
        "port": FEDERATION_PORT,
        "listening": federation_listening,
        "container_ip": container_ip,
    }


# ══════════════════════════════════════════════════════════════════
# Logs
# ══════════════════════════════════════════════════════════════════

@app.get("/logs")
async def get_logs(
    lines: int = Query(100, ge=10, le=1000),
    user=Depends(require_jwt)
):
    """Get Matrix Synapse logs."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec(["journalctl", "-u", "matrix-synapse", "-n", str(lines), "--no-pager"])

    log_lines = result.stdout.splitlines() if result.returncode == 0 else []

    return {"logs": log_lines}


# ══════════════════════════════════════════════════════════════════
# Bridges (Element, Telegram, etc.)
# ══════════════════════════════════════════════════════════════════

@app.get("/bridges")
async def list_bridges(user=Depends(require_jwt)):
    """List available Matrix bridges."""
    bridges = [
        {"id": "telegram", "name": "Telegram", "installed": False, "description": "Bridge to Telegram"},
        {"id": "discord", "name": "Discord", "installed": False, "description": "Bridge to Discord"},
        {"id": "slack", "name": "Slack", "installed": False, "description": "Bridge to Slack"},
        {"id": "signal", "name": "Signal", "installed": False, "description": "Bridge to Signal"},
        {"id": "whatsapp", "name": "WhatsApp", "installed": False, "description": "Bridge to WhatsApp"},
        {"id": "irc", "name": "IRC", "installed": False, "description": "Bridge to IRC networks"},
    ]

    if lxc_running():
        # Check which bridges are installed
        for bridge in bridges:
            result = lxc_exec(["systemctl", "is-active", f"mautrix-{bridge['id']}"])
            bridge["installed"] = result.returncode == 0

    return {"bridges": bridges}


@app.post("/bridges/{bridge_id}/install")
async def install_bridge(bridge_id: str, user=Depends(require_jwt)):
    """Install a Matrix bridge."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    valid_bridges = ["telegram", "discord", "slack", "signal", "whatsapp"]
    if bridge_id not in valid_bridges:
        raise HTTPException(400, f"Invalid bridge: {bridge_id}")

    # Install mautrix bridge
    install_cmd = f"""
apt-get update
apt-get install -y python3-pip
pip3 install mautrix-{bridge_id}
"""

    result = lxc_exec(["bash", "-c", install_cmd], timeout=300)

    return {
        "success": result.returncode == 0,
        "bridge": bridge_id,
        "message": "Bridge installed - configure via /bridges/{bridge_id}/config"
    }


# ══════════════════════════════════════════════════════════════════
# Backup/Restore
# ══════════════════════════════════════════════════════════════════

@app.post("/backup")
async def create_backup(user=Depends(require_jwt)):
    """Create Matrix data backup."""
    backup_dir = Path("/var/lib/secubox/backups/matrix")
    backup_dir.mkdir(parents=True, exist_ok=True)

    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"matrix-backup-{timestamp}.tar.gz"

    # Stop Synapse for consistent backup
    was_running = lxc_running()
    if was_running:
        lxc_exec(["systemctl", "stop", "matrix-synapse"])

    try:
        result = subprocess.run([
            "tar", "-czf", str(backup_file),
            "-C", str(DATA_DIR.parent),
            DATA_DIR.name
        ], capture_output=True, text=True, timeout=600)

        if result.returncode != 0:
            raise HTTPException(500, f"Backup failed: {result.stderr}")

        size = backup_file.stat().st_size

        return {
            "success": True,
            "file": str(backup_file),
            "size": f"{size / 1024 / 1024:.1f} MB",
        }
    finally:
        if was_running:
            lxc_exec(["systemctl", "start", "matrix-synapse"])


# ══════════════════════════════════════════════════════════════════
# Element Web Client
# ══════════════════════════════════════════════════════════════════

@app.post("/element/install")
async def install_element(user=Depends(require_jwt)):
    """Install Element web client."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    install_script = """
#!/bin/bash
set -e

# Install nginx
apt-get install -y nginx

# Download Element Web
ELEMENT_VERSION=$(curl -s https://api.github.com/repos/vector-im/element-web/releases/latest | grep tag_name | cut -d'"' -f4)
wget -qO /tmp/element.tar.gz "https://github.com/vector-im/element-web/releases/download/${ELEMENT_VERSION}/element-${ELEMENT_VERSION}.tar.gz"
tar -xzf /tmp/element.tar.gz -C /var/www/
mv /var/www/element-* /var/www/element

# Configure Element
SERVER_NAME=$(grep server_name /data/homeserver.yaml | head -1 | awk '{print $2}' | tr -d '"')
cat > /var/www/element/config.json << EOF
{
    "default_server_config": {
        "m.homeserver": {
            "base_url": "https://${SERVER_NAME}",
            "server_name": "${SERVER_NAME}"
        }
    },
    "brand": "SecuBox Matrix",
    "defaultCountryCode": "FR"
}
EOF

# Nginx config
cat > /etc/nginx/sites-available/element << EOF
server {
    listen 80;
    root /var/www/element;
    index index.html;
    location / {
        try_files \\$uri \\$uri/ /index.html;
    }
}
EOF

ln -sf /etc/nginx/sites-available/element /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx
"""

    result = lxc_exec(["bash", "-c", install_script], timeout=300)

    return {
        "success": result.returncode == 0,
        "message": "Element web client installed",
        "url": f"http://{lxc_get_ip()}/"
    }


# ══════════════════════════════════════════════════════════════════
# Server Info
# ══════════════════════════════════════════════════════════════════

@app.get("/server/info")
async def server_info(user=Depends(require_jwt)):
    """Get detailed server information."""
    container_ip = lxc_get_ip() if lxc_running() else None

    info = {
        "version": None,
        "python_version": None,
        "total_rooms": 0,
        "total_users": 0,
        "total_local_users": 0
    }

    if not container_ip:
        return info

    # Get version via admin API
    result = synapse_admin_api("/server_version", container_ip=container_ip)
    if result["success"]:
        info["version"] = result["data"].get("server_version")
        info["python_version"] = result["data"].get("python_version")

    # Get room count
    rooms_result = synapse_admin_api("/rooms?limit=1", container_ip=container_ip)
    if rooms_result["success"]:
        info["total_rooms"] = rooms_result.get("data", {}).get("total_rooms", 0)

    # Get user count
    users_result = synapse_admin_api("/users?limit=1", container_ip=container_ip)
    if users_result["success"]:
        info["total_users"] = users_result.get("data", {}).get("total", 0)

    return info


# ══════════════════════════════════════════════════════════════════
# Container Management (Docker/Podman)
# ══════════════════════════════════════════════════════════════════

@app.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """Get Docker/Podman container status."""
    runtime = get_container_runtime()
    if not runtime:
        return {"available": False, "runtime": None}

    if not COMPOSE_FILE.exists():
        return {
            "available": True,
            "runtime": runtime,
            "deployed": False
        }

    result = run_cmd([runtime, "compose", "-f", str(COMPOSE_FILE), "ps", "--format", "json"])

    containers = []
    if result["success"]:
        try:
            data = json.loads(result["stdout"]) if result["stdout"].strip() else []
            if isinstance(data, list):
                for c in data:
                    containers.append({
                        "name": c.get("Name", ""),
                        "state": c.get("State", ""),
                        "health": c.get("Health", ""),
                        "ports": c.get("Ports", "")
                    })
        except json.JSONDecodeError:
            pass

    return {
        "available": True,
        "runtime": runtime,
        "deployed": COMPOSE_FILE.exists(),
        "containers": containers
    }


@app.post("/container/install")
async def container_install(
    server_name: str = Query(..., description="Matrix server domain"),
    user=Depends(require_jwt)
):
    """Install Matrix Synapse via Docker/Podman container."""
    runtime = get_container_runtime()
    if not runtime:
        raise HTTPException(400, "No container runtime available (install docker or podman)")

    # Create directories
    COMPOSE_DIR.mkdir(parents=True, exist_ok=True)
    data_dir = COMPOSE_DIR / "data"
    data_dir.mkdir(exist_ok=True)
    postgres_dir = COMPOSE_DIR / "postgres"
    postgres_dir.mkdir(exist_ok=True)

    # Generate compose file
    compose_content = f"""version: '3.8'
services:
  synapse:
    image: matrixdotorg/synapse:latest
    container_name: secubox-matrix-synapse
    restart: unless-stopped
    environment:
      - SYNAPSE_SERVER_NAME={server_name}
      - SYNAPSE_REPORT_STATS=no
    volumes:
      - {data_dir}:/data
    ports:
      - "{SYNAPSE_PORT}:8008"
      - "{FEDERATION_PORT}:8448"
    healthcheck:
      test: ["CMD", "curl", "-fSs", "http://localhost:8008/health"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 5s
    depends_on:
      - postgres

  postgres:
    image: postgres:15-alpine
    container_name: secubox-matrix-postgres
    restart: unless-stopped
    environment:
      - POSTGRES_USER=synapse
      - POSTGRES_PASSWORD=synapse_secubox_password
      - POSTGRES_DB=synapse
      - POSTGRES_INITDB_ARGS=--encoding=UTF-8 --lc-collate=C --lc-ctype=C
    volumes:
      - {postgres_dir}:/var/lib/postgresql/data
"""

    COMPOSE_FILE.write_text(compose_content)

    # Generate initial config
    result = run_cmd([
        runtime, "run", "--rm",
        "-v", f"{data_dir}:/data",
        "-e", f"SYNAPSE_SERVER_NAME={server_name}",
        "-e", "SYNAPSE_REPORT_STATS=no",
        "matrixdotorg/synapse:latest",
        "generate"
    ], timeout=300)

    if not result["success"]:
        raise HTTPException(500, f"Failed to generate config: {result.get('stderr', result.get('error'))}")

    log.info(f"Matrix Synapse container installed for {server_name}")
    return {"success": True, "message": f"Matrix container installed for {server_name}"}


@app.post("/container/start")
async def container_start(user=Depends(require_jwt)):
    """Start Matrix Docker/Podman containers."""
    runtime = get_container_runtime()
    if not runtime or not COMPOSE_FILE.exists():
        raise HTTPException(400, "Container setup not found")

    result = run_cmd([runtime, "compose", "-f", str(COMPOSE_FILE), "up", "-d"], timeout=120)

    if not result["success"]:
        raise HTTPException(500, result.get("stderr", "Failed to start containers"))

    return {"success": True}


@app.post("/container/stop")
async def container_stop(user=Depends(require_jwt)):
    """Stop Matrix Docker/Podman containers."""
    runtime = get_container_runtime()
    if not runtime or not COMPOSE_FILE.exists():
        raise HTTPException(400, "Container setup not found")

    result = run_cmd([runtime, "compose", "-f", str(COMPOSE_FILE), "stop"])

    if not result["success"]:
        raise HTTPException(500, result.get("stderr", "Failed to stop containers"))

    return {"success": True}


@app.post("/container/restart")
async def container_restart(user=Depends(require_jwt)):
    """Restart Matrix Docker/Podman containers."""
    runtime = get_container_runtime()
    if not runtime or not COMPOSE_FILE.exists():
        raise HTTPException(400, "Container setup not found")

    result = run_cmd([runtime, "compose", "-f", str(COMPOSE_FILE), "restart"])

    if not result["success"]:
        raise HTTPException(500, result.get("stderr", "Failed to restart containers"))

    return {"success": True}


# ══════════════════════════════════════════════════════════════════
# Federation Management (Enhanced)
# ══════════════════════════════════════════════════════════════════

@app.get("/federation/status")
async def get_federation_status(user=Depends(require_jwt)):
    """Get federation status."""
    container_ip = lxc_get_ip() if lxc_running() else None
    if not container_ip:
        return {"enabled": False, "total_peers": 0, "active_peers": 0}

    result = synapse_admin_api("/federation/destinations", container_ip=container_ip)

    if not result["success"]:
        return {"enabled": False, "error": result.get("error")}

    destinations = result["data"].get("destinations", [])
    return {
        "enabled": True,
        "total_peers": result["data"].get("total", 0),
        "active_peers": len([d for d in destinations if d.get("last_successful_stream_ordering")])
    }


@app.get("/federation/peers")
async def get_federation_peers(
    start: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    user=Depends(require_jwt)
):
    """List federated servers."""
    container_ip = lxc_get_ip() if lxc_running() else None
    if not container_ip:
        raise HTTPException(400, "Container not running")

    result = synapse_admin_api(f"/federation/destinations?from={start}&limit={limit}", container_ip=container_ip)

    if not result["success"]:
        raise HTTPException(503, result.get("error", "Failed to get federation data"))

    peers = []
    for d in result["data"].get("destinations", []):
        peers.append({
            "destination": d.get("destination", ""),
            "retry_last_ts": d.get("retry_last_ts", 0),
            "retry_interval": d.get("retry_interval", 0),
            "failure_ts": d.get("failure_ts"),
            "last_successful": d.get("last_successful_stream_ordering") is not None
        })

    return {
        "peers": peers,
        "total": result["data"].get("total", 0)
    }


@app.post("/federation/block")
async def block_federation_server(block: FederationBlock, user=Depends(require_jwt)):
    """Block a federated server."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    # Read current config
    result = lxc_exec(["cat", "/data/homeserver.yaml"])
    if result.returncode != 0:
        raise HTTPException(500, "Failed to read config")

    # Parse YAML and add to blacklist
    config_lines = result.stdout.splitlines()
    blacklist_found = False
    updated = []

    for line in config_lines:
        if line.strip().startswith("federation_domain_blacklist:"):
            blacklist_found = True
            updated.append(line)
            updated.append(f"  - {block.server_name}")
        else:
            updated.append(line)

    if not blacklist_found:
        updated.append(f"federation_domain_blacklist:")
        updated.append(f"  - {block.server_name}")

    config_content = "\n".join(updated)
    lxc_exec(["bash", "-c", f"cat > /data/homeserver.yaml << 'EOFCONFIG'\n{config_content}\nEOFCONFIG"])

    return {"success": True, "message": f"Blocked {block.server_name}. Restart required."}


# ══════════════════════════════════════════════════════════════════
# Media Storage Management
# ══════════════════════════════════════════════════════════════════

@app.get("/media/stats")
async def get_media_stats(user=Depends(require_jwt)):
    """Get media storage statistics."""
    local_size = 0
    remote_size = 0

    if lxc_running():
        # Get local media size
        result = lxc_exec(["du", "-sb", "/data/media_store/local_content"])
        if result.returncode == 0 and result.stdout.strip():
            try:
                local_size = int(result.stdout.split()[0])
            except (ValueError, IndexError):
                pass

        # Get remote media size
        result = lxc_exec(["du", "-sb", "/data/media_store/remote_content"])
        if result.returncode == 0 and result.stdout.strip():
            try:
                remote_size = int(result.stdout.split()[0])
            except (ValueError, IndexError):
                pass
    elif MEDIA_DIR.exists():
        # Direct filesystem access
        local_media = MEDIA_DIR / "local_content"
        remote_media = MEDIA_DIR / "remote_content"

        if local_media.exists():
            for f in local_media.rglob("*"):
                if f.is_file():
                    local_size += f.stat().st_size

        if remote_media.exists():
            for f in remote_media.rglob("*"):
                if f.is_file():
                    remote_size += f.stat().st_size

    return {
        "local_media_size_bytes": local_size,
        "local_media_size_mb": round(local_size / 1024 / 1024, 2),
        "remote_media_size_bytes": remote_size,
        "remote_media_size_mb": round(remote_size / 1024 / 1024, 2),
        "total_size_mb": round((local_size + remote_size) / 1024 / 1024, 2)
    }


@app.post("/media/purge")
async def purge_media(
    before_days: int = Query(30, ge=1, le=365),
    user=Depends(require_jwt)
):
    """Purge old remote media cache."""
    container_ip = lxc_get_ip() if lxc_running() else None
    if not container_ip:
        raise HTTPException(400, "Container not running")

    # Calculate timestamp (milliseconds)
    before_ts = int(time.time() * 1000) - (before_days * 24 * 60 * 60 * 1000)

    result = synapse_admin_api(
        f"/purge_media_cache?before_ts={before_ts}",
        method="POST",
        container_ip=container_ip
    )

    if not result["success"]:
        raise HTTPException(500, result.get("error", "Failed to purge media"))

    return {"success": True, "deleted": result["data"].get("deleted", 0)}


# ══════════════════════════════════════════════════════════════════
# Registration Token Management
# ══════════════════════════════════════════════════════════════════

@app.get("/registrations")
async def get_registration_settings(user=Depends(require_jwt)):
    """Get registration settings and tokens."""
    container_ip = lxc_get_ip() if lxc_running() else None

    settings = {
        "enabled": False,
        "requires_token": False,
        "tokens": []
    }

    if not container_ip:
        return settings

    # Get registration tokens
    result = synapse_admin_api("/registration_tokens", container_ip=container_ip)

    if result["success"]:
        settings["enabled"] = True
        for t in result["data"].get("registration_tokens", []):
            settings["tokens"].append({
                "token": t.get("token", ""),
                "uses_allowed": t.get("uses_allowed"),
                "pending": t.get("pending", 0),
                "completed": t.get("completed", 0),
                "expiry_time": t.get("expiry_time")
            })

    return settings


@app.post("/registrations/token")
async def create_registration_token(
    token_config: RegistrationToken,
    user=Depends(require_jwt)
):
    """Generate a registration token."""
    container_ip = lxc_get_ip() if lxc_running() else None
    if not container_ip:
        raise HTTPException(400, "Container not running")

    token = secrets.token_urlsafe(16)

    data = {"token": token}
    if token_config.uses_allowed is not None:
        data["uses_allowed"] = token_config.uses_allowed
    if token_config.expiry_time is not None:
        data["expiry_time"] = token_config.expiry_time

    result = synapse_admin_api("/registration_tokens/new", method="POST", data=data, container_ip=container_ip)

    if not result["success"]:
        raise HTTPException(500, result.get("error", "Failed to create token"))

    return {"success": True, "token": token}


@app.delete("/registrations/token/{token}")
async def delete_registration_token(token: str, user=Depends(require_jwt)):
    """Delete a registration token."""
    container_ip = lxc_get_ip() if lxc_running() else None
    if not container_ip:
        raise HTTPException(400, "Container not running")

    result = synapse_admin_api(f"/registration_tokens/{token}", method="DELETE", container_ip=container_ip)

    if not result["success"]:
        raise HTTPException(500, result.get("error", "Failed to delete token"))

    return {"success": True}


# ══════════════════════════════════════════════════════════════════
# Room Management (Enhanced)
# ══════════════════════════════════════════════════════════════════

@app.get("/room/{room_id:path}")
async def get_room_details(room_id: str, user=Depends(require_jwt)):
    """Get room details."""
    container_ip = lxc_get_ip() if lxc_running() else None
    if not container_ip:
        raise HTTPException(400, "Container not running")

    result = synapse_admin_api(f"/rooms/{room_id}", container_ip=container_ip)

    if not result["success"]:
        raise HTTPException(404, result.get("error", "Room not found"))

    return result["data"]


@app.delete("/room/{room_id:path}")
async def delete_room(
    room_id: str,
    purge: bool = True,
    user=Depends(require_jwt)
):
    """Delete a Matrix room."""
    container_ip = lxc_get_ip() if lxc_running() else None
    if not container_ip:
        raise HTTPException(400, "Container not running")

    result = synapse_admin_api(
        f"/rooms/{room_id}",
        method="DELETE",
        data={"purge": purge},
        container_ip=container_ip
    )

    if not result["success"]:
        raise HTTPException(500, result.get("error", "Failed to delete room"))

    return {"success": True, "delete_id": result["data"].get("delete_id")}


# ══════════════════════════════════════════════════════════════════
# User Management (Enhanced)
# ══════════════════════════════════════════════════════════════════

@app.post("/user/{user_id:path}/deactivate")
async def deactivate_user(
    user_id: str,
    erase: bool = False,
    user=Depends(require_jwt)
):
    """Deactivate a Matrix user."""
    container_ip = lxc_get_ip() if lxc_running() else None
    if not container_ip:
        raise HTTPException(400, "Container not running")

    result = synapse_admin_api(
        f"/deactivate/{user_id}",
        method="POST",
        data={"erase": erase},
        container_ip=container_ip
    )

    if not result["success"]:
        raise HTTPException(500, result.get("error", "Failed to deactivate user"))

    return {"success": True}
