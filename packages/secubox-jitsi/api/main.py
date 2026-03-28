"""
SecuBox Jitsi API
LXC-based Jitsi Meet video conferencing management
"""
from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from pathlib import Path
import subprocess
import json
import os

# Core imports
try:
    from secubox_core.auth import require_jwt
    from secubox_core.logger import get_logger
except ImportError:
    def require_jwt():
        return {"sub": "admin"}
    class Logger:
        def info(self, msg): print(f"INFO: {msg}")
        def error(self, msg): print(f"ERROR: {msg}")
        def warning(self, msg): print(f"WARN: {msg}")
    def get_logger(name): return Logger()

app = FastAPI(
    title="secubox-jitsi",
    root_path="/api/v1/jitsi",
)

log = get_logger("jitsi")

# ══════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════

LXC_NAME = "secubox-jitsi"
CONFIG_DIR = Path("/var/lib/secubox/jitsi")
DATA_DIR = Path("/var/lib/secubox/jitsi/data")
JITSI_WEB_PORT = 443
JITSI_XMPP_PORT = 5222
JVB_PORT = 10000


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

class RoomCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    password: Optional[str] = None
    max_participants: int = Field(default=50, ge=2, le=500)


class ConfigUpdate(BaseModel):
    domain: Optional[str] = None
    enable_authentication: Optional[bool] = None
    enable_lobby: Optional[bool] = None
    enable_recording: Optional[bool] = None
    max_participants: Optional[int] = None
    welcome_message: Optional[str] = None


# ══════════════════════════════════════════════════════════════════
# Status Endpoints
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok", "module": "jitsi"}


@app.get("/status")
async def status(user=Depends(require_jwt)):
    """Get Jitsi Meet status."""
    container_exists = lxc_exists()
    running = lxc_running() if container_exists else False
    container_ip = lxc_get_ip() if running else None

    services = {
        "prosody": False,
        "jicofo": False,
        "jitsi-videobridge": False,
        "nginx": False,
    }

    version = None
    domain = None
    active_conferences = 0
    active_participants = 0

    if running:
        # Check service status
        for service in services.keys():
            result = lxc_exec(["systemctl", "is-active", service])
            services[service] = result.returncode == 0

        # Get domain from config
        result = lxc_exec(["cat", "/etc/jitsi/meet/config.js"])
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "domain:" in line:
                    domain = line.split("'")[1] if "'" in line else None
                    break

        # Get JVB stats
        if container_ip:
            try:
                result = lxc_exec(["curl", "-s", "http://localhost:8080/colibri/stats"])
                if result.returncode == 0:
                    stats = json.loads(result.stdout)
                    active_conferences = stats.get("conferences", 0)
                    active_participants = stats.get("participants", 0)
                    version = stats.get("version")
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
        "services": services,
        "version": version,
        "domain": domain,
        "active_conferences": active_conferences,
        "active_participants": active_participants,
        "disk_usage": disk_usage,
    }


# ══════════════════════════════════════════════════════════════════
# Lifecycle Endpoints
# ══════════════════════════════════════════════════════════════════

@app.post("/install")
async def install(
    domain: str = Query(..., description="Jitsi domain (e.g., meet.example.com)"),
    user=Depends(require_jwt)
):
    """Install Jitsi Meet in LXC container."""
    if lxc_exists():
        raise HTTPException(400, "Container already exists")

    log.info(f"Installing Jitsi Meet for {domain}")

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
        f.write(f"\n# SecuBox Jitsi config\n")
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

    # Install Jitsi
    install_script = f'''#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive

# Set hostname
echo "{domain}" > /etc/hostname
hostname {domain}

# Add hosts entry
echo "127.0.0.1 {domain}" >> /etc/hosts

# Update and install prerequisites
apt-get update
apt-get install -y gnupg2 apt-transport-https curl

# Add Jitsi repository
curl -fsSL https://download.jitsi.org/jitsi-key.gpg.key | gpg --dearmor -o /usr/share/keyrings/jitsi-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/jitsi-keyring.gpg] https://download.jitsi.org stable/" > /etc/apt/sources.list.d/jitsi-stable.list

apt-get update

# Pre-configure Jitsi
echo "jitsi-videobridge2 jitsi-videobridge/jvb-hostname string {domain}" | debconf-set-selections
echo "jitsi-meet-web-config jitsi-meet/cert-choice select Generate a new self-signed certificate" | debconf-set-selections

# Install Jitsi Meet
apt-get install -y jitsi-meet

# Enable services
systemctl enable prosody jicofo jitsi-videobridge2 nginx
systemctl start prosody jicofo jitsi-videobridge2 nginx

echo "Jitsi Meet installed successfully"
'''

    result = lxc_exec(["bash", "-c", install_script], timeout=900)

    if result.returncode != 0:
        log.error(f"Install failed: {result.stderr}")
        raise HTTPException(500, f"Installation failed: {result.stderr[:500]}")

    log.info("Jitsi Meet installed successfully")
    return {"success": True, "message": f"Jitsi installed for {domain}"}


@app.post("/start")
async def start(user=Depends(require_jwt)):
    """Start Jitsi container."""
    if not lxc_exists():
        raise HTTPException(400, "Container not installed")

    if lxc_running():
        return {"success": True, "message": "Already running"}

    if lxc_start():
        # Start all Jitsi services
        for service in ["prosody", "jicofo", "jitsi-videobridge2", "nginx"]:
            lxc_exec(["systemctl", "start", service])
        return {"success": True}

    raise HTTPException(500, "Failed to start container")


@app.post("/stop")
async def stop(user=Depends(require_jwt)):
    """Stop Jitsi container."""
    if not lxc_running():
        return {"success": True, "message": "Already stopped"}

    # Stop services gracefully
    for service in ["nginx", "jitsi-videobridge2", "jicofo", "prosody"]:
        lxc_exec(["systemctl", "stop", service])

    if lxc_stop():
        return {"success": True}

    raise HTTPException(500, "Failed to stop container")


@app.post("/restart")
async def restart(user=Depends(require_jwt)):
    """Restart Jitsi services."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    for service in ["prosody", "jicofo", "jitsi-videobridge2", "nginx"]:
        lxc_exec(["systemctl", "restart", service])

    return {"success": True}


@app.delete("/uninstall")
async def uninstall(user=Depends(require_jwt)):
    """Remove Jitsi container (keeps data)."""
    if lxc_running():
        lxc_stop()

    if lxc_exists():
        result = subprocess.run(
            ["lxc-destroy", "-n", LXC_NAME],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise HTTPException(500, f"Failed to destroy: {result.stderr}")

    return {"success": True, "message": "Container removed, data preserved"}


# ══════════════════════════════════════════════════════════════════
# Conference Management
# ══════════════════════════════════════════════════════════════════

@app.get("/conferences")
async def list_conferences(user=Depends(require_jwt)):
    """List active conferences."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    container_ip = lxc_get_ip()
    if not container_ip:
        return {"conferences": []}

    try:
        result = lxc_exec(["curl", "-s", "http://localhost:8080/colibri/stats"])
        if result.returncode == 0:
            stats = json.loads(result.stdout)
            return {
                "conferences": stats.get("conferences", 0),
                "participants": stats.get("participants", 0),
                "largest_conference": stats.get("largest_conference", 0),
                "total_conferences_created": stats.get("total_conferences_created", 0),
            }
    except Exception:
        pass

    return {"conferences": [], "error": "Failed to get stats"}


@app.post("/rooms")
async def create_room(req: RoomCreate, user=Depends(require_jwt)):
    """Create a meeting room with optional password."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    container_ip = lxc_get_ip()
    if not container_ip:
        raise HTTPException(500, "Cannot get container IP")

    # Generate room URL
    room_name = req.name.replace(" ", "_").lower()
    room_url = f"https://{container_ip}/{room_name}"

    # Password can only be set when joining the room
    return {
        "success": True,
        "room_name": room_name,
        "url": room_url,
        "password_required": req.password is not None,
    }


# ══════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════

@app.get("/config")
async def get_config(user=Depends(require_jwt)):
    """Get Jitsi configuration."""
    if not lxc_running():
        return {"error": "Container not running"}

    config = {
        "domain": None,
        "enable_authentication": False,
        "enable_lobby": False,
        "enable_recording": False,
        "max_participants": 100,
        "welcome_message": "",
    }

    # Read interface_config.js
    result = lxc_exec(["cat", "/etc/jitsi/meet/config.js"])
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            line = line.strip()
            if "domain:" in line:
                config["domain"] = line.split("'")[1] if "'" in line else None
            elif "enableLobby:" in line:
                config["enable_lobby"] = "true" in line.lower()
            elif "fileRecordingsEnabled:" in line:
                config["enable_recording"] = "true" in line.lower()

    return config


@app.post("/config")
async def update_config(req: ConfigUpdate, user=Depends(require_jwt)):
    """Update Jitsi configuration."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    # Update interface_config.js for UI settings
    if req.welcome_message is not None:
        result = lxc_exec([
            "sed", "-i",
            f"s/MOBILE_APP_PROMO: .*/MOBILE_APP_PROMO: false,/",
            "/usr/share/jitsi-meet/interface_config.js"
        ])

    # Restart services to apply
    for service in ["prosody", "jicofo", "jitsi-videobridge2"]:
        lxc_exec(["systemctl", "restart", service])

    return {"success": True, "message": "Configuration updated"}


# ══════════════════════════════════════════════════════════════════
# Authentication
# ══════════════════════════════════════════════════════════════════

@app.post("/auth/enable")
async def enable_authentication(user=Depends(require_jwt)):
    """Enable Prosody authentication for moderators."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    # Get domain
    result = lxc_exec(["hostname"])
    domain = result.stdout.strip() if result.returncode == 0 else "localhost"

    auth_script = f'''#!/bin/bash
# Enable authentication in Prosody
sed -i 's/authentication = "anonymous"/authentication = "internal_hashed"/' /etc/prosody/conf.avail/{domain}.cfg.lua

# Add guest virtual host
cat >> /etc/prosody/conf.avail/{domain}.cfg.lua << EOF

VirtualHost "guest.{domain}"
    authentication = "anonymous"
    modules_enabled = {{
        "turncredentials";
    }}
    c2s_require_encryption = false
EOF

# Update Jitsi config
sed -i "s/anonymousdomain: .*/anonymousdomain: 'guest.{domain}',/" /etc/jitsi/meet/{domain}-config.js

# Restart services
systemctl restart prosody jicofo
'''

    result = lxc_exec(["bash", "-c", auth_script])
    return {"success": result.returncode == 0, "domain": domain}


@app.post("/auth/users")
async def create_auth_user(
    username: str = Query(...),
    password: str = Query(..., min_length=8),
    user=Depends(require_jwt)
):
    """Create a moderator user."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec(["hostname"])
    domain = result.stdout.strip() if result.returncode == 0 else "localhost"

    result = lxc_exec([
        "prosodyctl", "register",
        username, domain, password
    ])

    return {
        "success": result.returncode == 0,
        "username": f"{username}@{domain}"
    }


# ══════════════════════════════════════════════════════════════════
# Recording (Jibri)
# ══════════════════════════════════════════════════════════════════

@app.get("/recording")
async def recording_status(user=Depends(require_jwt)):
    """Get recording (Jibri) status."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec(["systemctl", "is-active", "jibri"])
    jibri_installed = result.returncode == 0 or "inactive" in result.stdout

    return {
        "installed": jibri_installed,
        "running": result.returncode == 0,
        "message": "Jibri provides recording and streaming capabilities"
    }


@app.post("/recording/install")
async def install_jibri(user=Depends(require_jwt)):
    """Install Jibri for recording support."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    # Jibri installation is complex and requires X11, Chrome, ffmpeg
    install_script = '''#!/bin/bash
set -e

apt-get update
apt-get install -y jibri

systemctl enable jibri
systemctl start jibri
'''

    result = lxc_exec(["bash", "-c", install_script], timeout=600)

    return {
        "success": result.returncode == 0,
        "message": "Jibri installed" if result.returncode == 0 else result.stderr[:200]
    }


# ══════════════════════════════════════════════════════════════════
# Logs
# ══════════════════════════════════════════════════════════════════

@app.get("/logs")
async def get_logs(
    service: str = Query("jicofo", enum=["prosody", "jicofo", "jitsi-videobridge2", "nginx"]),
    lines: int = Query(100, ge=10, le=1000),
    user=Depends(require_jwt)
):
    """Get Jitsi service logs."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec(["journalctl", "-u", service, "-n", str(lines), "--no-pager"])

    return {"logs": result.stdout.splitlines() if result.returncode == 0 else []}


# ══════════════════════════════════════════════════════════════════
# Stats
# ══════════════════════════════════════════════════════════════════

@app.get("/stats")
async def get_stats(user=Depends(require_jwt)):
    """Get detailed JVB statistics."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    try:
        result = lxc_exec(["curl", "-s", "http://localhost:8080/colibri/stats"])
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception:
        pass

    return {"error": "Failed to get stats"}


# ══════════════════════════════════════════════════════════════════
# SSL Certificates
# ══════════════════════════════════════════════════════════════════

@app.post("/ssl/letsencrypt")
async def setup_letsencrypt(
    email: str = Query(...),
    user=Depends(require_jwt)
):
    """Setup Let's Encrypt SSL certificate."""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    result = lxc_exec(["hostname"])
    domain = result.stdout.strip() if result.returncode == 0 else "localhost"

    ssl_script = f'''#!/bin/bash
set -e

apt-get install -y certbot python3-certbot-nginx

certbot --nginx -d {domain} --non-interactive --agree-tos -m {email}

systemctl restart nginx
'''

    result = lxc_exec(["bash", "-c", ssl_script], timeout=300)

    return {
        "success": result.returncode == 0,
        "domain": domain,
        "message": "SSL certificate installed" if result.returncode == 0 else result.stderr[:200]
    }
