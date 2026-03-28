"""
SecuBox PeerTube API
LXC-based federated video platform management
"""
from fastapi import FastAPI, Depends, HTTPException, Query, UploadFile, File
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
    def require_jwt(): return {"sub": "admin"}
    class Logger:
        def info(self, msg): print(f"INFO: {msg}")
        def error(self, msg): print(f"ERROR: {msg}")
    def get_logger(name): return Logger()

app = FastAPI(title="secubox-peertube", root_path="/api/v1/peertube")
log = get_logger("peertube")

LXC_NAME = "secubox-peertube"
CONFIG_DIR = Path("/var/lib/secubox/peertube")
DATA_DIR = Path("/var/lib/secubox/peertube/data")
PEERTUBE_PORT = 9000


def lxc_exists() -> bool:
    return subprocess.run(["lxc-info", "-n", LXC_NAME], capture_output=True).returncode == 0

def lxc_running() -> bool:
    try:
        r = subprocess.run(["lxc-info", "-n", LXC_NAME, "-s"], capture_output=True, text=True, timeout=10)
        return "RUNNING" in r.stdout
    except: return False

def lxc_get_ip() -> Optional[str]:
    try:
        r = subprocess.run(["lxc-info", "-n", LXC_NAME, "-iH"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().split("\n")[0]
    except: pass
    return None

def lxc_exec(cmd: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["lxc-attach", "-n", LXC_NAME, "--"] + cmd, capture_output=True, text=True, timeout=timeout)

def lxc_start() -> bool:
    return subprocess.run(["lxc-start", "-n", LXC_NAME], capture_output=True).returncode == 0

def lxc_stop() -> bool:
    return subprocess.run(["lxc-stop", "-n", LXC_NAME], capture_output=True).returncode == 0


class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    email: str
    password: str = Field(..., min_length=8)
    role: str = Field(default="user", pattern="^(admin|moderator|user)$")

class ConfigUpdate(BaseModel):
    instance_name: Optional[str] = None
    instance_description: Optional[str] = None
    signup_enabled: Optional[bool] = None
    signup_requires_approval: Optional[bool] = None


@app.get("/health")
async def health():
    return {"status": "ok", "module": "peertube"}

@app.get("/status")
async def status(user=Depends(require_jwt)):
    container_exists = lxc_exists()
    running = lxc_running() if container_exists else False
    container_ip = lxc_get_ip() if running else None

    version = None
    domain = None
    users_count = 0
    videos_count = 0
    storage_used = None

    if running:
        # Get version
        r = lxc_exec(["cat", "/var/www/peertube/versions/peertube-latest/package.json"])
        if r.returncode == 0:
            try:
                pkg = json.loads(r.stdout)
                version = pkg.get("version")
            except: pass

        # Get stats from PostgreSQL
        r = lxc_exec(["sudo", "-u", "postgres", "psql", "-t", "-c",
                      "SELECT COUNT(*) FROM \"user\";", "peertube"])
        if r.returncode == 0:
            try: users_count = int(r.stdout.strip())
            except: pass

        r = lxc_exec(["sudo", "-u", "postgres", "psql", "-t", "-c",
                      "SELECT COUNT(*) FROM video;", "peertube"])
        if r.returncode == 0:
            try: videos_count = int(r.stdout.strip())
            except: pass

        # Storage
        r = lxc_exec(["du", "-sh", "/var/www/peertube/storage"])
        if r.returncode == 0:
            storage_used = r.stdout.split()[0]

    disk_usage = None
    if DATA_DIR.exists():
        try:
            r = subprocess.run(["du", "-sh", str(DATA_DIR)], capture_output=True, text=True)
            if r.returncode == 0: disk_usage = r.stdout.split()[0]
        except: pass

    return {
        "container_exists": container_exists,
        "running": running,
        "container_ip": container_ip,
        "version": version,
        "domain": domain,
        "users_count": users_count,
        "videos_count": videos_count,
        "storage_used": storage_used,
        "disk_usage": disk_usage,
        "port": PEERTUBE_PORT,
    }


@app.post("/install")
async def install(
    domain: str = Query(..., description="PeerTube domain"),
    admin_email: str = Query(..., description="Admin email"),
    user=Depends(require_jwt)
):
    if lxc_exists():
        raise HTTPException(400, "Container already exists")

    log.info(f"Installing PeerTube for {domain}")
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Create container
    r = subprocess.run([
        "lxc-create", "-n", LXC_NAME, "-t", "download", "--",
        "-d", "debian", "-r", "bookworm", "-a", "amd64"
    ], capture_output=True, text=True, timeout=600)

    if r.returncode != 0:
        raise HTTPException(500, f"Failed to create container: {r.stderr}")

    # Configure LXC
    lxc_config = f"/var/lib/lxc/{LXC_NAME}/config"
    with open(lxc_config, "a") as f:
        f.write(f"\n# SecuBox PeerTube\n")
        f.write(f"lxc.mount.entry = {DATA_DIR} data none bind,create=dir 0 0\n")
        f.write("lxc.start.auto = 1\n")

    if not lxc_start():
        raise HTTPException(500, "Failed to start container")

    import time
    for _ in range(30):
        if lxc_get_ip(): break
        time.sleep(1)

    install_script = f'''#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive

# Install dependencies
apt-get update
apt-get install -y curl sudo gnupg ca-certificates

# Add NodeSource repo (Node.js 18)
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -

# Install packages
apt-get install -y nodejs postgresql postgresql-contrib redis-server \
    ffmpeg python3 python3-dev g++ make openssl certbot nginx

# Create peertube user
useradd -m -d /var/www/peertube -s /bin/bash peertube || true

# Setup PostgreSQL
sudo -u postgres psql -c "CREATE USER peertube WITH PASSWORD 'peertube';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE peertube OWNER peertube;" 2>/dev/null || true
sudo -u postgres psql -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;" peertube 2>/dev/null || true
sudo -u postgres psql -c "CREATE EXTENSION IF NOT EXISTS unaccent;" peertube 2>/dev/null || true

# Download PeerTube
cd /var/www/peertube
sudo -u peertube mkdir -p versions config storage
cd versions

VERSION=$(curl -s https://api.github.com/repos/Chocobozzz/PeerTube/releases/latest | grep tag_name | cut -d'"' -f4)
sudo -u peertube wget -q "https://github.com/Chocobozzz/PeerTube/releases/download/${{VERSION}}/peertube-${{VERSION}}.zip"
sudo -u peertube unzip -q "peertube-${{VERSION}}.zip"
sudo -u peertube rm "peertube-${{VERSION}}.zip"
cd /var/www/peertube
sudo -u peertube ln -sf "versions/peertube-${{VERSION}}" peertube-latest

# Install dependencies
cd /var/www/peertube/peertube-latest
sudo -u peertube yarn install --production --pure-lockfile

# Create config
cat > /var/www/peertube/config/production.yaml << 'EOFCONFIG'
listen:
  hostname: '0.0.0.0'
  port: {PEERTUBE_PORT}

webserver:
  https: true
  hostname: '{domain}'
  port: 443

database:
  hostname: 'localhost'
  port: 5432
  name: 'peertube'
  username: 'peertube'
  password: 'peertube'

redis:
  hostname: 'localhost'
  port: 6379

smtp:
  transport: 'sendmail'
  sendmail: '/usr/sbin/sendmail'

storage:
  tmp: '/var/www/peertube/storage/tmp/'
  bin: '/var/www/peertube/storage/bin/'
  avatars: '/var/www/peertube/storage/avatars/'
  videos: '/var/www/peertube/storage/videos/'
  streaming_playlists: '/var/www/peertube/storage/streaming-playlists/'
  redundancy: '/var/www/peertube/storage/redundancy/'
  logs: '/var/www/peertube/storage/logs/'
  previews: '/var/www/peertube/storage/previews/'
  thumbnails: '/var/www/peertube/storage/thumbnails/'
  torrents: '/var/www/peertube/storage/torrents/'
  captions: '/var/www/peertube/storage/captions/'
  cache: '/var/www/peertube/storage/cache/'
  plugins: '/var/www/peertube/storage/plugins/'
  client_overrides: '/var/www/peertube/storage/client-overrides/'

admin:
  email: '{admin_email}'

signup:
  enabled: false
  requires_approval: true

instance:
  name: 'SecuBox PeerTube'
  short_description: 'Federated video platform'
  description: 'PeerTube instance powered by SecuBox'
EOFCONFIG

chown peertube:peertube /var/www/peertube/config/production.yaml

# Create storage directories
for dir in tmp bin avatars videos streaming-playlists redundancy logs previews thumbnails torrents captions cache plugins client-overrides; do
    sudo -u peertube mkdir -p "/var/www/peertube/storage/$dir"
done

# Systemd service
cat > /etc/systemd/system/peertube.service << 'EOFSVC'
[Unit]
Description=PeerTube daemon
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=peertube
Group=peertube
WorkingDirectory=/var/www/peertube/peertube-latest
ExecStart=/usr/bin/node dist/server
Environment=NODE_ENV=production
Environment=NODE_CONFIG_DIR=/var/www/peertube/config
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOFSVC

systemctl daemon-reload
systemctl enable postgresql redis-server peertube
systemctl start postgresql redis-server
sleep 3
systemctl start peertube

echo "PeerTube installed"
'''

    r = lxc_exec(["bash", "-c", install_script], timeout=900)

    if r.returncode != 0:
        log.error(f"Install failed: {r.stderr}")
        raise HTTPException(500, f"Installation failed: {r.stderr[:500]}")

    return {"success": True, "message": f"PeerTube installed for {domain}"}


@app.post("/start")
async def start(user=Depends(require_jwt)):
    if not lxc_exists(): raise HTTPException(400, "Container not installed")
    if lxc_running(): return {"success": True, "message": "Already running"}
    if lxc_start():
        lxc_exec(["systemctl", "start", "postgresql", "redis-server", "peertube"])
        return {"success": True}
    raise HTTPException(500, "Failed to start")

@app.post("/stop")
async def stop(user=Depends(require_jwt)):
    if not lxc_running(): return {"success": True, "message": "Already stopped"}
    lxc_exec(["systemctl", "stop", "peertube", "redis-server", "postgresql"])
    if lxc_stop(): return {"success": True}
    raise HTTPException(500, "Failed to stop")

@app.post("/restart")
async def restart(user=Depends(require_jwt)):
    if not lxc_running(): raise HTTPException(400, "Container not running")
    lxc_exec(["systemctl", "restart", "peertube"])
    return {"success": True}

@app.delete("/uninstall")
async def uninstall(user=Depends(require_jwt)):
    if lxc_running(): lxc_stop()
    if lxc_exists():
        subprocess.run(["lxc-destroy", "-n", LXC_NAME], capture_output=True)
    return {"success": True, "message": "Container removed, data preserved"}


@app.get("/users")
async def list_users(user=Depends(require_jwt)):
    if not lxc_running(): raise HTTPException(400, "Container not running")

    r = lxc_exec(["sudo", "-u", "postgres", "psql", "-t", "-A", "-F", "|", "-c",
                  'SELECT username, email, role, "createdAt" FROM "user" ORDER BY "createdAt" DESC LIMIT 50;',
                  "peertube"])

    users = []
    if r.returncode == 0 and r.stdout.strip():
        for line in r.stdout.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 3:
                users.append({
                    "username": parts[0],
                    "email": parts[1] if len(parts) > 1 else "",
                    "role": parts[2] if len(parts) > 2 else "user",
                })
    return {"users": users}

@app.post("/users")
async def create_user(req: UserCreate, user=Depends(require_jwt)):
    if not lxc_running(): raise HTTPException(400, "Container not running")

    cmd = f'''cd /var/www/peertube/peertube-latest && \
NODE_ENV=production NODE_CONFIG_DIR=/var/www/peertube/config \
npx ts-node --transpile-only ./scripts/create-user.ts \
--username "{req.username}" --email "{req.email}" --password "{req.password}" --role "{req.role}"'''

    r = lxc_exec(["bash", "-c", cmd], timeout=60)
    return {"success": r.returncode == 0, "username": req.username}


@app.get("/videos")
async def list_videos(
    limit: int = Query(20, ge=1, le=100),
    user=Depends(require_jwt)
):
    if not lxc_running(): raise HTTPException(400, "Container not running")

    r = lxc_exec(["sudo", "-u", "postgres", "psql", "-t", "-A", "-F", "|", "-c",
                  f'SELECT uuid, name, views, likes, duration, "createdAt" FROM video ORDER BY "createdAt" DESC LIMIT {limit};',
                  "peertube"])

    videos = []
    if r.returncode == 0 and r.stdout.strip():
        for line in r.stdout.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 4:
                videos.append({
                    "uuid": parts[0],
                    "name": parts[1],
                    "views": int(parts[2]) if parts[2].isdigit() else 0,
                    "likes": int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0,
                })
    return {"videos": videos}


@app.get("/config")
async def get_config(user=Depends(require_jwt)):
    if not lxc_running(): return {"error": "Container not running"}

    r = lxc_exec(["cat", "/var/www/peertube/config/production.yaml"])
    if r.returncode != 0: raise HTTPException(500, "Failed to read config")

    # Parse YAML simply
    config = {}
    for line in r.stdout.splitlines():
        if ":" in line and not line.strip().startswith("#"):
            key = line.split(":")[0].strip()
            value = ":".join(line.split(":")[1:]).strip().strip("'\"")
            config[key] = value
    return config


@app.get("/logs")
async def get_logs(lines: int = Query(100, ge=10, le=1000), user=Depends(require_jwt)):
    if not lxc_running(): raise HTTPException(400, "Container not running")
    r = lxc_exec(["journalctl", "-u", "peertube", "-n", str(lines), "--no-pager"])
    return {"logs": r.stdout.splitlines() if r.returncode == 0 else []}


@app.get("/stats")
async def get_stats(user=Depends(require_jwt)):
    if not lxc_running(): raise HTTPException(400, "Container not running")

    stats = {"users": 0, "videos": 0, "views": 0, "storage": "0"}

    r = lxc_exec(["sudo", "-u", "postgres", "psql", "-t", "-c", 'SELECT COUNT(*) FROM "user";', "peertube"])
    if r.returncode == 0: stats["users"] = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0

    r = lxc_exec(["sudo", "-u", "postgres", "psql", "-t", "-c", "SELECT COUNT(*) FROM video;", "peertube"])
    if r.returncode == 0: stats["videos"] = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0

    r = lxc_exec(["sudo", "-u", "postgres", "psql", "-t", "-c", "SELECT COALESCE(SUM(views), 0) FROM video;", "peertube"])
    if r.returncode == 0: stats["views"] = int(r.stdout.strip()) if r.stdout.strip().isdigit() else 0

    r = lxc_exec(["du", "-sh", "/var/www/peertube/storage/videos"])
    if r.returncode == 0: stats["storage"] = r.stdout.split()[0]

    return stats


@app.post("/backup")
async def create_backup(user=Depends(require_jwt)):
    backup_dir = Path("/var/lib/secubox/backups/peertube")
    backup_dir.mkdir(parents=True, exist_ok=True)

    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"peertube-backup-{timestamp}.tar.gz"

    was_running = lxc_running()
    if was_running:
        lxc_exec(["systemctl", "stop", "peertube"])

    # Dump database
    lxc_exec(["sudo", "-u", "postgres", "pg_dump", "-Fc", "peertube", "-f", "/tmp/peertube.dump"])

    try:
        r = subprocess.run([
            "tar", "-czf", str(backup_file),
            "-C", str(DATA_DIR.parent), DATA_DIR.name
        ], capture_output=True, text=True, timeout=600)

        if r.returncode != 0:
            raise HTTPException(500, f"Backup failed: {r.stderr}")

        return {
            "success": True,
            "file": str(backup_file),
            "size": f"{backup_file.stat().st_size / 1024 / 1024:.1f} MB"
        }
    finally:
        if was_running:
            lxc_exec(["systemctl", "start", "peertube"])
