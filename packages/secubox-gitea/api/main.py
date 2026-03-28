"""SecuBox Gitea API - Git Server Management

Three-fold perspective:
1. Components: Gitea LXC container
2. Status: Running state, repos, users, storage
3. Access: HTTP URL, SSH URL, web interface

SecuBox is an appliance and network model - distributed peer applications.

Enhanced features (v2.0.0):
- Repository activity tracking
- User activity history
- Clone/push statistics
- Storage quota management
- Webhook notifications
- Background health monitoring
"""
import subprocess
import os
import json
import time
import threading
import asyncio
import hashlib
import hmac
import httpx
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel, Field
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Gitea", version="2.0.0")
config = get_config("gitea")

CONTAINER = config.get("container_name", "gitea")
LXC_PATH = Path(config.get("lxc_path", "/srv/lxc"))
DATA_PATH = Path(config.get("data_path", "/srv/gitea"))
GITEA_VERSION = config.get("version", "1.22.6")
HTTP_PORT = config.get("http_port", 3000)
SSH_PORT = config.get("ssh_port", 2222)
DOMAIN = config.get("domain", "git.local")
LXC_IP = config.get("lxc_ip", "192.168.255.40")

# Data paths for enhanced features
MODULE_DATA_DIR = Path("/var/lib/secubox/gitea")
STATS_HISTORY_FILE = MODULE_DATA_DIR / "stats_history.json"
ACTIVITY_FILE = MODULE_DATA_DIR / "activity.json"
WEBHOOKS_FILE = MODULE_DATA_DIR / "webhooks.json"
QUOTA_FILE = MODULE_DATA_DIR / "quotas.json"

MODULE_DATA_DIR.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════

class QuotaConfig(BaseModel):
    max_repos_per_user: int = Field(default=100, ge=1)
    max_storage_mb: int = Field(default=5000, ge=100)
    max_file_size_mb: int = Field(default=100, ge=1)
    enabled: bool = True


class RepoActivity(BaseModel):
    repo: str
    owner: str
    action: str
    timestamp: str
    details: Optional[Dict[str, Any]] = None


class WebhookConfig(BaseModel):
    id: str
    url: str
    events: List[str] = ["repo_created", "user_created", "backup_complete"]
    secret: Optional[str] = None
    enabled: bool = True
    created_at: str
    last_triggered: Optional[str] = None
    failure_count: int = 0


# ═══════════════════════════════════════════════════════════════════════
# Stats Cache
# ═══════════════════════════════════════════════════════════════════════

class StatsCache:
    """Thread-safe stats cache with TTL."""
    def __init__(self, ttl_seconds: int = 60):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps[key] < self.ttl:
                    return self._cache[key]
                del self._cache[key]
                del self._timestamps[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()


stats_cache = StatsCache(ttl_seconds=60)


# ═══════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════

def _load_json(path: Path, default=None) -> Any:
    if default is None:
        default = {}
    try:
        if path.exists():
            return json.loads(path.read_text())
    except (json.JSONDecodeError, IOError):
        pass
    return default


def _save_json(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


async def _trigger_webhooks(event: str, payload: dict):
    """Trigger webhooks for events."""
    webhooks = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    for hook in webhooks.get("webhooks", []):
        if not hook.get("enabled", True):
            continue
        if event not in hook.get("events", []):
            continue

        try:
            data = {
                "event": event,
                "timestamp": datetime.now().isoformat(),
                "payload": payload,
                "source": "secubox-gitea"
            }

            headers = {"Content-Type": "application/json"}
            if hook.get("secret"):
                sig = hmac.new(
                    hook["secret"].encode(),
                    json.dumps(data).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers["X-SecuBox-Signature"] = f"sha256={sig}"

            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(hook["url"], json=data, headers=headers)

            hook["last_triggered"] = datetime.now().isoformat()
            hook["failure_count"] = 0
        except Exception:
            hook["failure_count"] = hook.get("failure_count", 0) + 1

    _save_json(WEBHOOKS_FILE, webhooks)


def _record_activity(action: str, details: dict):
    """Record activity for history."""
    activity = _load_json(ACTIVITY_FILE, {"records": []})
    activity["records"].append({
        "action": action,
        "timestamp": datetime.now().isoformat(),
        "details": details
    })
    # Keep last 1000 records
    activity["records"] = activity["records"][-1000:]
    _save_json(ACTIVITY_FILE, activity)


# ═══════════════════════════════════════════════════════════════════════
# Background Tasks
# ═══════════════════════════════════════════════════════════════════════

_health_monitor_task: Optional[asyncio.Task] = None


async def _periodic_health_monitor():
    """Monitor Gitea health and collect stats."""
    while True:
        try:
            await asyncio.sleep(60)  # Check every minute

            running = lxc_running()

            # Record stats snapshot
            history = _load_json(STATS_HISTORY_FILE, {"records": []})

            # Get storage usage
            storage_bytes = 0
            if DATA_PATH.exists():
                try:
                    result = subprocess.run(
                        ["du", "-sb", str(DATA_PATH)],
                        capture_output=True, text=True, timeout=30
                    )
                    if result.returncode == 0:
                        storage_bytes = int(result.stdout.split()[0])
                except:
                    pass

            # Count repos
            repo_count = 0
            repo_root = DATA_PATH / "git" / "repositories"
            if repo_root.exists():
                try:
                    result = subprocess.run(
                        ["find", str(repo_root), "-name", "*.git", "-type", "d"],
                        capture_output=True, text=True, timeout=10
                    )
                    repo_count = len([l for l in result.stdout.strip().split("\n") if l])
                except:
                    pass

            history["records"].append({
                "timestamp": datetime.now().isoformat(),
                "running": running,
                "storage_bytes": storage_bytes,
                "repo_count": repo_count
            })

            # Keep last 1440 records (24h)
            history["records"] = history["records"][-1440:]
            _save_json(STATS_HISTORY_FILE, history)

        except asyncio.CancelledError:
            break
        except Exception:
            pass


@app.on_event("startup")
async def startup_event():
    """Start background tasks."""
    global _health_monitor_task
    _health_monitor_task = asyncio.create_task(_periodic_health_monitor())


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks."""
    global _health_monitor_task
    if _health_monitor_task:
        _health_monitor_task.cancel()


def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def lxc_running() -> bool:
    """Check if LXC container is running"""
    success, out, _ = run_cmd(["lxc-info", "-n", CONTAINER, "-s"])
    return success and "RUNNING" in out


def lxc_exists() -> bool:
    """Check if LXC container exists"""
    return (LXC_PATH / CONTAINER / "rootfs").exists()


def lxc_attach(command: str, timeout: int = 30) -> tuple:
    """Execute command inside LXC container"""
    cmd = ["lxc-attach", "-n", CONTAINER, "--", "sh", "-c", command]
    return run_cmd(cmd, timeout)


# =============================================================================
# STATUS - Module state and health
# =============================================================================

@app.get("/status")
async def status():
    """Get unified Gitea status (public endpoint)"""
    running = lxc_running()
    installed = lxc_exists()

    # Count repositories
    repo_count = 0
    repo_root = DATA_PATH / "git" / "repositories"
    if repo_root.exists():
        try:
            result = subprocess.run(
                ["find", str(repo_root), "-name", "*.git", "-type", "d"],
                capture_output=True, text=True, timeout=10
            )
            repo_count = len([l for l in result.stdout.strip().split("\n") if l])
        except:
            pass

    # Count users
    user_count = 0
    db_file = DATA_PATH / "git" / "gitea.db"
    if db_file.exists():
        success, out, _ = run_cmd(["sqlite3", str(db_file), "SELECT COUNT(*) FROM user"])
        if success:
            try:
                user_count = int(out)
            except:
                pass

    # Storage usage
    storage = "0"
    if DATA_PATH.exists():
        success, out, _ = run_cmd(["du", "-sh", str(DATA_PATH)])
        if success:
            storage = out.split()[0]

    return {
        "module": "gitea",
        "version": GITEA_VERSION,
        "enabled": config.get("enabled", True),
        "domain": DOMAIN,
        "components": {
            "gitea": {
                "name": CONTAINER,
                "installed": installed,
                "running": running,
                "ip": LXC_IP if running else None,
            }
        },
        "repo_count": repo_count,
        "user_count": user_count,
        "storage": storage,
        "http_port": HTTP_PORT,
        "ssh_port": SSH_PORT,
        "running": running,
        "installed": installed,
    }


@app.get("/health")
async def health():
    """Health check endpoint"""
    running = lxc_running()
    return {
        "status": "ok" if running else "down",
        "gitea": "ok" if running else "down",
    }


# =============================================================================
# ACCESS - Connection URLs and configuration
# =============================================================================

@app.get("/access")
async def get_access():
    """Get connection URLs and client configuration (public)"""
    running = lxc_running()
    host = LXC_IP if running else DOMAIN

    return {
        "domain": DOMAIN,
        "http": {
            "url": f"http://{host}:{HTTP_PORT}",
            "clone_template": f"http://{host}:{HTTP_PORT}/OWNER/REPO.git",
        },
        "ssh": {
            "port": SSH_PORT,
            "clone_template": f"git@{host}:{SSH_PORT}/OWNER/REPO.git",
        },
        "web_interface": f"http://{host}:{HTTP_PORT}",
        "api": f"http://{host}:{HTTP_PORT}/api/v1",
        "running": running,
    }


# =============================================================================
# REPOSITORIES
# =============================================================================

@app.get("/repos", dependencies=[Depends(require_jwt)])
async def list_repos():
    """List all repositories"""
    repos = []
    repo_root = DATA_PATH / "git" / "repositories"

    if repo_root.exists():
        for owner_dir in repo_root.iterdir():
            if owner_dir.is_dir():
                for repo_dir in owner_dir.iterdir():
                    if repo_dir.is_dir() and repo_dir.suffix == ".git":
                        size = "0"
                        try:
                            result = subprocess.run(
                                ["du", "-sh", str(repo_dir)],
                                capture_output=True, text=True, timeout=5
                            )
                            if result.returncode == 0:
                                size = result.stdout.split()[0]
                        except:
                            pass

                        repos.append({
                            "name": repo_dir.stem,
                            "owner": owner_dir.name,
                            "path": str(repo_dir),
                            "size": size,
                            "clone_http": f"http://{LXC_IP}:{HTTP_PORT}/{owner_dir.name}/{repo_dir.stem}.git",
                            "clone_ssh": f"git@{LXC_IP}:{SSH_PORT}/{owner_dir.name}/{repo_dir.stem}.git",
                        })

    return {"repos": repos, "count": len(repos)}


# =============================================================================
# USERS
# =============================================================================

class UserCreate(BaseModel):
    username: str
    password: str
    email: str
    admin: bool = False


@app.get("/users", dependencies=[Depends(require_jwt)])
async def list_users():
    """List Gitea users"""
    users = []
    db_file = DATA_PATH / "git" / "gitea.db"

    if db_file.exists():
        success, out, _ = run_cmd([
            "sqlite3", "-separator", "|", str(db_file),
            "SELECT id, name, lower_name, email, is_admin, created_unix FROM user"
        ])
        if success:
            for line in out.split("\n"):
                if line:
                    parts = line.split("|")
                    if len(parts) >= 4:
                        users.append({
                            "id": parts[0],
                            "name": parts[1],
                            "email": parts[3] if len(parts) > 3 else "",
                            "is_admin": parts[4] == "1" if len(parts) > 4 else False
                        })

    return {"users": users, "count": len(users)}


@app.post("/user", dependencies=[Depends(require_jwt)])
async def create_user(user: UserCreate):
    """Create a new Gitea user"""
    if not lxc_running():
        raise HTTPException(400, "Service must be running")

    admin_flag = "--admin" if user.admin else ""
    cmd = f"su-exec git /usr/local/bin/gitea admin user create --username '{user.username}' --password '{user.password}' --email '{user.email}' {admin_flag} --config /etc/gitea/app.ini"

    success, out, err = lxc_attach(cmd)
    if success:
        return {"success": True, "message": f"User created: {user.username}"}
    raise HTTPException(500, f"Failed to create user: {err}")


@app.delete("/user/{username}", dependencies=[Depends(require_jwt)])
async def delete_user(username: str):
    """Delete a Gitea user"""
    if not lxc_running():
        raise HTTPException(400, "Service must be running")

    success, _, err = run_cmd(["/usr/sbin/giteactl", "user", "del", username])
    if success:
        return {"success": True, "message": f"User {username} deleted"}
    raise HTTPException(500, f"Failed: {err}")


# =============================================================================
# SERVICE CONTROL
# =============================================================================

@app.post("/start", dependencies=[Depends(require_jwt)])
async def start_service():
    """Start Gitea LXC container"""
    if lxc_running():
        raise HTTPException(400, "Service is already running")
    if not lxc_exists():
        raise HTTPException(400, "Container not installed")

    success, _, err = run_cmd(["/usr/sbin/giteactl", "start"])
    if success:
        return {"success": True, "message": "Service started"}
    raise HTTPException(500, f"Failed to start: {err}")


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop_service():
    """Stop Gitea LXC container"""
    if not lxc_running():
        raise HTTPException(400, "Service is not running")

    success, _, err = run_cmd(["/usr/sbin/giteactl", "stop"])
    if success:
        return {"success": True, "message": "Service stopped"}
    raise HTTPException(500, f"Failed to stop: {err}")


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart_service():
    """Restart Gitea LXC container"""
    success, _, err = run_cmd(["/usr/sbin/giteactl", "restart"])
    if success:
        return {"success": True, "message": "Service restarted"}
    raise HTTPException(500, f"Failed to restart: {err}")


@app.post("/install", dependencies=[Depends(require_jwt)])
async def install(background_tasks: BackgroundTasks):
    """Install Gitea (background task)"""
    if lxc_exists():
        raise HTTPException(400, "Already installed")

    def do_install():
        subprocess.run(["/usr/sbin/giteactl", "install"],
                      stdout=open("/var/log/gitea-install.log", "w"),
                      stderr=subprocess.STDOUT)

    background_tasks.add_task(do_install)
    return {
        "success": True,
        "message": "Installation started in background",
        "log_file": "/var/log/gitea-install.log"
    }


# =============================================================================
# MIGRATION
# =============================================================================

class MigrateRequest(BaseModel):
    source: str = "192.168.255.1"


@app.post("/migrate", dependencies=[Depends(require_jwt)])
async def migrate(req: MigrateRequest, background_tasks: BackgroundTasks):
    """Migrate Gitea data from OpenWrt source"""
    def do_migrate():
        subprocess.run(["/usr/sbin/giteactl", "migrate", req.source],
                      stdout=open("/var/log/gitea-migrate.log", "w"),
                      stderr=subprocess.STDOUT)

    background_tasks.add_task(do_migrate)
    return {"success": True, "message": f"Migration from {req.source} started"}


# =============================================================================
# BACKUP / RESTORE
# =============================================================================

@app.get("/backups", dependencies=[Depends(require_jwt)])
async def list_backups():
    """List available backups"""
    backups = []
    backup_dir = DATA_PATH / "backups"

    if backup_dir.exists():
        for f in backup_dir.glob("gitea_*.tar.gz"):
            stat = f.stat()
            backups.append({
                "name": f.name,
                "size": f"{stat.st_size // 1024 // 1024}M",
                "timestamp": int(stat.st_mtime),
            })

    return {"backups": sorted(backups, key=lambda x: x["timestamp"], reverse=True)}


@app.post("/backup", dependencies=[Depends(require_jwt)])
async def create_backup():
    """Create backup"""
    success, out, err = run_cmd(["/usr/sbin/giteactl", "backup"])
    if success:
        return {"success": True, "file": out}
    raise HTTPException(500, f"Backup failed: {err}")


@app.post("/restore/{backup_name}", dependencies=[Depends(require_jwt)])
async def restore_backup(backup_name: str, background_tasks: BackgroundTasks):
    """Restore from backup"""
    backup_file = DATA_PATH / "backups" / backup_name
    if not backup_file.exists():
        raise HTTPException(404, "Backup not found")

    def do_restore():
        subprocess.run(["/usr/sbin/giteactl", "restore", str(backup_file)],
                      stdout=open("/var/log/gitea-restore.log", "w"),
                      stderr=subprocess.STDOUT)

    background_tasks.add_task(do_restore)
    return {"success": True, "message": "Restore started"}


# =============================================================================
# LOGS & PROGRESS
# =============================================================================

@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = 100):
    """Get Gitea logs"""
    logs = []
    log_file = DATA_PATH / "log" / "gitea.log"

    if log_file.exists():
        success, out, _ = run_cmd(["tail", f"-n{lines}", str(log_file)])
        if success:
            logs = out.split("\n")

    return {"logs": logs}


@app.get("/install-progress", dependencies=[Depends(require_jwt)])
async def get_install_progress():
    """Get installation progress"""
    log_file = Path("/var/log/gitea-install.log")

    if not log_file.exists():
        return {"status": "not_started", "progress": 0, "message": "Not started"}

    content = log_file.read_text()

    if "Installation complete" in content:
        return {"status": "completed", "progress": 100, "message": "Completed"}

    if "ERROR" in content:
        return {"status": "error", "progress": 0, "message": "Installation failed"}

    # Estimate progress
    progress = 5
    message = "Initializing..."

    if "Gitea installed" in content:
        progress, message = 90, "Finalizing setup..."
    elif "Gitea binary installed" in content:
        progress, message = 70, "Configuring..."
    elif "Downloading Gitea" in content:
        progress, message = 50, "Downloading Gitea..."
    elif "Installing packages" in content:
        progress, message = 40, "Installing packages..."
    elif "Installing base system" in content:
        progress, message = 30, "Setting up container..."
    elif "Bootstrapping" in content:
        progress, message = 20, "Bootstrapping Alpine..."

    return {"status": "running", "progress": progress, "message": message}


# =============================================================================
# STORAGE & QUOTAS
# =============================================================================

@app.get("/storage", dependencies=[Depends(require_jwt)])
async def get_storage_stats():
    """Get detailed storage statistics."""
    cached = stats_cache.get("storage_stats")
    if cached:
        return cached

    storage = {
        "total_bytes": 0,
        "repos_bytes": 0,
        "lfs_bytes": 0,
        "avatars_bytes": 0,
        "attachments_bytes": 0,
        "breakdown": []
    }

    def get_dir_size(path: Path) -> int:
        if not path.exists():
            return 0
        try:
            result = subprocess.run(
                ["du", "-sb", str(path)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return int(result.stdout.split()[0])
        except:
            pass
        return 0

    # Repositories
    repo_path = DATA_PATH / "git" / "repositories"
    storage["repos_bytes"] = get_dir_size(repo_path)

    # LFS
    lfs_path = DATA_PATH / "git" / "lfs"
    storage["lfs_bytes"] = get_dir_size(lfs_path)

    # Avatars
    avatar_path = DATA_PATH / "avatars"
    storage["avatars_bytes"] = get_dir_size(avatar_path)

    # Attachments
    attach_path = DATA_PATH / "attachments"
    storage["attachments_bytes"] = get_dir_size(attach_path)

    storage["total_bytes"] = (
        storage["repos_bytes"] + storage["lfs_bytes"] +
        storage["avatars_bytes"] + storage["attachments_bytes"]
    )

    storage["breakdown"] = [
        {"name": "Repositories", "bytes": storage["repos_bytes"], "human": _human_bytes(storage["repos_bytes"])},
        {"name": "LFS Objects", "bytes": storage["lfs_bytes"], "human": _human_bytes(storage["lfs_bytes"])},
        {"name": "Avatars", "bytes": storage["avatars_bytes"], "human": _human_bytes(storage["avatars_bytes"])},
        {"name": "Attachments", "bytes": storage["attachments_bytes"], "human": _human_bytes(storage["attachments_bytes"])},
    ]

    storage["total_human"] = _human_bytes(storage["total_bytes"])

    stats_cache.set("storage_stats", storage)
    return storage


def _human_bytes(b: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


@app.get("/quotas", dependencies=[Depends(require_jwt)])
async def get_quotas():
    """Get quota configuration."""
    quotas = _load_json(QUOTA_FILE, {
        "max_repos_per_user": 100,
        "max_storage_mb": 5000,
        "max_file_size_mb": 100,
        "enabled": False
    })
    return quotas


@app.post("/quotas", dependencies=[Depends(require_jwt)])
async def set_quotas(config: QuotaConfig):
    """Configure storage quotas."""
    quotas = config.model_dump()
    _save_json(QUOTA_FILE, quotas)

    _record_activity("quota_updated", quotas)

    return {"status": "success", "quotas": quotas}


# =============================================================================
# ACTIVITY & HISTORY
# =============================================================================

@app.get("/activity", dependencies=[Depends(require_jwt)])
async def get_activity(
    limit: int = Query(default=100, le=1000),
    action: Optional[str] = None
):
    """Get activity history."""
    activity = _load_json(ACTIVITY_FILE, {"records": []})
    records = activity.get("records", [])

    if action:
        records = [r for r in records if r.get("action") == action]

    records = sorted(records, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "records": records[:limit],
        "total": len(records)
    }


@app.get("/stats/history", dependencies=[Depends(require_jwt)])
async def get_stats_history(hours: int = Query(default=24, le=168)):
    """Get stats history over time."""
    history = _load_json(STATS_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    # Filter by time
    cutoff = datetime.now() - timedelta(hours=hours)
    cutoff_str = cutoff.isoformat()
    records = [r for r in records if r.get("timestamp", "") >= cutoff_str]

    return {
        "records": records,
        "period_hours": hours
    }


# =============================================================================
# REPOSITORY DETAILS
# =============================================================================

@app.get("/repos/{owner}/{repo}", dependencies=[Depends(require_jwt)])
async def get_repo_details(owner: str, repo: str):
    """Get detailed repository information."""
    repo_path = DATA_PATH / "git" / "repositories" / owner / f"{repo}.git"

    if not repo_path.exists():
        raise HTTPException(404, "Repository not found")

    # Get size
    size_bytes = 0
    try:
        result = subprocess.run(
            ["du", "-sb", str(repo_path)],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            size_bytes = int(result.stdout.split()[0])
    except:
        pass

    # Get commit count (approximate from pack files)
    commit_count = 0
    try:
        # Count objects in pack files
        pack_dir = repo_path / "objects" / "pack"
        if pack_dir.exists():
            for pack in pack_dir.glob("*.idx"):
                result = subprocess.run(
                    ["git", "verify-pack", "-v", str(pack)],
                    capture_output=True, text=True, timeout=30, cwd=str(repo_path)
                )
                if result.returncode == 0:
                    commit_count += result.stdout.count(" commit ")
    except:
        pass

    # Get last modified
    last_modified = None
    try:
        stat = repo_path.stat()
        last_modified = datetime.fromtimestamp(stat.st_mtime).isoformat()
    except:
        pass

    return {
        "name": repo,
        "owner": owner,
        "path": str(repo_path),
        "size_bytes": size_bytes,
        "size_human": _human_bytes(size_bytes),
        "commit_count": commit_count,
        "last_modified": last_modified,
        "clone_http": f"http://{LXC_IP}:{HTTP_PORT}/{owner}/{repo}.git",
        "clone_ssh": f"git@{LXC_IP}:{SSH_PORT}/{owner}/{repo}.git"
    }


@app.delete("/repos/{owner}/{repo}", dependencies=[Depends(require_jwt)])
async def delete_repo(owner: str, repo: str, background_tasks: BackgroundTasks):
    """Delete a repository."""
    if not lxc_running():
        raise HTTPException(400, "Service must be running")

    repo_path = DATA_PATH / "git" / "repositories" / owner / f"{repo}.git"

    if not repo_path.exists():
        raise HTTPException(404, "Repository not found")

    # Use gitea CLI to delete properly
    cmd = f"su-exec git /usr/local/bin/gitea admin repo delete --user '{owner}' --repo '{repo}' --config /etc/gitea/app.ini"
    success, out, err = lxc_attach(cmd)

    if success:
        _record_activity("repo_deleted", {"owner": owner, "repo": repo})
        await _trigger_webhooks("repo_deleted", {"owner": owner, "repo": repo})
        return {"success": True, "message": f"Repository {owner}/{repo} deleted"}

    raise HTTPException(500, f"Failed to delete repository: {err}")


# =============================================================================
# WEBHOOKS
# =============================================================================

@app.get("/webhooks", dependencies=[Depends(require_jwt)])
async def list_webhooks():
    """List configured webhooks."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})
    return {
        "webhooks": data.get("webhooks", []),
        "available_events": [
            "repo_created", "repo_deleted", "user_created", "user_deleted",
            "backup_complete", "restore_complete", "service_start", "service_stop"
        ]
    }


class WebhookCreate(BaseModel):
    url: str
    events: List[str] = ["repo_created", "backup_complete"]
    secret: Optional[str] = None
    enabled: bool = True


@app.post("/webhooks", dependencies=[Depends(require_jwt)])
async def add_webhook(config: WebhookCreate):
    """Add a webhook."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    webhook_id = hashlib.sha256(f"{config.url}{time.time()}".encode()).hexdigest()[:12]

    webhook = {
        "id": webhook_id,
        "url": config.url,
        "events": config.events,
        "secret": config.secret,
        "enabled": config.enabled,
        "created_at": datetime.now().isoformat(),
        "last_triggered": None,
        "failure_count": 0
    }

    data["webhooks"].append(webhook)
    _save_json(WEBHOOKS_FILE, data)

    return {"status": "success", "webhook": webhook}


@app.delete("/webhooks/{webhook_id}", dependencies=[Depends(require_jwt)])
async def delete_webhook(webhook_id: str):
    """Delete a webhook."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    original_len = len(data["webhooks"])
    data["webhooks"] = [w for w in data["webhooks"] if w.get("id") != webhook_id]

    if len(data["webhooks"]) == original_len:
        raise HTTPException(status_code=404, detail="Webhook not found")

    _save_json(WEBHOOKS_FILE, data)
    return {"status": "success"}


@app.post("/webhooks/{webhook_id}/test", dependencies=[Depends(require_jwt)])
async def test_webhook(webhook_id: str):
    """Test a webhook with a sample payload."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    webhook = next((w for w in data["webhooks"] if w.get("id") == webhook_id), None)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    test_payload = {
        "event": "test",
        "timestamp": datetime.now().isoformat(),
        "payload": {"message": "This is a test webhook from SecuBox Gitea"}
    }

    try:
        headers = {"Content-Type": "application/json"}
        if webhook.get("secret"):
            sig = hmac.new(
                webhook["secret"].encode(),
                json.dumps(test_payload).encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-SecuBox-Signature"] = f"sha256={sig}"

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook["url"], json=test_payload, headers=headers)
            return {
                "status": "success",
                "response_code": resp.status_code,
                "response_body": resp.text[:500]
            }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# =============================================================================
# SUMMARY
# =============================================================================

@app.get("/summary", dependencies=[Depends(require_jwt)])
async def get_gitea_summary():
    """Get comprehensive Gitea summary."""
    running = lxc_running()
    installed = lxc_exists()

    # Get storage
    storage = await get_storage_stats()

    # Count repos and users
    repo_count = 0
    user_count = 0

    repo_root = DATA_PATH / "git" / "repositories"
    if repo_root.exists():
        try:
            result = subprocess.run(
                ["find", str(repo_root), "-name", "*.git", "-type", "d"],
                capture_output=True, text=True, timeout=10
            )
            repo_count = len([l for l in result.stdout.strip().split("\n") if l])
        except:
            pass

    db_file = DATA_PATH / "git" / "gitea.db"
    if db_file.exists():
        success, out, _ = run_cmd(["sqlite3", str(db_file), "SELECT COUNT(*) FROM user"])
        if success:
            try:
                user_count = int(out)
            except:
                pass

    # Get quotas
    quotas = _load_json(QUOTA_FILE, {"enabled": False})

    return {
        "service": {
            "installed": installed,
            "running": running,
            "version": GITEA_VERSION,
            "domain": DOMAIN
        },
        "stats": {
            "repositories": repo_count,
            "users": user_count,
            "storage_total": storage["total_human"],
            "storage_bytes": storage["total_bytes"]
        },
        "quotas": {
            "enabled": quotas.get("enabled", False),
            "max_storage_mb": quotas.get("max_storage_mb", 5000)
        },
        "access": {
            "http_port": HTTP_PORT,
            "ssh_port": SSH_PORT,
            "web_url": f"http://{LXC_IP}:{HTTP_PORT}" if running else None
        },
        "timestamp": datetime.now().isoformat()
    }


# =============================================================================
# EXPORT
# =============================================================================

@app.get("/export/repos", dependencies=[Depends(require_jwt)])
async def export_repos(format: str = Query(default="json", enum=["json", "csv"])):
    """Export repository list."""
    repos_result = await list_repos()
    repos = repos_result.get("repos", [])

    if format == "csv":
        lines = ["owner,name,size,clone_http"]
        for r in repos:
            lines.append(",".join([
                r.get("owner", ""),
                r.get("name", ""),
                r.get("size", ""),
                r.get("clone_http", "")
            ]))
        return {"format": "csv", "data": "\n".join(lines)}

    return {
        "format": "json",
        "exported_at": datetime.now().isoformat(),
        "repos": repos
    }


@app.get("/export/users", dependencies=[Depends(require_jwt)])
async def export_users(format: str = Query(default="json", enum=["json", "csv"])):
    """Export user list."""
    users_result = await list_users()
    users = users_result.get("users", [])

    if format == "csv":
        lines = ["id,name,email,is_admin"]
        for u in users:
            lines.append(",".join([
                str(u.get("id", "")),
                u.get("name", ""),
                u.get("email", ""),
                str(u.get("is_admin", False))
            ]))
        return {"format": "csv", "data": "\n".join(lines)}

    return {
        "format": "json",
        "exported_at": datetime.now().isoformat(),
        "users": users
    }
