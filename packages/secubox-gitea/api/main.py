"""SecuBox Gitea API - Git Server Management

Three-fold perspective:
1. Components: Gitea LXC container
2. Status: Running state, repos, users, storage
3. Access: HTTP URL, SSH URL, web interface

SecuBox is an appliance and network model - distributed peer applications.
"""
import subprocess
import os
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Gitea", version="1.0.0")
config = get_config("gitea")

CONTAINER = config.get("container_name", "gitea")
LXC_PATH = Path(config.get("lxc_path", "/srv/lxc"))
DATA_PATH = Path(config.get("data_path", "/srv/gitea"))
GITEA_VERSION = config.get("version", "1.22.6")
HTTP_PORT = config.get("http_port", 3000)
SSH_PORT = config.get("ssh_port", 2222)
DOMAIN = config.get("domain", "git.local")
LXC_IP = config.get("lxc_ip", "192.168.255.40")


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
