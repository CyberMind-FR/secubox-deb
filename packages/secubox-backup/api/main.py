"""
SecuBox Backup Manager API
Backup system configs, LXC containers, and services
"""

from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List
from pathlib import Path
import subprocess
import os
import time

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/secubox/core')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "dev"}

app = FastAPI(title="SecuBox Backup API", version="1.0.0")

# Configuration
BACKUP_PATH = Path("/srv/backups")
LXC_PATH = Path("/srv/lxc")
CONFIG_PATHS = [
    "/etc/secubox",
    "/etc/nginx",
    "/etc/wireguard",
    "/etc/haproxy",
    "/etc/nftables.conf"
]


# Models
class BackupCreate(BaseModel):
    type: str = "full"  # full, config, containers, services


class RestoreRequest(BaseModel):
    file: str
    dry_run: bool = False


class ContainerBackup(BaseModel):
    name: str


class ContainerRestore(BaseModel):
    name: str
    file: str


# Helpers
def run_cmd(cmd: list, timeout: int = 300) -> tuple:
    """Run command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def get_dir_size(path: Path) -> str:
    """Get human-readable directory size"""
    try:
        result = subprocess.run(
            ["du", "-sh", str(path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return result.stdout.split()[0]
    except:
        pass
    return "0"


def get_file_size(path: Path) -> str:
    """Get human-readable file size"""
    try:
        result = subprocess.run(
            ["du", "-h", str(path)],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.split()[0]
    except:
        pass
    return "0"


def lxc_running(name: str) -> bool:
    """Check if LXC container is running"""
    success, out, _ = run_cmd(["lxc-info", "-P", str(LXC_PATH), "-n", name, "-s"])
    return success and "RUNNING" in out


def list_backups(backup_type: str = "all") -> List[dict]:
    """List backup files"""
    backups = []

    types_to_check = []
    if backup_type == "all":
        types_to_check = ["config", "containers", "services"]
    else:
        types_to_check = [backup_type]

    for btype in types_to_check:
        type_dir = BACKUP_PATH / btype
        if not type_dir.exists():
            continue

        for f in type_dir.glob("*.tar*"):
            if f.is_file():
                stat = f.stat()
                backups.append({
                    "file": f.name,
                    "type": btype,
                    "size": get_file_size(f),
                    "timestamp": int(stat.st_mtime)
                })

    return sorted(backups, key=lambda x: x["timestamp"], reverse=True)


def ensure_backup_dirs():
    """Ensure backup directories exist"""
    for subdir in ["config", "containers", "services"]:
        (BACKUP_PATH / subdir).mkdir(parents=True, exist_ok=True)


# Public endpoints
@app.get("/status")
async def get_status():
    """Get backup system status"""
    ensure_backup_dirs()

    # Storage info
    storage_used = get_dir_size(BACKUP_PATH)

    # Last backup times per type
    last_backup = {}
    for btype in ["config", "containers", "services"]:
        type_dir = BACKUP_PATH / btype
        latest = None
        latest_time = 0

        if type_dir.exists():
            for f in type_dir.glob("*.tar*"):
                mtime = f.stat().st_mtime
                if mtime > latest_time:
                    latest_time = mtime
                    latest = f

        last_backup[btype] = int(latest_time) if latest else 0

    # Container count
    container_count = 0
    if LXC_PATH.exists():
        container_count = len([d for d in LXC_PATH.iterdir() if d.is_dir() and (d / "config").exists()])

    return {
        "storage_path": str(BACKUP_PATH),
        "storage_used": storage_used,
        "last_backup": last_backup,
        "container_count": container_count
    }


@app.get("/list")
async def list_all_backups(type: str = Query("all", description="Backup type: all, config, containers, services")):
    """List backup files"""
    return {"backups": list_backups(type)}


@app.get("/containers")
async def list_containers():
    """List LXC containers with backup info"""
    containers = []

    if not LXC_PATH.exists():
        return {"containers": []}

    for container_dir in LXC_PATH.iterdir():
        if not container_dir.is_dir():
            continue
        if not (container_dir / "config").exists():
            continue

        name = container_dir.name
        state = "running" if lxc_running(name) else "stopped"
        size = get_dir_size(container_dir)

        # Count backups for this container
        backup_count = 0
        containers_backup_dir = BACKUP_PATH / "containers"
        if containers_backup_dir.exists():
            backup_count = len(list(containers_backup_dir.glob(f"{name}-*.tar*")))

        containers.append({
            "name": name,
            "state": state,
            "size": size,
            "backups": backup_count
        })

    return {"containers": containers}


# Protected endpoints
@app.post("/create")
async def create_backup(req: BackupCreate, user: dict = Depends(require_jwt)):
    """Create a backup"""
    ensure_backup_dirs()

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    outputs = []

    if req.type in ["full", "config"]:
        # Backup config files
        archive = BACKUP_PATH / "config" / f"config-{timestamp}.tar.gz"
        existing_paths = [p for p in CONFIG_PATHS if os.path.exists(p)]

        if existing_paths:
            success, out, err = run_cmd(
                ["tar", "-czf", str(archive)] + existing_paths,
                timeout=300
            )
            if success:
                outputs.append(f"Config backup: {archive.name}")
            else:
                outputs.append(f"Config backup failed: {err}")

    if req.type in ["full", "containers"]:
        # Backup all containers
        if LXC_PATH.exists():
            for container_dir in LXC_PATH.iterdir():
                if not container_dir.is_dir():
                    continue
                if not (container_dir / "config").exists():
                    continue

                name = container_dir.name
                archive = BACKUP_PATH / "containers" / f"{name}-{timestamp}.tar.gz"

                # Stop if running for consistent backup
                was_running = lxc_running(name)
                if was_running:
                    run_cmd(["lxc-stop", "-P", str(LXC_PATH), "-n", name])

                success, out, err = run_cmd(
                    ["tar", "-czf", str(archive), "-C", str(LXC_PATH), name],
                    timeout=600
                )

                if was_running:
                    run_cmd(["lxc-start", "-P", str(LXC_PATH), "-n", name])

                if success:
                    outputs.append(f"Container backup: {name}")
                else:
                    outputs.append(f"Container {name} failed: {err}")

    if req.type in ["full", "services"]:
        # Backup service data
        service_paths = [
            "/var/lib/secubox",
            "/srv/nextcloud/data",
            "/srv/gitea/data"
        ]
        existing = [p for p in service_paths if os.path.exists(p)]

        if existing:
            archive = BACKUP_PATH / "services" / f"services-{timestamp}.tar.gz"
            success, out, err = run_cmd(
                ["tar", "-czf", str(archive)] + existing,
                timeout=600
            )
            if success:
                outputs.append(f"Services backup: {archive.name}")
            else:
                outputs.append(f"Services backup failed: {err}")

    return {
        "code": 0 if outputs else 1,
        "output": "\n".join(outputs) if outputs else "No backups created"
    }


@app.post("/restore")
async def restore_backup(req: RestoreRequest, user: dict = Depends(require_jwt)):
    """Restore from a backup file"""
    # Find the backup file
    backup_file = None
    for btype in ["config", "containers", "services"]:
        candidate = BACKUP_PATH / btype / req.file
        if candidate.exists():
            backup_file = candidate
            break

    if not backup_file:
        raise HTTPException(status_code=404, detail="Backup file not found")

    if req.dry_run:
        # List contents
        success, out, err = run_cmd(["tar", "-tzf", str(backup_file)])
        return {
            "code": 0 if success else 1,
            "output": out if success else err,
            "dry_run": True
        }

    # Determine restore location
    if "config" in str(backup_file.parent):
        success, out, err = run_cmd(
            ["tar", "-xzf", str(backup_file), "-C", "/"],
            timeout=300
        )
    elif "containers" in str(backup_file.parent):
        success, out, err = run_cmd(
            ["tar", "-xzf", str(backup_file), "-C", str(LXC_PATH)],
            timeout=600
        )
    else:
        success, out, err = run_cmd(
            ["tar", "-xzf", str(backup_file), "-C", "/"],
            timeout=600
        )

    return {
        "code": 0 if success else 1,
        "output": "Restore completed" if success else err
    }


@app.post("/cleanup")
async def cleanup_backups(user: dict = Depends(require_jwt)):
    """Remove old backups (keep last 5 per type)"""
    removed = []

    for btype in ["config", "containers", "services"]:
        type_dir = BACKUP_PATH / btype
        if not type_dir.exists():
            continue

        files = sorted(type_dir.glob("*.tar*"), key=lambda x: x.stat().st_mtime, reverse=True)

        # Keep last 5
        for f in files[5:]:
            try:
                f.unlink()
                removed.append(f.name)
            except:
                pass

    return {
        "code": 0,
        "removed": removed,
        "output": f"Removed {len(removed)} old backups"
    }


@app.post("/container/backup")
async def backup_container(req: ContainerBackup, user: dict = Depends(require_jwt)):
    """Backup a specific container"""
    container_dir = LXC_PATH / req.name

    if not container_dir.exists() or not (container_dir / "config").exists():
        raise HTTPException(status_code=404, detail="Container not found")

    ensure_backup_dirs()
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    archive = BACKUP_PATH / "containers" / f"{req.name}-{timestamp}.tar.gz"

    # Stop if running
    was_running = lxc_running(req.name)
    if was_running:
        run_cmd(["lxc-stop", "-P", str(LXC_PATH), "-n", req.name])

    success, out, err = run_cmd(
        ["tar", "-czf", str(archive), "-C", str(LXC_PATH), req.name],
        timeout=600
    )

    if was_running:
        run_cmd(["lxc-start", "-P", str(LXC_PATH), "-n", req.name])

    return {
        "code": 0 if success else 1,
        "output": f"Backup created: {archive.name}" if success else err
    }


@app.post("/container/restore")
async def restore_container(req: ContainerRestore, user: dict = Depends(require_jwt)):
    """Restore a specific container from backup"""
    backup_file = BACKUP_PATH / "containers" / req.file

    if not backup_file.exists():
        raise HTTPException(status_code=404, detail="Backup file not found")

    container_dir = LXC_PATH / req.name

    # Stop if running
    if container_dir.exists() and lxc_running(req.name):
        run_cmd(["lxc-stop", "-P", str(LXC_PATH), "-n", req.name])

    # Remove existing
    if container_dir.exists():
        run_cmd(["rm", "-rf", str(container_dir)])

    # Extract backup
    success, out, err = run_cmd(
        ["tar", "-xzf", str(backup_file), "-C", str(LXC_PATH)],
        timeout=600
    )

    return {
        "code": 0 if success else 1,
        "output": f"Container {req.name} restored" if success else err
    }


@app.get("/info")
async def get_info():
    """Get module info"""
    return {
        "module": "secubox-backup",
        "version": "1.0.0",
        "description": "Backup Manager for system configs and LXC containers"
    }
