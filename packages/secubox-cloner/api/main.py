"""SecuBox Cloner API - System backup and restore."""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import subprocess
import json
import os
import shutil
import tarfile
from datetime import datetime
from pathlib import Path

app = FastAPI(title="SecuBox Cloner API", version="1.0.0")

BACKUP_DIR = "/var/lib/secubox/backups"
CONFIG_FILE = "/etc/secubox/cloner.json"
STATE_FILE = "/var/lib/secubox/cloner/state.json"

# Default paths to backup
DEFAULT_PATHS = [
    "/etc/secubox",
    "/var/lib/secubox",
    "/etc/nginx/secubox.d",
    "/usr/share/secubox"
]

# Paths to exclude
EXCLUDE_PATHS = [
    "/var/lib/secubox/backups",
    "*.sock",
    "*.pid",
    "__pycache__",
    "*.pyc"
]


class BackupConfig(BaseModel):
    name: str = ""
    paths: list = DEFAULT_PATHS
    exclude: list = EXCLUDE_PATHS
    compress: bool = True
    description: str = ""


class RestoreConfig(BaseModel):
    backup_id: str
    target_path: str = "/"
    dry_run: bool = False


class ScheduleConfig(BaseModel):
    enabled: bool = True
    interval: str = "daily"  # daily, weekly, monthly
    retention: int = 7  # keep last N backups
    time: str = "03:00"


def run_cmd(cmd: list, timeout: int = 300) -> tuple:
    """Run command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def load_config() -> dict:
    """Load cloner configuration."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "paths": DEFAULT_PATHS,
        "exclude": EXCLUDE_PATHS,
        "schedule": {"enabled": False, "interval": "daily", "retention": 7, "time": "03:00"}
    }


def save_config(config: dict):
    """Save cloner configuration."""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def load_state() -> dict:
    """Load cloner state."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {"running": False, "last_backup": None, "last_error": None}


def save_state(state: dict):
    """Save cloner state."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)


def get_backup_list() -> list:
    """List all backups."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backups = []

    for entry in os.listdir(BACKUP_DIR):
        path = os.path.join(BACKUP_DIR, entry)
        if os.path.isfile(path) and entry.endswith(('.tar.gz', '.tar')):
            stat = os.stat(path)

            # Try to load metadata
            meta_file = path + '.meta.json'
            meta = {}
            if os.path.exists(meta_file):
                try:
                    with open(meta_file, 'r') as f:
                        meta = json.load(f)
                except Exception:
                    pass

            backups.append({
                "id": entry,
                "path": path,
                "size": stat.st_size,
                "size_human": format_size(stat.st_size),
                "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "description": meta.get("description", ""),
                "paths": meta.get("paths", [])
            })

    backups.sort(key=lambda x: x["created"], reverse=True)
    return backups


def format_size(size: int) -> str:
    """Format size in human readable form."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def get_disk_usage() -> dict:
    """Get disk usage for backup directory."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stat = shutil.disk_usage(BACKUP_DIR)
    return {
        "total": stat.total,
        "used": stat.used,
        "free": stat.free,
        "total_human": format_size(stat.total),
        "used_human": format_size(stat.used),
        "free_human": format_size(stat.free),
        "percent_used": round((stat.used / stat.total) * 100, 1)
    }


def create_backup_sync(config: BackupConfig) -> dict:
    """Create a backup synchronously."""
    os.makedirs(BACKUP_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = config.name or f"backup-{timestamp}"

    if config.compress:
        filename = f"{name}.tar.gz"
        mode = "w:gz"
    else:
        filename = f"{name}.tar"
        mode = "w"

    backup_path = os.path.join(BACKUP_DIR, filename)

    state = load_state()
    state["running"] = True
    state["current_backup"] = filename
    save_state(state)

    try:
        with tarfile.open(backup_path, mode) as tar:
            for path in config.paths:
                if os.path.exists(path):
                    # Add with relative path
                    arcname = path.lstrip('/')

                    def exclude_filter(tarinfo):
                        for excl in config.exclude:
                            if excl.startswith('*'):
                                if tarinfo.name.endswith(excl[1:]):
                                    return None
                            elif excl in tarinfo.name:
                                return None
                        return tarinfo

                    tar.add(path, arcname=arcname, filter=exclude_filter)

        # Save metadata
        meta = {
            "created": datetime.now().isoformat(),
            "description": config.description,
            "paths": config.paths,
            "compress": config.compress
        }
        with open(backup_path + '.meta.json', 'w') as f:
            json.dump(meta, f, indent=2)

        state["running"] = False
        state["last_backup"] = filename
        state["last_backup_time"] = datetime.now().isoformat()
        state["last_error"] = None
        save_state(state)

        return {"status": "completed", "backup_id": filename, "path": backup_path}

    except Exception as e:
        state["running"] = False
        state["last_error"] = str(e)
        save_state(state)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health():
    return {"status": "ok", "service": "cloner"}


@app.get("/status")
def get_status():
    """Get cloner status."""
    state = load_state()
    config = load_config()
    backups = get_backup_list()
    disk = get_disk_usage()

    total_backup_size = sum(b["size"] for b in backups)

    return {
        "running": state.get("running", False),
        "last_backup": state.get("last_backup"),
        "last_backup_time": state.get("last_backup_time"),
        "last_error": state.get("last_error"),
        "backup_count": len(backups),
        "total_backup_size": format_size(total_backup_size),
        "disk": disk,
        "schedule": config.get("schedule", {})
    }


@app.get("/backups")
def list_backups():
    """List all backups."""
    return {"backups": get_backup_list()}


@app.get("/backups/{backup_id}")
def get_backup(backup_id: str):
    """Get backup details."""
    backup_path = os.path.join(BACKUP_DIR, backup_id)

    if not os.path.exists(backup_path):
        raise HTTPException(status_code=404, detail="Backup not found")

    stat = os.stat(backup_path)

    # Load metadata
    meta_file = backup_path + '.meta.json'
    meta = {}
    if os.path.exists(meta_file):
        with open(meta_file, 'r') as f:
            meta = json.load(f)

    # List contents
    contents = []
    try:
        with tarfile.open(backup_path, 'r:*') as tar:
            for member in tar.getmembers()[:100]:  # Limit to first 100
                contents.append({
                    "name": member.name,
                    "size": member.size,
                    "type": "dir" if member.isdir() else "file"
                })
    except Exception:
        pass

    return {
        "id": backup_id,
        "path": backup_path,
        "size": stat.st_size,
        "size_human": format_size(stat.st_size),
        "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "description": meta.get("description", ""),
        "paths": meta.get("paths", []),
        "contents": contents,
        "contents_truncated": len(contents) >= 100
    }


@app.post("/backups")
def create_backup(config: BackupConfig, background_tasks: BackgroundTasks):
    """Create a new backup."""
    state = load_state()

    if state.get("running"):
        raise HTTPException(status_code=409, detail="Backup already in progress")

    # Run synchronously for now (could be made async)
    result = create_backup_sync(config)
    return result


@app.delete("/backups/{backup_id}")
def delete_backup(backup_id: str):
    """Delete a backup."""
    backup_path = os.path.join(BACKUP_DIR, backup_id)

    if not os.path.exists(backup_path):
        raise HTTPException(status_code=404, detail="Backup not found")

    os.remove(backup_path)

    # Remove metadata if exists
    meta_file = backup_path + '.meta.json'
    if os.path.exists(meta_file):
        os.remove(meta_file)

    return {"status": "deleted", "backup_id": backup_id}


@app.post("/backups/{backup_id}/restore")
def restore_backup(backup_id: str, config: RestoreConfig = None):
    """Restore from a backup."""
    backup_path = os.path.join(BACKUP_DIR, backup_id)

    if not os.path.exists(backup_path):
        raise HTTPException(status_code=404, detail="Backup not found")

    config = config or RestoreConfig(backup_id=backup_id)
    target = config.target_path

    if config.dry_run:
        # Just list what would be restored
        contents = []
        with tarfile.open(backup_path, 'r:*') as tar:
            for member in tar.getmembers():
                contents.append(member.name)
        return {"dry_run": True, "would_restore": contents[:100]}

    try:
        with tarfile.open(backup_path, 'r:*') as tar:
            tar.extractall(path=target)

        return {"status": "restored", "backup_id": backup_id, "target": target}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/config")
def get_config():
    """Get cloner configuration."""
    return load_config()


@app.put("/config")
def update_config(config: dict):
    """Update cloner configuration."""
    current = load_config()
    current.update(config)
    save_config(current)
    return {"status": "updated", "config": current}


@app.put("/schedule")
def update_schedule(schedule: ScheduleConfig):
    """Update backup schedule."""
    config = load_config()
    config["schedule"] = schedule.dict()
    save_config(config)

    # Update systemd timer if enabled
    if schedule.enabled:
        # Create timer unit
        timer_content = f"""[Unit]
Description=SecuBox Cloner scheduled backup

[Timer]
OnCalendar=*-*-* {schedule.time}:00
Persistent=true

[Install]
WantedBy=timers.target
"""
        timer_path = "/etc/systemd/system/secubox-cloner-backup.timer"
        with open(timer_path, 'w') as f:
            f.write(timer_content)

        run_cmd(["systemctl", "daemon-reload"])
        run_cmd(["systemctl", "enable", "secubox-cloner-backup.timer"])
        run_cmd(["systemctl", "start", "secubox-cloner-backup.timer"])
    else:
        run_cmd(["systemctl", "stop", "secubox-cloner-backup.timer"])
        run_cmd(["systemctl", "disable", "secubox-cloner-backup.timer"])

    return {"status": "updated", "schedule": schedule.dict()}


@app.post("/cleanup")
def cleanup_old_backups(keep: int = 7):
    """Remove old backups, keeping the N most recent."""
    backups = get_backup_list()

    if len(backups) <= keep:
        return {"status": "ok", "deleted": 0, "kept": len(backups)}

    to_delete = backups[keep:]
    deleted = 0

    for backup in to_delete:
        try:
            os.remove(backup["path"])
            meta_file = backup["path"] + '.meta.json'
            if os.path.exists(meta_file):
                os.remove(meta_file)
            deleted += 1
        except Exception:
            pass

    return {"status": "ok", "deleted": deleted, "kept": keep}


@app.get("/paths")
def get_default_paths():
    """Get default backup paths."""
    paths = []
    for path in DEFAULT_PATHS:
        exists = os.path.exists(path)
        size = 0
        if exists:
            try:
                for root, dirs, files in os.walk(path):
                    size += sum(os.path.getsize(os.path.join(root, f)) for f in files)
            except Exception:
                pass

        paths.append({
            "path": path,
            "exists": exists,
            "size": size,
            "size_human": format_size(size)
        })

    return {"paths": paths}
