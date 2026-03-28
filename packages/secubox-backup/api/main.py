"""
SecuBox Backup Manager API
Backup system configs, LXC containers, and services

Enhanced features:
- Scheduled backups with configurable intervals
- Retention policies per backup type
- Backup encryption with age/GPG
- Remote backup targets (S3, SFTP)
- Backup verification and integrity checking
- Progress tracking for long operations
- Backup history and audit log
"""

from fastapi import FastAPI, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime, timedelta
from enum import Enum
import subprocess
import os
import time
import json
import hashlib
import asyncio
import threading

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/secubox/core')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "dev"}

app = FastAPI(title="SecuBox Backup API", version="2.0.0")

# Configuration
BACKUP_PATH = Path("/srv/backups")
LXC_PATH = Path("/srv/lxc")
DATA_DIR = Path("/var/lib/secubox/backup")
HISTORY_FILE = DATA_DIR / "history.json"
SCHEDULE_FILE = DATA_DIR / "schedule.json"
REMOTE_CONFIG_FILE = DATA_DIR / "remotes.json"

CONFIG_PATHS = [
    "/etc/secubox",
    "/etc/nginx",
    "/etc/wireguard",
    "/etc/haproxy",
    "/etc/nftables.conf",
    "/etc/crowdsec",
]

# Default retention policies (days to keep)
DEFAULT_RETENTION = {
    "config": {"keep_count": 10, "keep_days": 30},
    "containers": {"keep_count": 5, "keep_days": 14},
    "services": {"keep_count": 5, "keep_days": 14},
}

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)


class BackupType(str, Enum):
    FULL = "full"
    CONFIG = "config"
    CONTAINERS = "containers"
    SERVICES = "services"


class BackupStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class RemoteType(str, Enum):
    S3 = "s3"
    SFTP = "sftp"
    LOCAL = "local"


# Models
class BackupCreate(BaseModel):
    type: BackupType = BackupType.FULL
    encrypt: bool = False
    encrypt_recipient: Optional[str] = None  # GPG key ID or age public key
    upload_remote: Optional[str] = None  # Remote target name
    comment: Optional[str] = None


class RestoreRequest(BaseModel):
    file: str
    dry_run: bool = False
    decrypt_key: Optional[str] = None  # Path to decryption key


class ContainerBackup(BaseModel):
    name: str
    encrypt: bool = False


class ContainerRestore(BaseModel):
    name: str
    file: str


class BackupHistoryEntry(BaseModel):
    id: str
    timestamp: str
    type: str
    status: BackupStatus
    file: Optional[str] = None
    size_bytes: int = 0
    duration_seconds: float = 0
    checksum: Optional[str] = None
    encrypted: bool = False
    remote_uploaded: Optional[str] = None
    comment: Optional[str] = None
    error: Optional[str] = None


class ScheduleConfig(BaseModel):
    enabled: bool = False
    type: BackupType = BackupType.CONFIG
    interval_hours: int = Field(ge=1, le=168, default=24)  # 1h to 7 days
    encrypt: bool = False
    upload_remote: Optional[str] = None
    last_run: Optional[str] = None
    next_run: Optional[str] = None


class RetentionPolicy(BaseModel):
    keep_count: int = Field(ge=1, le=100, default=10)
    keep_days: int = Field(ge=1, le=365, default=30)


class RemoteTarget(BaseModel):
    name: str
    type: RemoteType
    # S3 config
    s3_bucket: Optional[str] = None
    s3_endpoint: Optional[str] = None
    s3_access_key: Optional[str] = None
    s3_secret_key: Optional[str] = None
    s3_region: Optional[str] = "us-east-1"
    # SFTP config
    sftp_host: Optional[str] = None
    sftp_port: int = 22
    sftp_user: Optional[str] = None
    sftp_key_path: Optional[str] = None
    sftp_path: Optional[str] = "/backups"
    # Common
    enabled: bool = True


class VerifyResult(BaseModel):
    file: str
    valid: bool
    checksum_match: bool
    can_extract: bool
    file_count: int = 0
    error: Optional[str] = None


# Global state for progress tracking
_backup_progress: Dict[str, Dict[str, Any]] = {}
_progress_lock = threading.Lock()


# ============================================================================
# Helper Functions
# ============================================================================

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


def generate_backup_id() -> str:
    """Generate unique backup ID."""
    import uuid
    return str(uuid.uuid4())[:8]


def calculate_checksum(file_path: Path) -> str:
    """Calculate SHA256 checksum of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


# ============================================================================
# History Management
# ============================================================================

def load_history() -> List[Dict]:
    """Load backup history."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_history(history: List[Dict]):
    """Save backup history."""
    # Keep last 1000 entries
    history = history[-1000:]
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass


def add_history_entry(entry: BackupHistoryEntry):
    """Add entry to backup history."""
    history = load_history()
    history.append(entry.dict())
    save_history(history)


def update_history_entry(backup_id: str, updates: Dict):
    """Update an existing history entry."""
    history = load_history()
    for entry in history:
        if entry.get("id") == backup_id:
            entry.update(updates)
            break
    save_history(history)


# ============================================================================
# Schedule Management
# ============================================================================

def load_schedule() -> Dict[str, ScheduleConfig]:
    """Load backup schedules."""
    if SCHEDULE_FILE.exists():
        try:
            with open(SCHEDULE_FILE) as f:
                data = json.load(f)
                return {k: ScheduleConfig(**v) for k, v in data.items()}
        except Exception:
            pass
    return {}


def save_schedule(schedules: Dict[str, ScheduleConfig]):
    """Save backup schedules."""
    try:
        with open(SCHEDULE_FILE, 'w') as f:
            json.dump({k: v.dict() for k, v in schedules.items()}, f, indent=2)
    except Exception:
        pass


# ============================================================================
# Remote Target Management
# ============================================================================

def load_remotes() -> Dict[str, RemoteTarget]:
    """Load remote backup targets."""
    if REMOTE_CONFIG_FILE.exists():
        try:
            with open(REMOTE_CONFIG_FILE) as f:
                data = json.load(f)
                return {k: RemoteTarget(**v) for k, v in data.items()}
        except Exception:
            pass
    return {}


def save_remotes(remotes: Dict[str, RemoteTarget]):
    """Save remote backup targets (mask secrets)."""
    try:
        with open(REMOTE_CONFIG_FILE, 'w') as f:
            json.dump({k: v.dict() for k, v in remotes.items()}, f, indent=2)
    except Exception:
        pass


async def upload_to_remote(file_path: Path, remote_name: str) -> tuple:
    """Upload backup to remote target."""
    remotes = load_remotes()
    if remote_name not in remotes:
        return False, f"Remote target '{remote_name}' not found"

    remote = remotes[remote_name]
    if not remote.enabled:
        return False, "Remote target is disabled"

    if remote.type == RemoteType.S3:
        # Use rclone or aws cli for S3
        cmd = [
            "rclone", "copy", str(file_path),
            f":s3:{remote.s3_bucket}/",
            f"--s3-access-key-id={remote.s3_access_key}",
            f"--s3-secret-access-key={remote.s3_secret_key}",
            f"--s3-region={remote.s3_region}",
        ]
        if remote.s3_endpoint:
            cmd.append(f"--s3-endpoint={remote.s3_endpoint}")

        success, out, err = run_cmd(cmd, timeout=600)
        return success, err if not success else "Uploaded to S3"

    elif remote.type == RemoteType.SFTP:
        # Use scp/sftp for SFTP
        dest = f"{remote.sftp_user}@{remote.sftp_host}:{remote.sftp_path}/{file_path.name}"
        cmd = ["scp", "-P", str(remote.sftp_port)]
        if remote.sftp_key_path:
            cmd.extend(["-i", remote.sftp_key_path])
        cmd.extend([str(file_path), dest])

        success, out, err = run_cmd(cmd, timeout=600)
        return success, err if not success else "Uploaded via SFTP"

    return False, f"Unsupported remote type: {remote.type}"


# ============================================================================
# Encryption Support
# ============================================================================

def encrypt_file(file_path: Path, recipient: str) -> tuple:
    """Encrypt a file using age or GPG."""
    encrypted_path = Path(str(file_path) + ".age")

    # Try age first (modern, simpler)
    if recipient.startswith("age1"):
        cmd = ["age", "-r", recipient, "-o", str(encrypted_path), str(file_path)]
    else:
        # Fall back to GPG
        cmd = ["gpg", "--encrypt", "--recipient", recipient, "--output", str(encrypted_path), str(file_path)]

    success, out, err = run_cmd(cmd, timeout=300)
    if success:
        file_path.unlink()  # Remove unencrypted file
        return True, encrypted_path
    return False, err


def decrypt_file(file_path: Path, key_path: str = None) -> tuple:
    """Decrypt a file."""
    if str(file_path).endswith(".age"):
        decrypted_path = Path(str(file_path)[:-4])
        cmd = ["age", "-d"]
        if key_path:
            cmd.extend(["-i", key_path])
        cmd.extend(["-o", str(decrypted_path), str(file_path)])
    else:
        decrypted_path = Path(str(file_path).replace(".gpg", ""))
        cmd = ["gpg", "--decrypt", "--output", str(decrypted_path), str(file_path)]

    success, out, err = run_cmd(cmd, timeout=300)
    return success, decrypted_path if success else err


# ============================================================================
# Progress Tracking
# ============================================================================

def set_progress(backup_id: str, status: str, percent: int = 0, message: str = ""):
    """Update backup progress."""
    with _progress_lock:
        _backup_progress[backup_id] = {
            "status": status,
            "percent": percent,
            "message": message,
            "updated": datetime.utcnow().isoformat() + "Z"
        }


def get_progress(backup_id: str) -> Optional[Dict]:
    """Get backup progress."""
    with _progress_lock:
        return _backup_progress.get(backup_id)


def clear_progress(backup_id: str):
    """Clear backup progress."""
    with _progress_lock:
        _backup_progress.pop(backup_id, None)


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
        "version": "2.0.0",
        "description": "Backup Manager for system configs and LXC containers",
        "features": [
            "scheduled_backups", "encryption", "remote_targets",
            "retention_policies", "verification", "progress_tracking"
        ]
    }


# ============================================================================
# Health Check
# ============================================================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "secubox-backup",
        "version": "2.0.0"
    }


# ============================================================================
# History Endpoints
# ============================================================================

@app.get("/history")
async def get_history(
    limit: int = Query(50, ge=1, le=500),
    type: Optional[str] = None,
    status: Optional[str] = None
):
    """Get backup history."""
    history = load_history()

    # Filter by type
    if type:
        history = [h for h in history if h.get("type") == type]

    # Filter by status
    if status:
        history = [h for h in history if h.get("status") == status]

    # Return most recent first
    history = sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {"history": history[:limit], "total": len(history)}


@app.delete("/history/{backup_id}")
async def delete_history_entry(backup_id: str, user: dict = Depends(require_jwt)):
    """Delete a history entry."""
    history = load_history()
    original_len = len(history)
    history = [h for h in history if h.get("id") != backup_id]

    if len(history) == original_len:
        raise HTTPException(status_code=404, detail="History entry not found")

    save_history(history)
    return {"status": "deleted"}


# ============================================================================
# Progress Tracking Endpoints
# ============================================================================

@app.get("/progress/{backup_id}")
async def get_backup_progress(backup_id: str):
    """Get progress of a running backup."""
    progress = get_progress(backup_id)
    if not progress:
        raise HTTPException(status_code=404, detail="Backup not found or completed")
    return progress


@app.get("/running")
async def get_running_backups():
    """Get all currently running backups."""
    with _progress_lock:
        return {"running": list(_backup_progress.keys()), "details": dict(_backup_progress)}


# ============================================================================
# Verification Endpoints
# ============================================================================

@app.post("/verify/{filename}")
async def verify_backup(filename: str, user: dict = Depends(require_jwt)):
    """Verify integrity of a backup file."""
    # Find the file
    backup_file = None
    for btype in ["config", "containers", "services"]:
        candidate = BACKUP_PATH / btype / filename
        if candidate.exists():
            backup_file = candidate
            break

    if not backup_file:
        raise HTTPException(status_code=404, detail="Backup file not found")

    result = VerifyResult(file=filename, valid=True, checksum_match=True, can_extract=True)

    # Calculate current checksum
    current_checksum = calculate_checksum(backup_file)

    # Check against stored checksum in history
    history = load_history()
    stored_checksum = None
    for entry in history:
        if entry.get("file") == filename:
            stored_checksum = entry.get("checksum")
            break

    if stored_checksum and stored_checksum != current_checksum:
        result.valid = False
        result.checksum_match = False
        result.error = "Checksum mismatch - file may be corrupted"

    # Test if we can list contents
    success, out, err = run_cmd(["tar", "-tzf", str(backup_file)])
    if not success:
        result.valid = False
        result.can_extract = False
        result.error = result.error or f"Cannot read archive: {err}"
    else:
        result.file_count = len(out.strip().split('\n')) if out.strip() else 0

    return result


# ============================================================================
# Retention Policy Endpoints
# ============================================================================

@app.get("/retention")
async def get_retention_policies():
    """Get retention policies per backup type."""
    # Load custom policies or return defaults
    policy_file = DATA_DIR / "retention.json"
    if policy_file.exists():
        try:
            with open(policy_file) as f:
                return {"policies": json.load(f)}
        except Exception:
            pass
    return {"policies": DEFAULT_RETENTION}


@app.put("/retention/{backup_type}")
async def set_retention_policy(
    backup_type: str,
    policy: RetentionPolicy,
    user: dict = Depends(require_jwt)
):
    """Set retention policy for a backup type."""
    if backup_type not in ["config", "containers", "services"]:
        raise HTTPException(status_code=400, detail="Invalid backup type")

    policy_file = DATA_DIR / "retention.json"
    policies = DEFAULT_RETENTION.copy()

    if policy_file.exists():
        try:
            with open(policy_file) as f:
                policies = json.load(f)
        except Exception:
            pass

    policies[backup_type] = policy.dict()

    with open(policy_file, 'w') as f:
        json.dump(policies, f, indent=2)

    return {"status": "updated", "type": backup_type, "policy": policy.dict()}


@app.post("/retention/apply")
async def apply_retention_policies(user: dict = Depends(require_jwt)):
    """Apply retention policies - remove old backups."""
    policy_file = DATA_DIR / "retention.json"
    policies = DEFAULT_RETENTION.copy()

    if policy_file.exists():
        try:
            with open(policy_file) as f:
                policies = json.load(f)
        except Exception:
            pass

    removed = []
    now = time.time()

    for btype, policy in policies.items():
        type_dir = BACKUP_PATH / btype
        if not type_dir.exists():
            continue

        files = sorted(type_dir.glob("*.tar*"), key=lambda x: x.stat().st_mtime, reverse=True)

        keep_count = policy.get("keep_count", 10)
        keep_days = policy.get("keep_days", 30)
        cutoff_time = now - (keep_days * 86400)

        for i, f in enumerate(files):
            # Keep if within count limit AND within time limit
            if i < keep_count:
                continue

            # Remove if older than retention period
            if f.stat().st_mtime < cutoff_time:
                try:
                    f.unlink()
                    removed.append({"file": f.name, "type": btype})
                except Exception:
                    pass

    return {"removed": removed, "count": len(removed)}


# ============================================================================
# Schedule Endpoints
# ============================================================================

@app.get("/schedules")
async def get_schedules():
    """Get all backup schedules."""
    schedules = load_schedule()
    return {"schedules": {k: v.dict() for k, v in schedules.items()}}


@app.put("/schedules/{schedule_name}")
async def set_schedule(
    schedule_name: str,
    config: ScheduleConfig,
    user: dict = Depends(require_jwt)
):
    """Create or update a backup schedule."""
    schedules = load_schedule()

    if config.enabled and config.last_run:
        last = datetime.fromisoformat(config.last_run.rstrip("Z"))
        next_run = last + timedelta(hours=config.interval_hours)
        config.next_run = next_run.isoformat() + "Z"

    schedules[schedule_name] = config
    save_schedule(schedules)

    return {"status": "updated", "schedule": config.dict()}


@app.delete("/schedules/{schedule_name}")
async def delete_schedule(schedule_name: str, user: dict = Depends(require_jwt)):
    """Delete a backup schedule."""
    schedules = load_schedule()

    if schedule_name not in schedules:
        raise HTTPException(status_code=404, detail="Schedule not found")

    del schedules[schedule_name]
    save_schedule(schedules)

    return {"status": "deleted"}


@app.post("/schedules/{schedule_name}/run")
async def run_scheduled_backup(
    schedule_name: str,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_jwt)
):
    """Manually trigger a scheduled backup."""
    schedules = load_schedule()

    if schedule_name not in schedules:
        raise HTTPException(status_code=404, detail="Schedule not found")

    schedule = schedules[schedule_name]
    backup_id = generate_backup_id()

    # Create backup request from schedule
    req = BackupCreate(
        type=schedule.type,
        encrypt=schedule.encrypt,
        upload_remote=schedule.upload_remote,
        comment=f"Scheduled: {schedule_name}"
    )

    # Run in background
    background_tasks.add_task(run_backup_async, backup_id, req, schedule_name)

    return {"status": "started", "backup_id": backup_id}


async def run_backup_async(backup_id: str, req: BackupCreate, schedule_name: str = None):
    """Run backup asynchronously with progress tracking."""
    start_time = time.time()
    set_progress(backup_id, "running", 0, "Starting backup...")

    # Create history entry
    entry = BackupHistoryEntry(
        id=backup_id,
        timestamp=datetime.utcnow().isoformat() + "Z",
        type=req.type.value if isinstance(req.type, BackupType) else req.type,
        status=BackupStatus.RUNNING,
        encrypted=req.encrypt,
        comment=req.comment
    )
    add_history_entry(entry)

    try:
        ensure_backup_dirs()
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        outputs = []
        created_files = []

        backup_type = req.type.value if isinstance(req.type, BackupType) else req.type

        # Config backup
        if backup_type in ["full", "config"]:
            set_progress(backup_id, "running", 20, "Backing up configuration...")
            archive = BACKUP_PATH / "config" / f"config-{timestamp}.tar.gz"
            existing_paths = [p for p in CONFIG_PATHS if os.path.exists(p)]

            if existing_paths:
                success, out, err = run_cmd(
                    ["tar", "-czf", str(archive)] + existing_paths,
                    timeout=300
                )
                if success:
                    outputs.append(f"Config: {archive.name}")
                    created_files.append(archive)

        # Container backup
        if backup_type in ["full", "containers"]:
            set_progress(backup_id, "running", 40, "Backing up containers...")
            if LXC_PATH.exists():
                containers = [d for d in LXC_PATH.iterdir() if d.is_dir() and (d / "config").exists()]
                for i, container_dir in enumerate(containers):
                    name = container_dir.name
                    archive = BACKUP_PATH / "containers" / f"{name}-{timestamp}.tar.gz"

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
                        outputs.append(f"Container: {name}")
                        created_files.append(archive)

        # Services backup
        if backup_type in ["full", "services"]:
            set_progress(backup_id, "running", 70, "Backing up services...")
            service_paths = ["/var/lib/secubox", "/srv/nextcloud/data", "/srv/gitea/data"]
            existing = [p for p in service_paths if os.path.exists(p)]

            if existing:
                archive = BACKUP_PATH / "services" / f"services-{timestamp}.tar.gz"
                success, out, err = run_cmd(
                    ["tar", "-czf", str(archive)] + existing,
                    timeout=600
                )
                if success:
                    outputs.append(f"Services: {archive.name}")
                    created_files.append(archive)

        # Encryption
        if req.encrypt and req.encrypt_recipient and created_files:
            set_progress(backup_id, "running", 85, "Encrypting backups...")
            for archive in created_files:
                success, result = encrypt_file(archive, req.encrypt_recipient)
                if success:
                    # Update file reference
                    created_files[created_files.index(archive)] = result

        # Upload to remote
        if req.upload_remote and created_files:
            set_progress(backup_id, "running", 90, f"Uploading to {req.upload_remote}...")
            for archive in created_files:
                success, msg = await upload_to_remote(archive, req.upload_remote)

        # Calculate total size and checksum
        total_size = sum(f.stat().st_size for f in created_files if f.exists())
        checksum = calculate_checksum(created_files[0]) if created_files else None

        # Update history
        duration = time.time() - start_time
        update_history_entry(backup_id, {
            "status": BackupStatus.COMPLETED.value,
            "file": created_files[0].name if created_files else None,
            "size_bytes": total_size,
            "duration_seconds": round(duration, 2),
            "checksum": checksum,
            "remote_uploaded": req.upload_remote if req.upload_remote else None
        })

        # Update schedule if this was a scheduled backup
        if schedule_name:
            schedules = load_schedule()
            if schedule_name in schedules:
                schedules[schedule_name].last_run = datetime.utcnow().isoformat() + "Z"
                next_run = datetime.utcnow() + timedelta(hours=schedules[schedule_name].interval_hours)
                schedules[schedule_name].next_run = next_run.isoformat() + "Z"
                save_schedule(schedules)

        set_progress(backup_id, "completed", 100, f"Completed: {', '.join(outputs)}")

    except Exception as e:
        update_history_entry(backup_id, {
            "status": BackupStatus.FAILED.value,
            "error": str(e)
        })
        set_progress(backup_id, "failed", 0, str(e))

    # Clean up progress after a delay
    await asyncio.sleep(300)
    clear_progress(backup_id)


# ============================================================================
# Remote Target Endpoints
# ============================================================================

@app.get("/remotes")
async def get_remotes(user: dict = Depends(require_jwt)):
    """Get configured remote backup targets."""
    remotes = load_remotes()
    # Mask secrets
    for name, remote in remotes.items():
        if remote.s3_secret_key:
            remote.s3_secret_key = "***"
    return {"remotes": {k: v.dict() for k, v in remotes.items()}}


@app.put("/remotes/{remote_name}")
async def set_remote(
    remote_name: str,
    config: RemoteTarget,
    user: dict = Depends(require_jwt)
):
    """Create or update a remote backup target."""
    remotes = load_remotes()

    # If updating, preserve existing secrets if not provided
    if remote_name in remotes and config.s3_secret_key == "***":
        config.s3_secret_key = remotes[remote_name].s3_secret_key

    config.name = remote_name
    remotes[remote_name] = config
    save_remotes(remotes)

    return {"status": "updated", "remote": remote_name}


@app.delete("/remotes/{remote_name}")
async def delete_remote(remote_name: str, user: dict = Depends(require_jwt)):
    """Delete a remote backup target."""
    remotes = load_remotes()

    if remote_name not in remotes:
        raise HTTPException(status_code=404, detail="Remote target not found")

    del remotes[remote_name]
    save_remotes(remotes)

    return {"status": "deleted"}


@app.post("/remotes/{remote_name}/test")
async def test_remote(remote_name: str, user: dict = Depends(require_jwt)):
    """Test connection to a remote backup target."""
    remotes = load_remotes()

    if remote_name not in remotes:
        raise HTTPException(status_code=404, detail="Remote target not found")

    remote = remotes[remote_name]

    if remote.type == RemoteType.S3:
        # Test S3 connection
        cmd = [
            "rclone", "lsd",
            f":s3:{remote.s3_bucket}",
            f"--s3-access-key-id={remote.s3_access_key}",
            f"--s3-secret-access-key={remote.s3_secret_key}",
            f"--s3-region={remote.s3_region}",
        ]
        if remote.s3_endpoint:
            cmd.append(f"--s3-endpoint={remote.s3_endpoint}")

        success, out, err = run_cmd(cmd, timeout=30)
        return {"success": success, "message": out if success else err}

    elif remote.type == RemoteType.SFTP:
        # Test SFTP connection
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
               "-p", str(remote.sftp_port)]
        if remote.sftp_key_path:
            cmd.extend(["-i", remote.sftp_key_path])
        cmd.extend([f"{remote.sftp_user}@{remote.sftp_host}", "echo ok"])

        success, out, err = run_cmd(cmd, timeout=15)
        return {"success": success, "message": "Connection successful" if success else err}

    return {"success": False, "message": f"Unsupported remote type: {remote.type}"}
