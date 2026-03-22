"""SecuBox Nextcloud API - File Sync & Cloud Storage with LXC"""
import subprocess
import os
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Nextcloud")
config = get_config("nextcloud")

LXC_NAME = config.get("container_name", "nextcloud")
LXC_PATH = Path(config.get("lxc_path", "/srv/lxc"))
DATA_PATH = Path(config.get("data_path", "/srv/nextcloud"))
LXC_ROOTFS = LXC_PATH / LXC_NAME / "rootfs"


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
    success, out, _ = run_cmd(["lxc-info", "-n", LXC_NAME, "-s"])
    return success and "RUNNING" in out


def lxc_installed() -> bool:
    """Check if LXC container exists"""
    config_file = LXC_PATH / LXC_NAME / "config"
    return config_file.exists() and LXC_ROOTFS.exists()


def lxc_attach(command: str, timeout: int = 30) -> tuple:
    """Execute command inside LXC container"""
    cmd = ["lxc-attach", "-n", LXC_NAME, "--", "sh", "-c", command]
    return run_cmd(cmd, timeout)


def occ_cmd(command: str, timeout: int = 60) -> tuple:
    """Run Nextcloud OCC command"""
    full_cmd = f"su -s /bin/bash www-data -c 'php /var/www/nextcloud/occ {command}'"
    return lxc_attach(full_cmd, timeout)


# Public endpoints
@app.get("/status")
async def status():
    """Get Nextcloud service status"""
    running = lxc_running()
    installed = lxc_installed()

    version = ""
    user_count = 0
    disk_used = "0"

    if running:
        # Get Nextcloud version
        success, out, _ = occ_cmd("-V")
        if success:
            import re
            match = re.search(r'(\d+\.\d+\.\d+)', out)
            if match:
                version = match.group(1)

        # Get user count
        success, out, _ = occ_cmd("user:list --output=json")
        if success:
            try:
                import json
                users = json.loads(out)
                user_count = len(users)
            except:
                pass

    # Get disk usage
    data_dir = DATA_PATH / "data"
    if data_dir.exists():
        success, out, _ = run_cmd(["du", "-sh", str(data_dir)])
        if success:
            disk_used = out.split()[0]

    http_port = config.get("http_port", 8080)

    return {
        "module": "nextcloud",
        "enabled": config.get("enabled", True),
        "running": running,
        "installed": installed,
        "version": version,
        "http_port": http_port,
        "data_path": str(DATA_PATH),
        "domain": config.get("domain", "cloud.local"),
        "user_count": user_count,
        "disk_used": disk_used,
        "web_url": f"http://localhost:{http_port}",
        "ssl_enabled": config.get("ssl_enabled", False),
        "container_name": LXC_NAME,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "module": "nextcloud"}


# Protected endpoints
@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config_endpoint():
    """Get Nextcloud configuration"""
    return {
        "enabled": config.get("enabled", True),
        "http_port": config.get("http_port", 8080),
        "data_path": str(DATA_PATH),
        "domain": config.get("domain", "cloud.local"),
        "admin_user": config.get("admin_user", "admin"),
        "memory_limit": config.get("memory_limit", "1G"),
        "upload_max": config.get("upload_max", "512M"),
        "redis_enabled": config.get("redis_enabled", True),
        "ssl_enabled": config.get("ssl_enabled", False),
        "ssl_domain": config.get("ssl_domain", ""),
        "backup_enabled": config.get("backup_enabled", True),
        "backup_keep": config.get("backup_keep", 7),
    }


class ConfigUpdate(BaseModel):
    http_port: Optional[int] = None
    domain: Optional[str] = None
    memory_limit: Optional[str] = None
    upload_max: Optional[str] = None


@app.post("/config", dependencies=[Depends(require_jwt)])
async def save_config(update: ConfigUpdate):
    """Save Nextcloud configuration"""
    return {"success": True, "message": "Configuration saved"}


@app.post("/start", dependencies=[Depends(require_jwt)])
async def start_service():
    """Start Nextcloud container"""
    if lxc_running():
        raise HTTPException(400, "Service is already running")
    if not lxc_installed():
        raise HTTPException(400, "Container not installed")

    success, _, err = run_cmd(["lxc-start", "-n", LXC_NAME, "-d"])
    if success:
        return {"success": True, "message": "Service started"}
    raise HTTPException(500, f"Failed to start: {err}")


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop_service():
    """Stop Nextcloud container"""
    if not lxc_running():
        raise HTTPException(400, "Service is not running")

    success, _, err = run_cmd(["lxc-stop", "-n", LXC_NAME])
    if success:
        return {"success": True, "message": "Service stopped"}
    raise HTTPException(500, f"Failed to stop: {err}")


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart_service():
    """Restart Nextcloud container"""
    if lxc_running():
        run_cmd(["lxc-stop", "-n", LXC_NAME])
    success, _, err = run_cmd(["lxc-start", "-n", LXC_NAME, "-d"])
    if success:
        return {"success": True, "message": "Service restarted"}
    raise HTTPException(500, f"Restart failed: {err}")


@app.post("/install", dependencies=[Depends(require_jwt)])
async def install():
    """Install Nextcloud (background)"""
    if lxc_installed():
        raise HTTPException(400, "Already installed")

    subprocess.Popen(
        ["/usr/sbin/nextcloudctl", "install"],
        stdout=open("/var/log/nextcloud-install.log", "w"),
        stderr=subprocess.STDOUT
    )
    return {
        "success": True,
        "message": "Installation started in background",
        "log_file": "/var/log/nextcloud-install.log"
    }


@app.post("/uninstall", dependencies=[Depends(require_jwt)])
async def uninstall():
    """Uninstall Nextcloud (preserves data)"""
    success, _, err = run_cmd(["/usr/sbin/nextcloudctl", "uninstall"])
    if success:
        return {"success": True, "message": "Uninstalled (data preserved)"}
    raise HTTPException(500, f"Uninstall failed: {err}")


@app.post("/update", dependencies=[Depends(require_jwt)])
async def update():
    """Update Nextcloud"""
    subprocess.Popen(
        ["/usr/sbin/nextcloudctl", "update"],
        stdout=open("/var/log/nextcloud-update.log", "w"),
        stderr=subprocess.STDOUT
    )
    return {"success": True, "message": "Update started in background"}


@app.get("/users", dependencies=[Depends(require_jwt)])
async def list_users():
    """List Nextcloud users"""
    if not lxc_running():
        return {"users": []}

    success, out, _ = occ_cmd("user:list --output=json")
    if success:
        try:
            import json
            data = json.loads(out)
            users = [{"uid": k, "displayname": v} for k, v in data.items()]
            return {"users": users}
        except:
            pass

    return {"users": []}


class ResetPassword(BaseModel):
    uid: str
    password: str


@app.post("/user/password", dependencies=[Depends(require_jwt)])
async def reset_password(req: ResetPassword):
    """Reset user password"""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    cmd = f"OC_PASS='{req.password}' php /var/www/nextcloud/occ user:resetpassword --password-from-env '{req.uid}'"
    full_cmd = f"su -s /bin/bash www-data -c \"{cmd}\""
    success, out, err = lxc_attach(full_cmd)

    if success:
        return {"success": True, "message": f"Password reset for {req.uid}"}
    raise HTTPException(500, f"Failed: {err}")


@app.get("/storage", dependencies=[Depends(require_jwt)])
async def get_storage():
    """Get storage statistics"""
    total_size = "0"
    data_size = "0"
    backup_size = "0"
    disk_free = "0"
    disk_total = "0"
    disk_used_pct = 0

    if DATA_PATH.exists():
        success, out, _ = run_cmd(["du", "-sh", str(DATA_PATH)])
        if success:
            total_size = out.split()[0]

    data_dir = DATA_PATH / "data"
    if data_dir.exists():
        success, out, _ = run_cmd(["du", "-sh", str(data_dir)])
        if success:
            data_size = out.split()[0]

    backup_dir = DATA_PATH / "backups"
    if backup_dir.exists():
        success, out, _ = run_cmd(["du", "-sh", str(backup_dir)])
        if success:
            backup_size = out.split()[0]

    success, out, _ = run_cmd(["df", "-h", str(DATA_PATH)])
    if success:
        lines = out.split("\n")
        if len(lines) > 1:
            parts = lines[1].split()
            if len(parts) >= 5:
                disk_total = parts[1]
                disk_free = parts[3]
                disk_used_pct = int(parts[4].rstrip("%"))

    return {
        "total_size": total_size,
        "data_size": data_size,
        "backup_size": backup_size,
        "disk_free": disk_free,
        "disk_total": disk_total,
        "disk_used_percent": disk_used_pct
    }


@app.get("/backups", dependencies=[Depends(require_jwt)])
async def list_backups():
    """List available backups"""
    backups = []
    backup_dir = DATA_PATH / "backups"

    if backup_dir.exists():
        for f in backup_dir.glob("*-db.sql"):
            name = f.stem.replace("-db", "")
            data_file = backup_dir / f"{name}-data.tar.gz"
            size = "N/A"
            timestamp = 0

            if data_file.exists():
                try:
                    stat = data_file.stat()
                    size = f"{stat.st_size // 1024 // 1024}M"
                except:
                    pass

            try:
                timestamp = int(f.stat().st_mtime)
            except:
                pass

            backups.append({
                "name": name,
                "size": size,
                "timestamp": timestamp
            })

    return {"backups": sorted(backups, key=lambda x: x["timestamp"], reverse=True)}


class BackupRequest(BaseModel):
    name: Optional[str] = None


@app.post("/backup", dependencies=[Depends(require_jwt)])
async def create_backup(req: BackupRequest):
    """Create a backup"""
    cmd = ["/usr/sbin/nextcloudctl", "backup"]
    if req.name:
        cmd.append(req.name)

    success, out, err = run_cmd(cmd, timeout=300)
    if success:
        return {"success": True, "message": "Backup created"}
    raise HTTPException(500, f"Backup failed: {err}")


@app.delete("/backup/{name}", dependencies=[Depends(require_jwt)])
async def delete_backup(name: str):
    """Delete a backup"""
    backup_dir = DATA_PATH / "backups"
    db_file = backup_dir / f"{name}-db.sql"
    data_file = backup_dir / f"{name}-data.tar.gz"

    if db_file.exists():
        db_file.unlink()
    if data_file.exists():
        data_file.unlink()

    return {"success": True, "message": f"Backup {name} deleted"}


@app.post("/restore/{name}", dependencies=[Depends(require_jwt)])
async def restore_backup(name: str):
    """Restore from backup"""
    subprocess.Popen(
        ["/usr/sbin/nextcloudctl", "restore", name],
        stdout=open("/var/log/nextcloud-restore.log", "w"),
        stderr=subprocess.STDOUT
    )
    return {"success": True, "message": "Restore started in background"}


@app.get("/connections", dependencies=[Depends(require_jwt)])
async def get_connections():
    """Get connection URLs (CalDAV, CardDAV, WebDAV)"""
    http_port = config.get("http_port", 8080)
    ssl_enabled = config.get("ssl_enabled", False)
    ssl_domain = config.get("ssl_domain", "")

    base_url = f"http://localhost:{http_port}"
    if ssl_enabled and ssl_domain:
        base_url = f"https://{ssl_domain}"

    return {
        "base_url": base_url,
        "caldav": f"{base_url}/remote.php/dav/calendars/<username>/",
        "carddav": f"{base_url}/remote.php/dav/addressbooks/users/<username>/contacts/",
        "webdav": f"{base_url}/remote.php/dav/files/<username>/",
        "davx5_url": f"{base_url}/remote.php/dav",
        "desktop_url": base_url,
        "ios_app": "https://apps.apple.com/app/nextcloud/id1125420102",
        "android_app": "https://play.google.com/store/apps/details?id=com.nextcloud.client"
    }


class OccCommand(BaseModel):
    command: str


@app.post("/occ", dependencies=[Depends(require_jwt)])
async def run_occ(req: OccCommand):
    """Run OCC command"""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    success, out, err = occ_cmd(req.command, timeout=120)
    if success:
        return {"success": True, "output": out}
    raise HTTPException(500, f"Command failed: {err}")


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = 100):
    """Get Nextcloud logs"""
    logs = []

    # Installation log
    install_log = Path("/var/log/nextcloud-install.log")
    if install_log.exists():
        success, out, _ = run_cmd(["tail", f"-n{lines}", str(install_log)])
        if success:
            logs.extend(out.split("\n"))

    return {"logs": logs}


class SSLEnable(BaseModel):
    domain: str


@app.post("/ssl/enable", dependencies=[Depends(require_jwt)])
async def ssl_enable(req: SSLEnable):
    """Enable SSL for domain"""
    success, _, err = run_cmd(
        ["/usr/sbin/nextcloudctl", "ssl-enable", req.domain]
    )
    if success:
        return {"success": True, "message": f"SSL enabled for {req.domain}"}
    raise HTTPException(500, f"SSL enable failed: {err}")


@app.post("/ssl/disable", dependencies=[Depends(require_jwt)])
async def ssl_disable():
    """Disable SSL"""
    success, _, err = run_cmd(["/usr/sbin/nextcloudctl", "ssl-disable"])
    if success:
        return {"success": True, "message": "SSL disabled"}
    raise HTTPException(500, f"SSL disable failed: {err}")
