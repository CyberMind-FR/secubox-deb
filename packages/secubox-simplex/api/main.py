#!/usr/bin/env python3
"""
SecuBox-Deb :: SimpleX Chat Server API
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

SimpleX Chat SMP/XFTP server management with Docker/Podman support.
Zero-knowledge messaging infrastructure with no user identifiers.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import subprocess
import os
import json
import shutil
from pathlib import Path
from datetime import datetime
import asyncio

app = FastAPI(
    title="SecuBox SimpleX API",
    description="SimpleX Chat SMP/XFTP server management",
    version="1.0.0"
)

# Configuration
CONTAINER_NAME = "simplex-smp"
DATA_DIR = Path("/var/lib/secubox/simplex")
BACKUP_DIR = Path("/var/lib/secubox/simplex/backups")
CONFIG_DIR = Path("/etc/secubox/simplex")
TLS_DIR = Path("/etc/secubox/simplex/tls")
CACHE_FILE = Path("/var/cache/secubox/simplex/stats.json")

SMP_PORT = 5223
XFTP_PORT = 443
SMP_IMAGE = "simplexchat/smp-server:latest"
XFTP_IMAGE = "simplexchat/xftp-server:latest"


class ServerConfig(BaseModel):
    """Server configuration model"""
    server_address: Optional[str] = None
    enable_xftp: bool = False
    log_level: str = "info"
    max_connections: int = 10000
    require_auth: bool = False


class BackupRequest(BaseModel):
    """Backup request model"""
    name: Optional[str] = None


class RestoreRequest(BaseModel):
    """Restore request model"""
    backup_name: str


def run_cmd(cmd: list, timeout: int = 30) -> dict:
    """Run command and return result"""
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
    """Detect container runtime (docker or podman)"""
    for runtime in ["docker", "podman"]:
        result = run_cmd([runtime, "--version"])
        if result["success"]:
            return runtime
    return None


def container_cmd(args: list, timeout: int = 30) -> dict:
    """Run container command with detected runtime"""
    runtime = get_container_runtime()
    if not runtime:
        return {"success": False, "error": "No container runtime (docker/podman) found"}
    return run_cmd([runtime] + args, timeout)


def container_exec(cmd: str, timeout: int = 30) -> dict:
    """Execute command inside container"""
    runtime = get_container_runtime()
    if not runtime:
        return {"success": False, "error": "No container runtime found"}
    return run_cmd([runtime, "exec", CONTAINER_NAME, "sh", "-c", cmd], timeout)


def container_exists() -> bool:
    """Check if container exists"""
    result = container_cmd(["ps", "-a", "--filter", f"name=^{CONTAINER_NAME}$", "--format", "{{.Names}}"])
    return result["success"] and CONTAINER_NAME in result.get("stdout", "")


def container_running() -> bool:
    """Check if container is running"""
    result = container_cmd(["ps", "--filter", f"name=^{CONTAINER_NAME}$", "--format", "{{.Names}}"])
    return result["success"] and CONTAINER_NAME in result.get("stdout", "")


def get_container_ip() -> Optional[str]:
    """Get container IP address"""
    result = container_cmd([
        "inspect", CONTAINER_NAME,
        "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
    ])
    if result["success"] and result["stdout"].strip():
        return result["stdout"].strip()
    return None


def get_server_fingerprint() -> Optional[str]:
    """Get SMP server fingerprint"""
    fingerprint_file = DATA_DIR / "smp" / "fingerprint"
    if fingerprint_file.exists():
        return fingerprint_file.read_text().strip()
    # Try from container
    result = container_exec("cat /etc/opt/simplex/fingerprint 2>/dev/null")
    if result["success"] and result["stdout"].strip():
        return result["stdout"].strip()
    return None


def load_config() -> dict:
    """Load server configuration"""
    config_file = CONFIG_DIR / "simplex.json"
    if config_file.exists():
        try:
            return json.loads(config_file.read_text())
        except:
            pass
    return {
        "server_address": "",
        "enable_xftp": False,
        "log_level": "info",
        "max_connections": 10000,
        "require_auth": False
    }


def save_config(config: dict):
    """Save server configuration"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config_file = CONFIG_DIR / "simplex.json"
    config_file.write_text(json.dumps(config, indent=2))


# =============================================================================
# Health and Status Endpoints
# =============================================================================

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok", "service": "simplex"}


@app.get("/status")
async def status():
    """Get SimpleX server status"""
    runtime = get_container_runtime()
    exists = container_exists()
    running = container_running() if exists else False
    ip = get_container_ip() if running else None
    fingerprint = get_server_fingerprint() if running else None
    config = load_config()

    smp_running = False
    xftp_running = False

    if running:
        # Check SMP process
        result = container_exec("pgrep -x smp-server || pgrep -f 'smp-server'")
        smp_running = result["success"] and result.get("stdout", "").strip()

        # Check XFTP process
        if config.get("enable_xftp"):
            result = container_exec("pgrep -x xftp-server || pgrep -f 'xftp-server'")
            xftp_running = result["success"] and result.get("stdout", "").strip()

    return {
        "container_exists": exists,
        "running": running,
        "container_runtime": runtime,
        "container_ip": ip,
        "smp_running": smp_running,
        "xftp_running": xftp_running,
        "smp_port": SMP_PORT,
        "xftp_port": XFTP_PORT,
        "server_address": config.get("server_address", ip),
        "fingerprint": fingerprint,
        "enable_xftp": config.get("enable_xftp", False)
    }


# =============================================================================
# Server Information
# =============================================================================

@app.get("/server/info")
async def server_info():
    """Get detailed server information"""
    if not container_running():
        raise HTTPException(status_code=400, detail="Container not running")

    fingerprint = get_server_fingerprint()
    config = load_config()
    ip = get_container_ip()

    # Get version
    result = container_exec("smp-server --version 2>/dev/null || echo 'unknown'")
    version = result.get("stdout", "unknown").strip()

    # Get uptime
    result = container_cmd(["inspect", CONTAINER_NAME, "--format", "{{.State.StartedAt}}"])
    started_at = result.get("stdout", "").strip() if result["success"] else None

    return {
        "version": version,
        "fingerprint": fingerprint,
        "server_address": config.get("server_address") or ip,
        "container_ip": ip,
        "smp_port": SMP_PORT,
        "xftp_port": XFTP_PORT if config.get("enable_xftp") else None,
        "started_at": started_at,
        "data_dir": str(DATA_DIR)
    }


@app.get("/server/config")
async def get_config():
    """Get server configuration"""
    config = load_config()
    return {"config": config}


@app.post("/server/config")
async def update_config(new_config: ServerConfig):
    """Update server configuration"""
    config = load_config()

    if new_config.server_address is not None:
        config["server_address"] = new_config.server_address
    config["enable_xftp"] = new_config.enable_xftp
    config["log_level"] = new_config.log_level
    config["max_connections"] = new_config.max_connections
    config["require_auth"] = new_config.require_auth

    save_config(config)
    return {"success": True, "config": config}


# =============================================================================
# Statistics Endpoints
# =============================================================================

@app.get("/stats")
async def get_stats():
    """Get server statistics"""
    if not container_running():
        return {"stats": {"queues": 0, "connections": 0, "storage_used": "0"}}

    stats = {}

    # Count queues
    result = container_exec("ls -1 /var/opt/simplex/smp-server/queues/ 2>/dev/null | wc -l")
    stats["queues"] = int(result.get("stdout", "0").strip()) if result["success"] else 0

    # Storage used
    result = container_exec("du -sh /var/opt/simplex/ 2>/dev/null | cut -f1")
    stats["storage_used"] = result.get("stdout", "0").strip() if result["success"] else "0"

    # Active connections (approximate from netstat)
    result = container_exec(f"netstat -an 2>/dev/null | grep :{SMP_PORT} | grep ESTABLISHED | wc -l")
    stats["connections"] = int(result.get("stdout", "0").strip()) if result["success"] else 0

    # Messages processed (from logs if available)
    result = container_exec("cat /var/log/smp-server.log 2>/dev/null | grep -c 'message' || echo 0")
    stats["messages_processed"] = int(result.get("stdout", "0").strip()) if result["success"] else 0

    return {"stats": stats}


@app.get("/stats/queues")
async def get_queue_stats():
    """Get detailed queue statistics"""
    if not container_running():
        return {"queues": [], "total": 0}

    result = container_exec("ls -la /var/opt/simplex/smp-server/queues/ 2>/dev/null")
    queues = []

    if result["success"]:
        for line in result["stdout"].split("\n")[1:]:  # Skip total line
            parts = line.split()
            if len(parts) >= 9 and not parts[-1].startswith('.'):
                queues.append({
                    "name": parts[-1],
                    "size": parts[4],
                    "modified": f"{parts[5]} {parts[6]} {parts[7]}"
                })

    return {"queues": queues, "total": len(queues)}


@app.get("/stats/connections")
async def get_connections():
    """Get active connection statistics"""
    if not container_running():
        return {"connections": [], "total": 0}

    result = container_exec(f"netstat -an 2>/dev/null | grep :{SMP_PORT} | grep ESTABLISHED")
    connections = []

    if result["success"]:
        for line in result["stdout"].split("\n"):
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    "local": parts[3],
                    "remote": parts[4],
                    "state": parts[5] if len(parts) > 5 else "ESTABLISHED"
                })

    return {"connections": connections, "total": len(connections)}


# =============================================================================
# Container Management
# =============================================================================

@app.get("/container/status")
async def container_status():
    """Get container status"""
    runtime = get_container_runtime()
    if not runtime:
        return {
            "runtime": None,
            "available": False,
            "message": "No container runtime (docker/podman) found"
        }

    exists = container_exists()
    running = container_running() if exists else False

    info = {}
    if exists:
        result = container_cmd(["inspect", CONTAINER_NAME])
        if result["success"]:
            try:
                data = json.loads(result["stdout"])[0]
                info = {
                    "id": data.get("Id", "")[:12],
                    "image": data.get("Config", {}).get("Image", ""),
                    "created": data.get("Created", ""),
                    "status": data.get("State", {}).get("Status", ""),
                    "started_at": data.get("State", {}).get("StartedAt", ""),
                }
            except:
                pass

    return {
        "runtime": runtime,
        "available": True,
        "exists": exists,
        "running": running,
        "info": info
    }


@app.post("/container/install")
async def install_container(server_address: str = ""):
    """Install SimpleX SMP server container"""
    runtime = get_container_runtime()
    if not runtime:
        raise HTTPException(status_code=500, detail="No container runtime found. Install docker or podman.")

    if container_exists():
        raise HTTPException(status_code=400, detail="Container already exists")

    # Create directories
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "smp").mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    TLS_DIR.mkdir(parents=True, exist_ok=True)

    # Pull image
    result = container_cmd(["pull", SMP_IMAGE], timeout=300)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Failed to pull image: {result.get('stderr')}")

    # Get host IP if not provided
    if not server_address:
        result = run_cmd(["hostname", "-I"])
        if result["success"]:
            server_address = result["stdout"].strip().split()[0]
        else:
            server_address = "127.0.0.1"

    # Create container
    result = container_cmd([
        "run", "-d",
        "--name", CONTAINER_NAME,
        "--restart", "unless-stopped",
        "-p", f"{SMP_PORT}:{SMP_PORT}",
        "-v", f"{DATA_DIR}/smp:/var/opt/simplex:Z",
        "-v", f"{TLS_DIR}:/etc/opt/simplex/tls:Z",
        "-e", f"ADDR={server_address}",
        "-e", "PASS=",
        SMP_IMAGE
    ], timeout=120)

    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Container creation failed: {result.get('stderr')}")

    # Save config
    save_config({
        "server_address": server_address,
        "enable_xftp": False,
        "log_level": "info",
        "max_connections": 10000,
        "require_auth": False
    })

    # Wait for initialization
    await asyncio.sleep(5)

    fingerprint = get_server_fingerprint()

    return {
        "success": True,
        "message": "SimpleX SMP server installed",
        "server_address": server_address,
        "fingerprint": fingerprint,
        "smp_port": SMP_PORT
    }


@app.post("/container/start")
async def start_container():
    """Start SimpleX container"""
    if not container_exists():
        raise HTTPException(status_code=404, detail="Container not found. Install first.")

    if container_running():
        return {"success": True, "message": "Already running"}

    result = container_cmd(["start", CONTAINER_NAME])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Start failed"))

    await asyncio.sleep(2)
    return {"success": True, "container_ip": get_container_ip()}


@app.post("/container/stop")
async def stop_container():
    """Stop SimpleX container"""
    if not container_exists():
        raise HTTPException(status_code=404, detail="Container not found")

    result = container_cmd(["stop", CONTAINER_NAME])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Stop failed"))

    return {"success": True}


@app.post("/container/restart")
async def restart_container():
    """Restart SimpleX container"""
    if not container_exists():
        raise HTTPException(status_code=404, detail="Container not found")

    result = container_cmd(["restart", CONTAINER_NAME])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Restart failed"))

    await asyncio.sleep(2)
    return {"success": True, "container_ip": get_container_ip()}


@app.delete("/container")
async def delete_container():
    """Delete SimpleX container"""
    if container_running():
        container_cmd(["stop", CONTAINER_NAME])

    result = container_cmd(["rm", CONTAINER_NAME])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("stderr", "Delete failed"))

    return {"success": True, "message": "Container deleted"}


# =============================================================================
# TLS Certificate Management
# =============================================================================

@app.get("/tls/status")
async def tls_status():
    """Get TLS certificate status"""
    cert_file = TLS_DIR / "server.crt"
    key_file = TLS_DIR / "server.key"

    if not cert_file.exists():
        return {
            "enabled": False,
            "certificate": None,
            "message": "No TLS certificate configured"
        }

    # Get certificate info
    result = run_cmd([
        "openssl", "x509", "-in", str(cert_file),
        "-noout", "-subject", "-enddate", "-issuer"
    ])

    cert_info = {}
    if result["success"]:
        for line in result["stdout"].split("\n"):
            if "subject=" in line:
                cert_info["subject"] = line.split("subject=")[1].strip()
            elif "notAfter=" in line:
                cert_info["expires"] = line.split("notAfter=")[1].strip()
            elif "issuer=" in line:
                cert_info["issuer"] = line.split("issuer=")[1].strip()

    return {
        "enabled": True,
        "certificate": cert_info,
        "cert_path": str(cert_file),
        "key_path": str(key_file)
    }


@app.post("/tls/renew")
async def tls_renew(domain: Optional[str] = None):
    """Renew TLS certificate (self-signed or request Let's Encrypt)"""
    TLS_DIR.mkdir(parents=True, exist_ok=True)

    config = load_config()
    domain = domain or config.get("server_address") or "localhost"

    # Generate self-signed certificate
    result = run_cmd([
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", str(TLS_DIR / "server.key"),
        "-out", str(TLS_DIR / "server.crt"),
        "-days", "365", "-nodes",
        "-subj", f"/CN={domain}/O=SecuBox/C=FR"
    ])

    if not result["success"]:
        raise HTTPException(status_code=500, detail=f"Certificate generation failed: {result.get('stderr')}")

    # Set permissions
    os.chmod(TLS_DIR / "server.key", 0o600)
    os.chmod(TLS_DIR / "server.crt", 0o644)

    # Restart container to pick up new cert
    if container_running():
        container_cmd(["restart", CONTAINER_NAME])

    return {
        "success": True,
        "message": f"Self-signed certificate generated for {domain}",
        "expires_in_days": 365
    }


# =============================================================================
# Backup and Restore
# =============================================================================

@app.get("/backup")
async def list_backups():
    """List available backups"""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    backups = []
    for backup in sorted(BACKUP_DIR.glob("*.tar.gz"), reverse=True):
        stat = backup.stat()
        backups.append({
            "name": backup.name,
            "size": stat.st_size,
            "size_human": f"{stat.st_size / (1024*1024):.1f} MB",
            "created": datetime.fromtimestamp(stat.st_mtime).isoformat()
        })

    return {"backups": backups, "total": len(backups)}


@app.post("/backup/create")
async def create_backup(request: BackupRequest):
    """Create a backup of SimpleX data"""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = request.name or f"simplex_backup_{timestamp}"
    if not backup_name.endswith(".tar.gz"):
        backup_name += ".tar.gz"

    backup_path = BACKUP_DIR / backup_name

    # Stop container for consistent backup
    was_running = container_running()
    if was_running:
        container_cmd(["stop", CONTAINER_NAME])

    try:
        # Create backup
        result = run_cmd([
            "tar", "-czf", str(backup_path),
            "-C", str(DATA_DIR.parent),
            DATA_DIR.name
        ])

        if not result["success"]:
            raise HTTPException(status_code=500, detail=f"Backup failed: {result.get('stderr')}")

    finally:
        # Restart container if it was running
        if was_running:
            container_cmd(["start", CONTAINER_NAME])

    stat = backup_path.stat()
    return {
        "success": True,
        "backup": {
            "name": backup_name,
            "path": str(backup_path),
            "size": stat.st_size,
            "size_human": f"{stat.st_size / (1024*1024):.1f} MB"
        }
    }


@app.post("/backup/restore")
async def restore_backup(request: RestoreRequest):
    """Restore from a backup"""
    backup_path = BACKUP_DIR / request.backup_name

    if not backup_path.exists():
        raise HTTPException(status_code=404, detail=f"Backup not found: {request.backup_name}")

    # Stop container
    was_running = container_running()
    if was_running:
        container_cmd(["stop", CONTAINER_NAME])

    try:
        # Remove current data
        if (DATA_DIR / "smp").exists():
            shutil.rmtree(DATA_DIR / "smp")

        # Restore backup
        result = run_cmd([
            "tar", "-xzf", str(backup_path),
            "-C", str(DATA_DIR.parent)
        ])

        if not result["success"]:
            raise HTTPException(status_code=500, detail=f"Restore failed: {result.get('stderr')}")

    finally:
        # Restart container
        if was_running:
            container_cmd(["start", CONTAINER_NAME])

    return {"success": True, "message": f"Restored from {request.backup_name}"}


@app.delete("/backup/{backup_name}")
async def delete_backup(backup_name: str):
    """Delete a backup"""
    backup_path = BACKUP_DIR / backup_name

    if not backup_path.exists():
        raise HTTPException(status_code=404, detail="Backup not found")

    backup_path.unlink()
    return {"success": True, "message": f"Deleted {backup_name}"}


# =============================================================================
# Maintenance
# =============================================================================

@app.post("/maintenance/cleanup")
async def cleanup_old_queues(days_old: int = 30):
    """Clean up old/inactive queues"""
    if not container_running():
        raise HTTPException(status_code=400, detail="Container not running")

    result = container_exec(
        f"find /var/opt/simplex/smp-server/queues -type f -mtime +{days_old} -delete 2>/dev/null; echo $?"
    )

    return {
        "success": True,
        "message": f"Cleaned up queues older than {days_old} days"
    }


# =============================================================================
# Connection String
# =============================================================================

@app.get("/connection-string")
async def get_connection_string():
    """Get SMP server connection string for clients"""
    if not container_running():
        raise HTTPException(status_code=400, detail="Container not running")

    fingerprint = get_server_fingerprint()
    config = load_config()
    address = config.get("server_address") or get_container_ip()

    if fingerprint and address:
        connection_string = f"smp://{fingerprint}@{address}:{SMP_PORT}"
        return {
            "connection_string": connection_string,
            "fingerprint": fingerprint,
            "address": address,
            "port": SMP_PORT
        }

    raise HTTPException(status_code=404, detail="Could not generate connection string")


@app.get("/fingerprint")
async def get_fingerprint():
    """Get server fingerprint"""
    fingerprint = get_server_fingerprint()
    if fingerprint:
        return {"fingerprint": fingerprint}
    raise HTTPException(status_code=404, detail="Fingerprint not found")


# =============================================================================
# Logs
# =============================================================================

@app.get("/logs")
async def get_logs(lines: int = 100, filter: Optional[str] = None):
    """Get server logs"""
    result = container_cmd(["logs", "--tail", str(lines), CONTAINER_NAME])

    if result["success"]:
        logs = result["stdout"].split("\n") + result["stderr"].split("\n")
        if filter:
            logs = [l for l in logs if filter.lower() in l.lower()]
        return {"logs": logs}

    return {"logs": []}


# Legacy endpoints for backward compatibility
@app.post("/install")
async def install(server_address: str = ""):
    """Legacy install endpoint - redirects to container/install"""
    return await install_container(server_address)


@app.post("/start")
async def start():
    """Legacy start endpoint"""
    return await start_container()


@app.post("/stop")
async def stop():
    """Legacy stop endpoint"""
    return await stop_container()


@app.post("/restart")
async def restart():
    """Legacy restart endpoint"""
    return await restart_container()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
