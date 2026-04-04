"""
SecuBox-Deb :: secubox-admin
CyberMind - https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

System administration module - advanced admin tasks for SecuBox.
"""
import subprocess
import psutil
import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-admin", version="1.0.0", root_path="/api/v1/admin")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("admin")

# Configuration
DATA_DIR = Path("/var/lib/secubox/admin")
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = Path("/etc/secubox/admin.toml")
AUDIT_LOG = Path("/var/log/secubox/audit.log")


# Pydantic Models
class ServiceActionRequest(BaseModel):
    """Service action request."""
    confirm: bool = Field(default=False, description="Confirmation flag")


class SystemActionRequest(BaseModel):
    """System action request (reboot/shutdown)."""
    confirm: bool = Field(..., description="Must confirm dangerous action")
    reason: str = Field(default="", description="Reason for action")


class UpdateRequest(BaseModel):
    """APT update request."""
    confirm: bool = Field(..., description="Must confirm update")
    packages: List[str] = Field(default=[], description="Specific packages to update, empty = all")


def _audit_log(user: str, action: str, details: str = ""):
    """Write to audit log (CSPN compliant)."""
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().isoformat()
        entry = f"[{timestamp}] ADMIN user={user} action={action} {details}\n"
        with open(AUDIT_LOG, "a") as f:
            f.write(entry)
    except Exception as e:
        log.warning("audit log write failed: %s", e)


def _run_cmd(cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
    """Run command and return result."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout[:10000],
            "stderr": result.stderr[:2000],
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Command timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _format_size(size: float) -> str:
    """Format bytes to human readable size."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def _get_system_status() -> Dict[str, Any]:
    """Get system status overview."""
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        load = psutil.getloadavg()
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time

        # Get hostname
        hostname = subprocess.run(
            ["hostname"],
            capture_output=True,
            text=True,
            timeout=5
        ).stdout.strip()

        # Get kernel version
        kernel = subprocess.run(
            ["uname", "-r"],
            capture_output=True,
            text=True,
            timeout=5
        ).stdout.strip()

        # Get Debian version
        debian_version = ""
        try:
            with open("/etc/debian_version") as f:
                debian_version = f.read().strip()
        except Exception:
            pass

        return {
            "hostname": hostname,
            "kernel": kernel,
            "debian_version": debian_version,
            "cpu_percent": round(cpu, 1),
            "memory_percent": round(mem.percent, 1),
            "memory_used": _format_size(mem.used),
            "memory_total": _format_size(mem.total),
            "disk_percent": round(disk.percent, 1),
            "disk_used": _format_size(disk.used),
            "disk_total": _format_size(disk.total),
            "load_avg": [round(l, 2) for l in load],
            "uptime_seconds": int(uptime.total_seconds()),
            "uptime_human": str(uptime).split('.')[0],
            "boot_time": boot_time.isoformat(),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        log.warning("status error: %s", e)
        return {"error": str(e), "timestamp": datetime.now().isoformat()}


def _get_services_status() -> List[Dict[str, Any]]:
    """Get all systemd services status."""
    try:
        # Get list of services
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend"],
            capture_output=True,
            text=True,
            timeout=30
        )

        services = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4:
                unit = parts[0]
                load = parts[1]
                active = parts[2]
                sub = parts[3]
                desc = ' '.join(parts[4:]) if len(parts) > 4 else ""

                # Skip temporary and slice units
                if unit.endswith('.slice') or unit.endswith('.mount'):
                    continue

                services.append({
                    "name": unit.replace('.service', ''),
                    "unit": unit,
                    "load": load,
                    "active": active,
                    "sub": sub,
                    "description": desc,
                    "is_running": active == "active" and sub == "running",
                    "is_secubox": unit.startswith("secubox-")
                })

        # Sort: secubox services first, then alphabetically
        services.sort(key=lambda x: (not x["is_secubox"], x["name"]))
        return services
    except Exception as e:
        log.warning("services error: %s", e)
        return []


def _get_service_status(name: str) -> Dict[str, Any]:
    """Get single service status."""
    try:
        unit = name if name.endswith('.service') else f"{name}.service"

        # Get status
        status_result = subprocess.run(
            ["systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,Description,MainPID,MemoryCurrent"],
            capture_output=True,
            text=True,
            timeout=10
        )

        props = {}
        for line in status_result.stdout.strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                props[key] = value

        # Get recent logs
        log_result = subprocess.run(
            ["journalctl", "-u", unit, "-n", "20", "--no-pager", "--output=short"],
            capture_output=True,
            text=True,
            timeout=10
        )

        return {
            "name": name,
            "unit": unit,
            "load_state": props.get("LoadState", "unknown"),
            "active_state": props.get("ActiveState", "unknown"),
            "sub_state": props.get("SubState", "unknown"),
            "description": props.get("Description", ""),
            "main_pid": int(props.get("MainPID", 0)) or None,
            "memory": props.get("MemoryCurrent", ""),
            "is_running": props.get("ActiveState") == "active",
            "recent_logs": log_result.stdout.split('\n')[-20:],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {"name": name, "error": str(e)}


def _get_storage_info() -> Dict[str, Any]:
    """Get disk usage overview."""
    try:
        partitions = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                partitions.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total": usage.total,
                    "total_human": _format_size(usage.total),
                    "used": usage.used,
                    "used_human": _format_size(usage.used),
                    "free": usage.free,
                    "free_human": _format_size(usage.free),
                    "percent": round(usage.percent, 1)
                })
            except PermissionError:
                continue

        # Get disk I/O
        io = psutil.disk_io_counters()
        io_info = {
            "read_bytes": io.read_bytes if io else 0,
            "write_bytes": io.write_bytes if io else 0,
            "read_count": io.read_count if io else 0,
            "write_count": io.write_count if io else 0
        }

        return {
            "partitions": partitions,
            "io": io_info,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {"partitions": [], "error": str(e)}


def _get_processes(sort_by: str = "cpu", limit: int = 50) -> Dict[str, Any]:
    """Get top processes by CPU or memory."""
    try:
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent',
                                       'status', 'username', 'num_threads', 'create_time', 'cmdline']):
            try:
                info = p.info
                if info['cpu_percent'] is None:
                    continue

                cmdline = info.get('cmdline', [])
                cmd = ' '.join(cmdline[:3]) if cmdline else info['name']

                procs.append({
                    "pid": info['pid'],
                    "name": info['name'] or "unknown",
                    "cmd": cmd[:100],
                    "cpu_percent": round(info['cpu_percent'] or 0, 1),
                    "memory_percent": round(info['memory_percent'] or 0, 1),
                    "status": info.get('status', 'unknown'),
                    "user": info.get('username', 'unknown'),
                    "threads": info.get('num_threads', 0),
                    "started": datetime.fromtimestamp(info.get('create_time', 0)).isoformat() if info.get('create_time') else None
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort by requested field
        sort_key = 'cpu_percent' if sort_by == 'cpu' else 'memory_percent'
        procs.sort(key=lambda x: x[sort_key], reverse=True)

        return {
            "processes": procs[:limit],
            "total": len(procs),
            "sort_by": sort_by,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {"processes": [], "error": str(e)}


def _get_system_logs(unit: str = "", lines: int = 100, priority: str = "") -> Dict[str, Any]:
    """Get system logs from journalctl."""
    try:
        cmd = ["journalctl", "-n", str(lines), "--no-pager", "-o", "short-iso"]

        if unit:
            cmd.extend(["-u", unit])
        if priority:
            cmd.extend(["-p", priority])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        log_lines = result.stdout.strip().split('\n')
        return {
            "logs": log_lines,
            "count": len(log_lines),
            "unit": unit or "all",
            "priority": priority or "all",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {"logs": [], "error": str(e)}


def _get_available_updates() -> Dict[str, Any]:
    """Check for available apt updates."""
    try:
        # First update cache (non-blocking check)
        update_result = subprocess.run(
            ["apt-get", "update", "-qq"],
            capture_output=True,
            text=True,
            timeout=60
        )

        # List upgradable packages
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True,
            text=True,
            timeout=30
        )

        packages = []
        for line in result.stdout.strip().split('\n'):
            if '/' in line and 'upgradable' in line.lower():
                # Parse: package/suite version arch [upgradable from: old_version]
                parts = line.split()
                if len(parts) >= 2:
                    pkg_name = parts[0].split('/')[0]
                    new_version = parts[1] if len(parts) > 1 else "unknown"
                    old_version = ""
                    if 'from:' in line:
                        old_version = line.split('from:')[-1].strip().rstrip(']')

                    packages.append({
                        "name": pkg_name,
                        "new_version": new_version,
                        "old_version": old_version
                    })

        # Check for security updates
        security_count = sum(1 for p in packages if 'security' in str(p).lower())

        return {
            "available": len(packages),
            "security_updates": security_count,
            "packages": packages,
            "last_check": datetime.now().isoformat()
        }
    except subprocess.TimeoutExpired:
        return {"available": 0, "packages": [], "error": "Update check timeout"}
    except Exception as e:
        return {"available": 0, "packages": [], "error": str(e)}


# Health endpoint (public)
@router.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "module": "admin", "version": "1.0.0"}


# Status endpoint (public for dashboard widgets)
@router.get("/status")
async def status():
    """System status overview."""
    return _get_system_status()


# Protected endpoints
@router.get("/services")
async def get_services(user=Depends(require_jwt)):
    """Get all systemd services status."""
    services = _get_services_status()
    return {
        "services": services,
        "count": len(services),
        "secubox_count": sum(1 for s in services if s.get("is_secubox")),
        "running_count": sum(1 for s in services if s.get("is_running")),
        "timestamp": datetime.now().isoformat()
    }


@router.get("/service/{name}")
async def get_service(name: str, user=Depends(require_jwt)):
    """Get single service status with logs."""
    return _get_service_status(name)


@router.post("/service/{name}/start")
async def start_service(name: str, user=Depends(require_jwt)):
    """Start a systemd service."""
    unit = name if name.endswith('.service') else f"{name}.service"

    _audit_log(user.get("sub", "unknown"), "service_start", f"unit={unit}")
    log.info("service start requested: %s by %s", unit, user.get("sub"))

    result = _run_cmd(["systemctl", "start", unit], timeout=30)
    result["unit"] = unit
    result["action"] = "start"
    return result


@router.post("/service/{name}/stop")
async def stop_service(name: str, user=Depends(require_jwt)):
    """Stop a systemd service."""
    unit = name if name.endswith('.service') else f"{name}.service"

    _audit_log(user.get("sub", "unknown"), "service_stop", f"unit={unit}")
    log.info("service stop requested: %s by %s", unit, user.get("sub"))

    result = _run_cmd(["systemctl", "stop", unit], timeout=30)
    result["unit"] = unit
    result["action"] = "stop"
    return result


@router.post("/service/{name}/restart")
async def restart_service(name: str, user=Depends(require_jwt)):
    """Restart a systemd service."""
    unit = name if name.endswith('.service') else f"{name}.service"

    _audit_log(user.get("sub", "unknown"), "service_restart", f"unit={unit}")
    log.info("service restart requested: %s by %s", unit, user.get("sub"))

    result = _run_cmd(["systemctl", "restart", unit], timeout=60)
    result["unit"] = unit
    result["action"] = "restart"
    return result


@router.get("/logs")
async def get_logs(
    unit: str = Query("", description="Filter by systemd unit"),
    lines: int = Query(100, ge=10, le=1000),
    priority: str = Query("", description="Filter by priority (emerg,alert,crit,err,warning,notice,info,debug)"),
    user=Depends(require_jwt)
):
    """Get recent system logs."""
    return _get_system_logs(unit, lines, priority)


@router.get("/storage")
async def get_storage(user=Depends(require_jwt)):
    """Get disk usage overview."""
    return _get_storage_info()


@router.get("/processes")
async def get_processes(
    sort: str = Query("cpu", pattern="^(cpu|memory)$"),
    limit: int = Query(50, ge=10, le=200),
    user=Depends(require_jwt)
):
    """Get top processes by CPU or memory."""
    return _get_processes(sort, limit)


@router.post("/reboot")
async def reboot_system(request: SystemActionRequest, user=Depends(require_jwt)):
    """Reboot the system (requires confirmation)."""
    if not request.confirm:
        raise HTTPException(status_code=400, detail="Confirmation required for reboot")

    _audit_log(user.get("sub", "unknown"), "system_reboot", f"reason={request.reason}")
    log.warning("SYSTEM REBOOT requested by %s, reason: %s", user.get("sub"), request.reason)

    # Schedule reboot in 5 seconds
    subprocess.Popen(["shutdown", "-r", "+0", request.reason or "Admin requested reboot"])

    return {
        "success": True,
        "message": "System reboot initiated",
        "timestamp": datetime.now().isoformat()
    }


@router.post("/shutdown")
async def shutdown_system(request: SystemActionRequest, user=Depends(require_jwt)):
    """Shutdown the system (requires confirmation)."""
    if not request.confirm:
        raise HTTPException(status_code=400, detail="Confirmation required for shutdown")

    _audit_log(user.get("sub", "unknown"), "system_shutdown", f"reason={request.reason}")
    log.warning("SYSTEM SHUTDOWN requested by %s, reason: %s", user.get("sub"), request.reason)

    # Schedule shutdown in 5 seconds
    subprocess.Popen(["shutdown", "-h", "+0", request.reason or "Admin requested shutdown"])

    return {
        "success": True,
        "message": "System shutdown initiated",
        "timestamp": datetime.now().isoformat()
    }


@router.get("/updates")
async def get_updates(user=Depends(require_jwt)):
    """Check for available apt updates."""
    return _get_available_updates()


@router.post("/update")
async def run_update(request: UpdateRequest, user=Depends(require_jwt)):
    """Run apt upgrade (requires confirmation)."""
    if not request.confirm:
        raise HTTPException(status_code=400, detail="Confirmation required for update")

    packages_str = ','.join(request.packages) if request.packages else "all"
    _audit_log(user.get("sub", "unknown"), "apt_upgrade", f"packages={packages_str}")
    log.info("APT upgrade requested by %s, packages: %s", user.get("sub"), packages_str)

    # Build command
    if request.packages:
        cmd = ["apt-get", "install", "-y", "--only-upgrade"] + request.packages
    else:
        cmd = ["apt-get", "upgrade", "-y"]

    # Run update (longer timeout)
    result = _run_cmd(cmd, timeout=300)
    result["action"] = "upgrade"
    result["packages"] = request.packages or ["all"]
    return result


@router.get("/summary")
async def summary():
    """Get admin summary for dashboard widget."""
    status_info = _get_system_status()
    services = _get_services_status()

    secubox_services = [s for s in services if s.get("is_secubox")]
    running_secubox = sum(1 for s in secubox_services if s.get("is_running"))

    return {
        "hostname": status_info.get("hostname", "unknown"),
        "uptime": status_info.get("uptime_human", "-"),
        "cpu": status_info.get("cpu_percent", 0),
        "memory": status_info.get("memory_percent", 0),
        "disk": status_info.get("disk_percent", 0),
        "load": status_info.get("load_avg", [0, 0, 0]),
        "services_total": len(services),
        "services_running": sum(1 for s in services if s.get("is_running")),
        "secubox_total": len(secubox_services),
        "secubox_running": running_secubox,
        "timestamp": datetime.now().isoformat()
    }


app.include_router(router)
