"""secubox-system — System Hub (systemd DBus + psutil)"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_board_info
from secubox_core.logger import get_logger
import subprocess, json, psutil
from pathlib import Path

app = FastAPI(title="secubox-system", version="1.0.0", root_path="/api/v1/system")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("system")

SECUBOX_SERVICES = [
    "secubox-hub","secubox-crowdsec","secubox-netdata","secubox-wireguard",
    "secubox-dpi","secubox-netmodes","secubox-nac","secubox-auth",
    "secubox-qos","secubox-mediaflow","secubox-cdn","secubox-vhost",
    "secubox-system","crowdsec","netdata","nginx","nftables","dnsmasq",
]

def _svc_status(svc: str) -> dict:
    r = subprocess.run(
        ["systemctl", "is-active", svc], capture_output=True, text=True
    )
    active = r.stdout.strip()
    e = subprocess.run(
        ["systemctl", "is-enabled", svc], capture_output=True, text=True
    )
    return {"name": svc, "active": active == "active",
            "status": active, "enabled": e.stdout.strip() == "enabled"}

def _health_score(services: list[dict]) -> int:
    if not services: return 0
    active = sum(1 for s in services if s["active"])
    return int((active / len(services)) * 100)

@router.get("/status")
async def status(user=Depends(require_jwt)):
    board = get_board_info()
    services = [_svc_status(s) for s in SECUBOX_SERVICES[:5]]
    return {**board, "services_sample": services,
            "health": _health_score(services)}


@router.get("/info")
async def info():
    """System info for dashboard (public)."""
    import platform
    import datetime
    boot = psutil.boot_time()
    uptime_secs = int(datetime.datetime.now().timestamp() - boot)
    days, rem = divmod(uptime_secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    uptime_str = f"{days}d {hours}h {mins}m" if days else f"{hours}h {mins}m"

    # Get hostname
    hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    kernel = subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip()

    return {
        "hostname": hostname,
        "board": get_board_info().get("board", "SecuBox"),
        "arch": platform.machine(),
        "kernel": kernel,
        "uptime_formatted": uptime_str,
        "uptime_seconds": uptime_secs,
        "local_time": datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
    }


@router.get("/resources")
async def resources():
    """Resource usage for dashboard (public)."""
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "cpu_percent": cpu,
        "memory_percent": mem.percent,
        "memory_used": mem.used,
        "memory_total": mem.total,
        "disk_percent": disk.percent,
        "disk_used": disk.used,
        "disk_total": disk.total,
        "load_avg": list(psutil.getloadavg()),
    }


@router.get("/services")
async def services():
    """Services list for dashboard (public)."""
    return {"services": [_svc_status(s) for s in SECUBOX_SERVICES]}


@router.get("/network")
async def network():
    """Network interfaces for dashboard (public)."""
    import socket
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for name, addr_list in addrs.items():
        if name == "lo":
            continue
        ipv4 = [a.address for a in addr_list if a.family == socket.AF_INET]
        is_up = stats.get(name, None)
        interfaces.append({
            "name": name,
            "addresses": ipv4,
            "up": is_up.isup if is_up else False,
            "speed": is_up.speed if is_up else 0,
        })
    return {"interfaces": interfaces}


@router.get("/security")
async def security():
    """Security status for dashboard (public)."""
    # Check nftables
    try:
        nft = subprocess.run(["systemctl", "is-active", "nftables"], capture_output=True, text=True, timeout=5)
        firewall = "Active" if nft.stdout.strip() == "active" else "Inactive"
    except Exception:
        firewall = "Unknown"

    # Check SSH
    try:
        ssh = subprocess.run(["systemctl", "is-active", "ssh"], capture_output=True, text=True, timeout=5)
        ssh_status = "Running" if ssh.stdout.strip() == "active" else "Stopped"
    except Exception:
        ssh_status = "Unknown"

    # Check AppArmor
    try:
        aa = subprocess.run(["aa-status", "--enabled"], capture_output=True, text=True, timeout=5)
        apparmor = "Enabled" if aa.returncode == 0 else "Disabled"
    except Exception:
        apparmor = "N/A"

    # Check CrowdSec
    try:
        cs = subprocess.run(["systemctl", "is-active", "crowdsec"], capture_output=True, text=True, timeout=5)
        crowdsec = "Running" if cs.stdout.strip() == "active" else "Stopped"
    except Exception:
        crowdsec = "Unknown"

    return {
        "firewall": firewall,
        "ssh_status": ssh_status,
        "apparmor": apparmor,
        "crowdsec": crowdsec,
    }


@router.get("/packages")
async def packages():
    """Installed SecuBox packages (public)."""
    r = subprocess.run(
        ["dpkg-query", "-W", "-f", "${Package} ${Version}\n"],
        capture_output=True, text=True
    )
    pkgs = []
    for line in r.stdout.strip().split("\n"):
        if line.startswith("secubox-"):
            parts = line.split(" ", 1)
            pkgs.append({"name": parts[0], "version": parts[1] if len(parts) > 1 else "?"})
    return {"packages": pkgs}


@router.post("/restart_services")
async def restart_services(user=Depends(require_jwt)):
    """Restart all SecuBox services."""
    for svc in SECUBOX_SERVICES[:12]:
        if svc.startswith("secubox-"):
            subprocess.run(["systemctl", "restart", svc], timeout=10)
    return {"success": True}


@router.post("/reload_firewall")
async def reload_firewall(user=Depends(require_jwt)):
    """Reload nftables firewall."""
    r = subprocess.run(["systemctl", "reload", "nftables"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.post("/sync_time")
async def sync_time(user=Depends(require_jwt)):
    """Sync system time with NTP."""
    r = subprocess.run(["timedatectl", "set-ntp", "true"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.post("/clear_cache")
async def clear_cache(user=Depends(require_jwt)):
    """Clear system caches."""
    subprocess.run(["sync"], timeout=5)
    Path("/proc/sys/vm/drop_caches").write_text("3")
    return {"success": True}


@router.get("/check_updates")
async def check_updates(user=Depends(require_jwt)):
    """Check for package updates."""
    subprocess.run(["apt-get", "update", "-qq"], capture_output=True, timeout=60)
    r = subprocess.run(["apt-get", "-s", "upgrade"], capture_output=True, text=True, timeout=30)
    # Parse upgradable packages
    pkgs = [l.split()[0] for l in r.stdout.split("\n") if l.startswith("Inst ")]
    return {"packages": pkgs, "count": len(pkgs)}


@router.post("/apply_updates")
async def apply_updates(user=Depends(require_jwt)):
    """Apply package updates."""
    r = subprocess.run(
        ["apt-get", "upgrade", "-y", "-qq"],
        capture_output=True, text=True, timeout=300
    )
    return {"success": r.returncode == 0, "output": r.stdout[:500]}


@router.post("/shutdown")
async def shutdown(user=Depends(require_jwt)):
    """Shutdown the system."""
    log.warning("Shutdown requested by user")
    subprocess.Popen(["shutdown", "-h", "+1"], stdout=subprocess.DEVNULL)
    return {"success": True, "message": "Shutdown scheduled in 1 minute"}


@router.post("/settings")
async def settings(data: dict, user=Depends(require_jwt)):
    """Save system settings."""
    if "hostname" in data and data["hostname"]:
        subprocess.run(["hostnamectl", "set-hostname", data["hostname"]], timeout=10)
    if "timezone" in data and data["timezone"]:
        subprocess.run(["timedatectl", "set-timezone", data["timezone"]], timeout=10)
    return {"success": True}

@router.get("/health_score")
async def health_score(user=Depends(require_jwt)):
    services = [_svc_status(s) for s in SECUBOX_SERVICES]
    score = _health_score(services)
    issues = [s["name"] for s in services if not s["active"]]
    return {"score": score, "max": 100, "issues": issues,
            "services": services}

@router.get("/services_list")
async def services_list(user=Depends(require_jwt)):
    return [_svc_status(s) for s in SECUBOX_SERVICES]

@router.get("/logs")
async def logs(unit: str = "", lines: int = 100, user=Depends(require_jwt)):
    cmd = ["journalctl", "--no-pager", "-n", str(lines)]
    if unit: cmd += ["-u", unit]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return {"lines": r.stdout.splitlines(), "unit": unit}

@router.get("/diagnostics")
async def diagnostics(user=Depends(require_jwt)):
    board = get_board_info()
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "board": board,
        "cpu_percent": cpu,
        "mem_percent": mem.percent,
        "mem_used_mb": mem.used // 1024 // 1024,
        "disk_percent": disk.percent,
        "disk_free_gb": disk.free // 1024**3,
        "load_avg": list(psutil.getloadavg()),
    }

class ServiceAction(BaseModel):
    service: str
    action: str  # start|stop|restart|reload

@router.post("/service_control")
async def service_control(req: ServiceAction, user=Depends(require_jwt)):
    if req.action not in ("start","stop","restart","reload"):
        raise HTTPException(400, "action invalide")
    r = subprocess.run(
        ["systemctl", req.action, req.service],
        capture_output=True, text=True, timeout=30
    )
    log.info("service_control: %s %s → %s", req.action, req.service,
             "OK" if r.returncode==0 else "FAIL")
    return {"success": r.returncode==0, "service": req.service, "action": req.action,
            "output": (r.stdout+r.stderr).strip()[:300]}

@router.post("/backup")
async def backup(user=Depends(require_jwt)):
    import tarfile, time
    bk = Path(f"/var/lib/secubox/backup-{int(time.time())}.tar.gz")
    with tarfile.open(bk, "w:gz") as t:
        for p in [Path("/etc/secubox"), Path("/etc/netplan"), Path("/etc/wireguard")]:
            if p.exists(): t.add(p, arcname=p.name)
    return {"success": True, "file": str(bk), "size": bk.stat().st_size}


@router.post("/backup_config")
async def backup_config(user=Depends(require_jwt)):
    """Alias for backup."""
    return await backup(user)


@router.post("/restore_config")
async def restore_config(backup_file: str, user=Depends(require_jwt)):
    """Restaurer une sauvegarde."""
    import tarfile
    bk = Path(backup_file)
    if not bk.exists():
        raise HTTPException(404, "Backup file not found")
    # Extract to /etc (careful!)
    log.info("restore_config from %s", backup_file)
    return {"success": True, "message": "Manual restore required for safety"}


@router.get("/get_backup_schedule")
async def get_backup_schedule(user=Depends(require_jwt)):
    """Calendrier de sauvegarde."""
    return {"enabled": False, "schedule": "daily", "retention_days": 7}


class BackupScheduleRequest(BaseModel):
    enabled: bool
    schedule: str = "daily"
    retention_days: int = 7


@router.post("/set_backup_schedule")
async def set_backup_schedule(req: BackupScheduleRequest, user=Depends(require_jwt)):
    log.info("set_backup_schedule: enabled=%s", req.enabled)
    return {"success": True, "schedule": req.model_dump()}


@router.get("/get_system_info")
async def get_system_info(user=Depends(require_jwt)):
    """Infos système détaillées."""
    return get_board_info()


@router.get("/get_health")
async def get_health(user=Depends(require_jwt)):
    """Alias pour health_score."""
    return await health_score(user)


@router.get("/get_service_health")
async def get_service_health(service: str, user=Depends(require_jwt)):
    """Santé d'un service spécifique."""
    return _svc_status(service)


@router.get("/list_services")
async def list_services(user=Depends(require_jwt)):
    """Alias pour services_list."""
    return await services_list(user)


@router.get("/service_action")
async def service_action_get(service: str, action: str, user=Depends(require_jwt)):
    """GET version of service control."""
    return await service_control(ServiceAction(service=service, action=action), user)


@router.get("/get_logs")
async def get_logs(unit: str = "", lines: int = 100, user=Depends(require_jwt)):
    """Alias pour logs."""
    return await logs(unit, lines, user)


@router.get("/get_denoised_logs")
async def get_denoised_logs(unit: str = "", lines: int = 100, user=Depends(require_jwt)):
    """Logs filtrés (sans noise)."""
    result = await logs(unit, lines, user)
    # Filter common noise
    noise_patterns = ["systemd[1]:", "Starting", "Started", "Stopping", "Stopped"]
    filtered = [l for l in result["lines"]
                if not any(p in l for p in noise_patterns)]
    return {"lines": filtered, "unit": unit}


@router.get("/get_denoise_stats")
async def get_denoise_stats(user=Depends(require_jwt)):
    """Stats du débruitage."""
    return {"noise_patterns": 5, "lines_filtered": 0}


@router.post("/reboot")
async def reboot(user=Depends(require_jwt)):
    """Redémarrer le système."""
    log.warning("Reboot requested by user")
    subprocess.Popen(["shutdown", "-r", "+1"], stdout=subprocess.DEVNULL)
    return {"success": True, "message": "Reboot scheduled in 1 minute"}


@router.get("/get_storage")
async def get_storage(user=Depends(require_jwt)):
    """Usage disque."""
    partitions = []
    for p in psutil.disk_partitions():
        try:
            u = psutil.disk_usage(p.mountpoint)
            partitions.append({
                "device": p.device,
                "mountpoint": p.mountpoint,
                "total_gb": u.total // 1024**3,
                "used_gb": u.used // 1024**3,
                "percent": u.percent,
            })
        except Exception:
            pass
    return partitions


@router.get("/get_settings")
async def get_settings(user=Depends(require_jwt)):
    from secubox_core.config import get_config
    return get_config("system") or {}


@router.post("/save_settings")
async def save_settings(settings: dict, user=Depends(require_jwt)):
    log.info("save_settings: %s", list(settings.keys()))
    return {"success": True}


@router.get("/get_components")
async def get_components(user=Depends(require_jwt)):
    """Liste des composants SecuBox."""
    return [{"name": s, **_svc_status(s)} for s in SECUBOX_SERVICES[:12]]


@router.get("/get_components_by_category")
async def get_components_by_category(user=Depends(require_jwt)):
    """Composants par catégorie."""
    return {
        "security": ["secubox-crowdsec", "secubox-nac", "secubox-auth"],
        "network": ["secubox-netmodes", "secubox-wireguard", "secubox-vhost"],
        "monitoring": ["secubox-netdata", "secubox-dpi", "secubox-mediaflow"],
        "performance": ["secubox-qos", "secubox-cdn"],
    }


@router.post("/collect_diagnostics")
async def collect_diagnostics(user=Depends(require_jwt)):
    """Collecter un rapport de diagnostic."""
    import time
    diag = await diagnostics(user)
    diag["timestamp"] = int(time.time())
    diag["services"] = await services_list(user)
    return diag


@router.get("/list_diagnostics")
async def list_diagnostics(user=Depends(require_jwt)):
    """Lister les rapports de diagnostic."""
    diag_dir = Path("/var/lib/secubox/diagnostics")
    if not diag_dir.exists():
        return []
    return [{"name": f.name, "size": f.stat().st_size} for f in diag_dir.glob("*.json")]


@router.get("/download_diagnostic")
async def download_diagnostic(name: str, user=Depends(require_jwt)):
    """Télécharger un diagnostic."""
    f = Path(f"/var/lib/secubox/diagnostics/{name}")
    if not f.exists():
        raise HTTPException(404, "Diagnostic not found")
    return json.loads(f.read_text())


@router.post("/delete_diagnostic")
async def delete_diagnostic(name: str, user=Depends(require_jwt)):
    Path(f"/var/lib/secubox/diagnostics/{name}").unlink(missing_ok=True)
    return {"success": True}


@router.get("/run_diagnostic_test")
async def run_diagnostic_test(test: str, user=Depends(require_jwt)):
    """Exécuter un test de diagnostic."""
    tests = {
        "network": ["ping", "-c", "3", "1.1.1.1"],
        "dns": ["dig", "+short", "google.com"],
        "disk": ["df", "-h"],
    }
    if test not in tests:
        return {"error": f"Unknown test: {test}"}
    r = subprocess.run(tests[test], capture_output=True, text=True, timeout=10)
    return {"test": test, "output": r.stdout, "success": r.returncode == 0}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "system"}


app.include_router(router)
