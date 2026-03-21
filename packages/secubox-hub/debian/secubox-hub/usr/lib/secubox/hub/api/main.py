"""secubox-hub — Dashboard central SecuBox"""
from fastapi import FastAPI, APIRouter, Depends
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_board_info, get_config
from secubox_core.logger import get_logger
import subprocess
from pathlib import Path

app = FastAPI(title="secubox-hub", version="1.0.0", root_path="/api/v1/hub")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("hub")

MODULES = {
    "crowdsec": "secubox-crowdsec",
    "netdata":  "secubox-netdata",
    "wireguard":"secubox-wireguard",
    "dpi":      "secubox-dpi",
    "netmodes": "secubox-netmodes",
    "nac":      "secubox-nac",
    "qos":      "secubox-qos",
    "vhost":    "secubox-vhost",
    "system":   "secubox-system",
    "auth":     "secubox-auth",
    "mediaflow":"secubox-mediaflow",
    "cdn":      "secubox-cdn",
}

def _svc(name: str) -> dict:
    r = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True)
    sock = Path(f"/run/secubox/{name.replace('secubox-','')}.sock")
    return {"name": name, "active": r.stdout.strip() == "active",
            "socket": sock.exists()}

@router.get("/status")
async def status(user=Depends(require_jwt)):
    board = get_board_info()
    modules_status = {k: _svc(v) for k,v in MODULES.items()}
    active = sum(1 for m in modules_status.values() if m["active"])
    return {**board, "modules": modules_status,
            "active_modules": active, "total_modules": len(MODULES)}

@router.get("/modules")
async def modules(user=Depends(require_jwt)):
    return [{"id": k, **_svc(v)} for k,v in MODULES.items()]

@router.get("/alerts")
async def alerts(user=Depends(require_jwt)):
    alerts_list = []
    for mod, svc in MODULES.items():
        r = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True)
        if r.stdout.strip() != "active":
            alerts_list.append({"type": "service_down", "module": mod,
                                 "service": svc, "severity": "warning"})
    return alerts_list

@router.get("/monitoring")
async def monitoring(user=Depends(require_jwt)):
    import psutil
    return {"cpu": psutil.cpu_percent(0.1),
            "mem": psutil.virtual_memory().percent,
            "load": list(psutil.getloadavg())}

@router.get("/settings")
async def settings(user=Depends(require_jwt)):
    return get_config()


@router.get("/dashboard")
async def dashboard(user=Depends(require_jwt)):
    """Données complètes du dashboard."""
    import psutil
    board = get_board_info()
    modules_status = {k: _svc(v) for k, v in MODULES.items()}
    active = sum(1 for m in modules_status.values() if m["active"])

    return {
        "board": board,
        "modules": modules_status,
        "active_modules": active,
        "total_modules": len(MODULES),
        "cpu_percent": psutil.cpu_percent(0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage("/").percent,
        "load_avg": list(psutil.getloadavg()),
        "uptime": int(Path("/proc/uptime").read_text().split()[0]),
    }


@router.get("/widgets")
async def widgets(user=Depends(require_jwt)):
    """Configuration des widgets dashboard."""
    widgets_file = Path("/var/lib/secubox/widgets.json")
    if widgets_file.exists():
        import json
        return json.loads(widgets_file.read_text())
    return [
        {"id": "system", "type": "system_info", "position": 0, "enabled": True},
        {"id": "modules", "type": "module_status", "position": 1, "enabled": True},
        {"id": "security", "type": "security_alerts", "position": 2, "enabled": True},
        {"id": "network", "type": "network_stats", "position": 3, "enabled": True},
    ]


from pydantic import BaseModel


class WidgetRequest(BaseModel):
    widgets: list[dict]


@router.post("/save_widgets")
async def save_widgets(req: WidgetRequest, user=Depends(require_jwt)):
    import json
    widgets_file = Path("/var/lib/secubox/widgets.json")
    widgets_file.parent.mkdir(parents=True, exist_ok=True)
    widgets_file.write_text(json.dumps(req.widgets, indent=2))
    return {"success": True}


@router.get("/security_summary")
async def security_summary(user=Depends(require_jwt)):
    """Résumé de sécurité."""
    return {
        "crowdsec_alerts": 0,
        "blocked_ips": 0,
        "quarantined_clients": 0,
        "threats_blocked_24h": 0,
        "last_scan": None,
    }


@router.get("/network_summary")
async def network_summary(user=Depends(require_jwt)):
    """Résumé réseau."""
    import json
    r = subprocess.run(["ip", "-j", "link", "show"], capture_output=True, text=True)
    try:
        links = json.loads(r.stdout)
        ifaces = [l for l in links if l.get("ifname") != "lo"]
        up_count = sum(1 for l in ifaces if "UP" in l.get("flags", []))
        return {
            "interfaces": len(ifaces),
            "interfaces_up": up_count,
            "wan_status": "connected",
            "lan_clients": 0,
        }
    except Exception:
        return {"interfaces": 0, "interfaces_up": 0}


@router.get("/quick_actions")
async def quick_actions(user=Depends(require_jwt)):
    """Actions rapides disponibles."""
    return [
        {"id": "restart_services", "label": "Redémarrer les services", "icon": "refresh"},
        {"id": "check_updates", "label": "Vérifier les mises à jour", "icon": "download"},
        {"id": "run_diagnostic", "label": "Diagnostic système", "icon": "search"},
        {"id": "backup_config", "label": "Sauvegarder la config", "icon": "save"},
    ]


class ActionRequest(BaseModel):
    action: str


@router.post("/execute_action")
async def execute_action(req: ActionRequest, user=Depends(require_jwt)):
    if req.action == "restart_services":
        for svc in list(MODULES.values())[:5]:
            subprocess.run(["systemctl", "restart", svc], capture_output=True)
        return {"success": True, "message": "Services redémarrés"}
    elif req.action == "check_updates":
        r = subprocess.run(["apt", "update"], capture_output=True, text=True)
        return {"success": r.returncode == 0}
    elif req.action == "run_diagnostic":
        return {"success": True, "redirect": "/api/v1/system/diagnostics"}
    elif req.action == "backup_config":
        return {"success": True, "redirect": "/api/v1/system/backup"}
    return {"success": False, "error": "Unknown action"}


@router.get("/notifications")
async def notifications(user=Depends(require_jwt)):
    """Notifications système."""
    notifs_file = Path("/var/lib/secubox/notifications.json")
    if notifs_file.exists():
        import json
        return json.loads(notifs_file.read_text())
    return []


@router.post("/dismiss_notification")
async def dismiss_notification(notification_id: str, user=Depends(require_jwt)):
    import json
    notifs_file = Path("/var/lib/secubox/notifications.json")
    if notifs_file.exists():
        notifs = json.loads(notifs_file.read_text())
        notifs = [n for n in notifs if n.get("id") != notification_id]
        notifs_file.write_text(json.dumps(notifs, indent=2))
    return {"success": True}


@router.post("/dismiss_all_notifications")
async def dismiss_all_notifications(user=Depends(require_jwt)):
    notifs_file = Path("/var/lib/secubox/notifications.json")
    notifs_file.write_text("[]") if notifs_file.parent.exists() else None
    return {"success": True}


@router.get("/theme")
async def theme(user=Depends(require_jwt)):
    """Thème de l'interface."""
    import json
    prefs_file = Path("/var/lib/secubox/preferences.json")
    if prefs_file.exists():
        prefs = json.loads(prefs_file.read_text())
        return {"theme": prefs.get("theme", "dark")}
    return {"theme": "dark"}


class ThemeRequest(BaseModel):
    theme: str


@router.post("/set_theme")
async def set_theme(req: ThemeRequest, user=Depends(require_jwt)):
    import json
    prefs_file = Path("/var/lib/secubox/preferences.json")
    prefs_file.parent.mkdir(parents=True, exist_ok=True)
    prefs = {}
    if prefs_file.exists():
        prefs = json.loads(prefs_file.read_text())
    prefs["theme"] = req.theme
    prefs_file.write_text(json.dumps(prefs, indent=2))
    return {"success": True}


@router.get("/version")
async def version(user=Depends(require_jwt)):
    """Version SecuBox."""
    r = subprocess.run(["dpkg", "-l", "secubox-hub"], capture_output=True, text=True)
    version_str = "1.0.0"
    for line in r.stdout.splitlines():
        if "secubox-hub" in line:
            parts = line.split()
            if len(parts) >= 3:
                version_str = parts[2]
    return {
        "version": version_str,
        "codename": "Armada",
        "build_date": "2025-01",
    }


@router.get("/about")
async def about(user=Depends(require_jwt)):
    board = get_board_info()
    return {
        "product": "SecuBox",
        "version": "1.0.0",
        "board": board,
        "project_url": "https://secubox.gondwana.systems",
        "support_email": "support@cybermind.fr",
    }


class ServiceActionRequest(BaseModel):
    module: str
    action: str  # start, stop, restart, enable, disable


@router.post("/module_control")
async def module_control(req: ServiceActionRequest, user=Depends(require_jwt)):
    """Contrôler un module."""
    if req.module not in MODULES:
        return {"success": False, "error": "Module inconnu"}
    svc = MODULES[req.module]
    if req.action not in ("start", "stop", "restart", "enable", "disable"):
        return {"success": False, "error": "Action invalide"}
    r = subprocess.run(["systemctl", req.action, svc], capture_output=True, text=True)
    log.info("module_control: %s %s → %s", req.action, svc, r.returncode == 0)
    return {"success": r.returncode == 0, "output": r.stderr[:200]}


@router.get("/module_status")
async def module_status(module: str, user=Depends(require_jwt)):
    """Statut d'un module."""
    if module not in MODULES:
        return {"error": "Module inconnu"}
    return _svc(MODULES[module])


@router.get("/module_logs")
async def module_logs(module: str, lines: int = 50, user=Depends(require_jwt)):
    """Logs d'un module."""
    if module not in MODULES:
        return {"error": "Module inconnu"}
    r = subprocess.run(
        ["journalctl", "-u", MODULES[module], "-n", str(lines), "--no-pager"],
        capture_output=True, text=True, timeout=10
    )
    return {"lines": r.stdout.splitlines()}


@router.get("/uptime")
async def uptime(user=Depends(require_jwt)):
    """Uptime système."""
    uptime_sec = int(float(Path("/proc/uptime").read_text().split()[0]))
    days = uptime_sec // 86400
    hours = (uptime_sec % 86400) // 3600
    mins = (uptime_sec % 3600) // 60
    return {
        "seconds": uptime_sec,
        "days": days,
        "hours": hours,
        "minutes": mins,
        "formatted": f"{days}d {hours}h {mins}m",
    }


@router.get("/cpu")
async def cpu(user=Depends(require_jwt)):
    import psutil
    return {
        "percent": psutil.cpu_percent(0.5),
        "count": psutil.cpu_count(),
        "freq_mhz": psutil.cpu_freq().current if psutil.cpu_freq() else 0,
    }


@router.get("/memory")
async def memory(user=Depends(require_jwt)):
    import psutil
    mem = psutil.virtual_memory()
    return {
        "total_mb": mem.total // 1024 // 1024,
        "used_mb": mem.used // 1024 // 1024,
        "available_mb": mem.available // 1024 // 1024,
        "percent": mem.percent,
    }


@router.get("/disk")
async def disk(user=Depends(require_jwt)):
    import psutil
    d = psutil.disk_usage("/")
    return {
        "total_gb": d.total // 1024**3,
        "used_gb": d.used // 1024**3,
        "free_gb": d.free // 1024**3,
        "percent": d.percent,
    }


@router.get("/network_stats")
async def network_stats(user=Depends(require_jwt)):
    import psutil
    counters = psutil.net_io_counters()
    return {
        "bytes_sent": counters.bytes_sent,
        "bytes_recv": counters.bytes_recv,
        "packets_sent": counters.packets_sent,
        "packets_recv": counters.packets_recv,
    }


@router.get("/recent_events")
async def recent_events(user=Depends(require_jwt)):
    """Événements récents."""
    return []


@router.get("/system_health")
async def system_health(user=Depends(require_jwt)):
    """Score de santé système."""
    import psutil
    cpu = psutil.cpu_percent(0.1)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent

    modules_status = [_svc(v) for v in MODULES.values()]
    active = sum(1 for m in modules_status if m["active"])
    module_health = (active / len(MODULES)) * 100

    resource_health = 100 - max(cpu, mem, disk) / 2
    overall = int((module_health + resource_health) / 2)

    return {
        "overall": overall,
        "module_health": int(module_health),
        "resource_health": int(resource_health),
        "issues": [m["name"] for m in modules_status if not m["active"]],
    }


@router.get("/preferences")
async def preferences(user=Depends(require_jwt)):
    import json
    prefs_file = Path("/var/lib/secubox/preferences.json")
    if prefs_file.exists():
        return json.loads(prefs_file.read_text())
    return {"theme": "dark", "language": "fr", "notifications": True}


class PreferencesRequest(BaseModel):
    theme: str = "dark"
    language: str = "fr"
    notifications: bool = True


@router.post("/save_preferences")
async def save_preferences(req: PreferencesRequest, user=Depends(require_jwt)):
    import json
    prefs_file = Path("/var/lib/secubox/preferences.json")
    prefs_file.parent.mkdir(parents=True, exist_ok=True)
    prefs_file.write_text(json.dumps(req.model_dump(), indent=2))
    return {"success": True}


@router.get("/logs")
async def logs(lines: int = 100, user=Depends(require_jwt)):
    """Logs système."""
    r = subprocess.run(
        ["journalctl", "-n", str(lines), "--no-pager", "-o", "short"],
        capture_output=True, text=True, timeout=10
    )
    return {"lines": r.stdout.splitlines()}


@router.get("/check_updates")
async def check_updates(user=Depends(require_jwt)):
    """Vérifier les mises à jour."""
    subprocess.run(["apt", "update"], capture_output=True)
    r = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)
    updates = []
    for line in r.stdout.splitlines()[1:]:
        if line.strip():
            updates.append(line.split("/")[0])
    return {"updates_available": len(updates), "packages": updates[:20]}


@router.post("/apply_updates")
async def apply_updates(user=Depends(require_jwt)):
    """Appliquer les mises à jour."""
    log.warning("System update requested")
    return {"success": True, "message": "Run 'apt upgrade' manually for safety"}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "hub"}


app.include_router(router)
