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
async def alerts():
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
async def dashboard():
    """Données complètes du dashboard (public for demo)."""
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
        "uptime": int(float(Path("/proc/uptime").read_text().split()[0])),
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
async def network_summary():
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
async def system_health():
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


# ── Development Roadmap / Migration Status ───────────────────────

# OpenWRT source modules to port
OPENWRT_MODULES = {
    # Portés et complets
    "luci-app-secubox": {"deb": "secubox-hub", "status": "complete", "category": "core"},
    "luci-app-crowdsec-dashboard": {"deb": "secubox-crowdsec", "status": "complete", "category": "security"},
    "luci-app-wireguard-dashboard": {"deb": "secubox-wireguard", "status": "complete", "category": "security"},
    "luci-app-auth-guardian": {"deb": "secubox-auth", "status": "complete", "category": "security"},
    "luci-app-client-guardian": {"deb": "secubox-nac", "status": "complete", "category": "security"},
    "luci-app-network-modes": {"deb": "secubox-netmodes", "status": "complete", "category": "network"},
    "luci-app-netifyd-dashboard": {"deb": "secubox-dpi", "status": "complete", "category": "network"},
    "luci-app-bandwidth-manager": {"deb": "secubox-qos", "status": "complete", "category": "network"},
    "luci-app-vhost-manager": {"deb": "secubox-vhost", "status": "complete", "category": "network"},
    "luci-app-cdn-cache": {"deb": "secubox-cdn", "status": "complete", "category": "network"},
    "luci-app-haproxy": {"deb": "secubox-haproxy", "status": "complete", "category": "network"},
    "luci-app-netdata-dashboard": {"deb": "secubox-netdata", "status": "complete", "category": "monitoring"},
    "luci-app-media-flow": {"deb": "secubox-mediaflow", "status": "complete", "category": "monitoring"},
    "luci-app-system-hub": {"deb": "secubox-system", "status": "complete", "category": "system"},
    "luci-app-droplet": {"deb": "secubox-droplet", "status": "complete", "category": "publishing"},
    "luci-app-metablogizer": {"deb": "secubox-metablogizer", "status": "complete", "category": "publishing"},
    "luci-app-streamlit": {"deb": "secubox-streamlit", "status": "complete", "category": "apps"},
    "luci-app-streamlit-forge": {"deb": "secubox-streamforge", "status": "complete", "category": "apps"},
    # Nouveaux modules Debian
    "secubox-waf": {"deb": "secubox-waf", "status": "complete", "category": "security", "new": True},
    "secubox-portal": {"deb": "secubox-portal", "status": "complete", "category": "security", "new": True},
    "secubox-dns": {"deb": "secubox-dns", "status": "complete", "category": "network", "new": True},
    "secubox-mail": {"deb": "secubox-mail", "status": "complete", "category": "admin", "new": True},
    "secubox-webmail": {"deb": "secubox-webmail", "status": "complete", "category": "admin", "new": True},
    "secubox-users": {"deb": "secubox-users", "status": "complete", "category": "admin", "new": True},
    "secubox-publish": {"deb": "secubox-publish", "status": "complete", "category": "publishing", "new": True},
    "secubox-mail-lxc": {"deb": "secubox-mail-lxc", "status": "complete", "category": "admin", "new": True},
    "secubox-webmail-lxc": {"deb": "secubox-webmail-lxc", "status": "complete", "category": "admin", "new": True},
    # En cours
    "luci-app-device-intel": {"deb": "secubox-device-intel", "status": "planned", "category": "monitoring"},
    "luci-app-vortex-dns": {"deb": "secubox-vortex-dns", "status": "planned", "category": "network"},
    "luci-app-vortex-firewall": {"deb": "secubox-vortex-firewall", "status": "planned", "category": "security"},
    "luci-app-meshname-dns": {"deb": "secubox-meshname", "status": "planned", "category": "network"},
    "luci-app-secubox-p2p": {"deb": "secubox-p2p", "status": "planned", "category": "network"},
}


@router.get("/roadmap")
async def roadmap():
    """Migration roadmap: OpenWRT → Debian status."""
    complete = []
    in_progress = []
    planned = []
    new_modules = []

    for openwrt, info in OPENWRT_MODULES.items():
        deb = info["deb"]
        sock = Path(f"/run/secubox/{deb.replace('secubox-','')}.sock")
        installed = sock.exists()

        entry = {
            "source": openwrt,
            "target": deb,
            "category": info["category"],
            "status": info["status"],
            "installed": installed,
            "new": info.get("new", False),
        }

        if info.get("new"):
            new_modules.append(entry)
        elif info["status"] == "complete":
            complete.append(entry)
        elif info["status"] == "in_progress":
            in_progress.append(entry)
        else:
            planned.append(entry)

    total = len(OPENWRT_MODULES)
    done = len([m for m in OPENWRT_MODULES.values() if m["status"] == "complete"])

    return {
        "summary": {
            "total": total,
            "complete": done,
            "in_progress": len(in_progress),
            "planned": len(planned),
            "new_debian": len(new_modules),
            "progress_percent": round(done / total * 100) if total else 0,
        },
        "by_category": {
            cat: {
                "total": len([m for m in OPENWRT_MODULES.values() if m["category"] == cat]),
                "complete": len([m for m in OPENWRT_MODULES.values() if m["category"] == cat and m["status"] == "complete"]),
            }
            for cat in ["core", "security", "network", "monitoring", "publishing", "apps", "admin", "system"]
        },
        "complete": complete,
        "in_progress": in_progress,
        "planned": planned,
        "new_modules": new_modules,
    }


# ── Dynamic Menu System ──────────────────────────────────────────

MENU_DIR = Path("/usr/share/secubox/menu.d")

# Default menu definitions (used if menu.d files don't exist)
DEFAULT_MENU = [
    {"id": "hub", "name": "Dashboard", "category": "dashboard", "icon": "🏠", "path": "/", "order": 0},
    {"id": "system", "name": "System Hub", "category": "dashboard", "icon": "🔧", "path": "/system/", "order": 10},
    {"id": "crowdsec", "name": "CrowdSec", "category": "security", "icon": "🛡️", "path": "/crowdsec/", "order": 100},
    {"id": "waf", "name": "WAF", "category": "security", "icon": "🔥", "path": "/waf/", "order": 105},
    {"id": "wireguard", "name": "WireGuard VPN", "category": "security", "icon": "🔐", "path": "/wireguard/", "order": 110},
    {"id": "auth", "name": "Auth Guardian", "category": "security", "icon": "🔑", "path": "/auth/", "order": 120},
    {"id": "nac", "name": "Client Guardian", "category": "security", "icon": "👥", "path": "/nac/", "order": 130},
    {"id": "netmodes", "name": "Network Modes", "category": "network", "icon": "🔀", "path": "/netmodes/", "order": 200},
    {"id": "dpi", "name": "DPI", "category": "network", "icon": "🔍", "path": "/dpi/", "order": 210},
    {"id": "qos", "name": "Bandwidth Manager", "category": "network", "icon": "📶", "path": "/qos/", "order": 220},
    {"id": "vhost", "name": "Virtual Hosts", "category": "network", "icon": "🌍", "path": "/vhost/", "order": 230},
    {"id": "cdn", "name": "CDN Cache", "category": "network", "icon": "💾", "path": "/cdn/", "order": 240},
    {"id": "haproxy", "name": "HAProxy", "category": "network", "icon": "⚖️", "path": "/haproxy/", "order": 250},
    {"id": "dns", "name": "DNS", "category": "network", "icon": "🌐", "path": "/dns/", "order": 260},
    {"id": "netdata", "name": "Netdata", "category": "monitoring", "icon": "📊", "path": "/netdata/", "order": 300},
    {"id": "mediaflow", "name": "Media Flow", "category": "monitoring", "icon": "📺", "path": "/mediaflow/", "order": 310},
    {"id": "droplet", "name": "Droplet", "category": "publishing", "icon": "📤", "path": "/droplet/", "order": 400},
    {"id": "metablogizer", "name": "MetaBlogizer", "category": "publishing", "icon": "📝", "path": "/metablogizer/", "order": 410},
    {"id": "publish", "name": "Publish", "category": "publishing", "icon": "🚀", "path": "/publish/", "order": 420},
    {"id": "streamlit", "name": "Streamlit", "category": "apps", "icon": "🎯", "path": "/streamlit/", "order": 500},
    {"id": "streamforge", "name": "StreamForge", "category": "apps", "icon": "🔨", "path": "/streamforge/", "order": 510},
    {"id": "users", "name": "Users", "category": "admin", "icon": "👤", "path": "/users/", "order": 600},
    {"id": "mail", "name": "Mail Server", "category": "admin", "icon": "📧", "path": "/mail/", "order": 610},
    {"id": "webmail", "name": "Webmail", "category": "admin", "icon": "📬", "path": "/webmail/", "order": 620},
    {"id": "mail-lxc", "name": "Mail LXC", "category": "admin", "icon": "📧", "path": "/mail-lxc/", "order": 630},
    {"id": "webmail-lxc", "name": "Webmail LXC", "category": "admin", "icon": "📬", "path": "/webmail-lxc/", "order": 640},
    {"id": "portal", "name": "Portal", "category": "security", "icon": "🚪", "path": "/portal/", "order": 140},
]

CATEGORY_META = {
    "dashboard": {"name": "Dashboard", "icon": "📊", "order": 0},
    "security": {"name": "Security", "icon": "🛡️", "order": 1},
    "network": {"name": "Network", "icon": "🌐", "order": 2},
    "monitoring": {"name": "Monitoring", "icon": "📈", "order": 3},
    "publishing": {"name": "Publishing", "icon": "📤", "order": 4},
    "apps": {"name": "Applications", "icon": "🎯", "order": 5},
    "admin": {"name": "Administration", "icon": "⚙️", "order": 6},
}


def _load_menu_definitions() -> list:
    """Load menu definitions from menu.d directory or use defaults."""
    import json
    menu_items = []

    if MENU_DIR.exists():
        for f in sorted(MENU_DIR.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                if isinstance(data, list):
                    menu_items.extend(data)
                elif isinstance(data, dict):
                    menu_items.append(data)
            except Exception as e:
                log.warning("Failed to load menu %s: %s", f.name, e)

    # If no menu files found, use defaults
    if not menu_items:
        menu_items = DEFAULT_MENU.copy()

    return menu_items


def _check_module_installed(module_id: str) -> bool:
    """Check if a module is installed by checking for its socket or service."""
    # Check for socket
    sock = Path(f"/run/secubox/{module_id}.sock")
    if sock.exists():
        return True

    # Check for service
    svc_name = f"secubox-{module_id}"
    result = subprocess.run(
        ["systemctl", "list-unit-files", f"{svc_name}.service"],
        capture_output=True, text=True
    )
    return svc_name in result.stdout


def _check_module_active(module_id: str) -> bool:
    """Check if a module's service is active."""
    sock = Path(f"/run/secubox/{module_id}.sock")
    if sock.exists():
        return True

    svc_name = f"secubox-{module_id}"
    result = subprocess.run(
        ["systemctl", "is-active", svc_name],
        capture_output=True, text=True
    )
    return result.stdout.strip() == "active"


@router.get("/menu")
async def menu():
    """
    Dynamic menu endpoint (public).
    Returns categorized menu items for installed modules only.
    """
    menu_items = _load_menu_definitions()

    # Filter to only installed modules and check active status
    installed_items = []
    for item in menu_items:
        module_id = item.get("id", "")

        # Hub is always installed
        if module_id == "hub":
            item["installed"] = True
            item["active"] = True
            installed_items.append(item)
            continue

        # Check if module is installed
        if _check_module_installed(module_id):
            item["installed"] = True
            item["active"] = _check_module_active(module_id)
            installed_items.append(item)

    # Group by category
    categories = {}
    for item in installed_items:
        cat = item.get("category", "other")
        if cat not in categories:
            cat_meta = CATEGORY_META.get(cat, {"name": cat.title(), "icon": "📦", "order": 99})
            categories[cat] = {
                "id": cat,
                "name": cat_meta["name"],
                "icon": cat_meta["icon"],
                "order": cat_meta["order"],
                "items": []
            }
        categories[cat]["items"].append(item)

    # Sort items within each category
    for cat in categories.values():
        cat["items"].sort(key=lambda x: x.get("order", 999))

    # Sort categories by order
    sorted_categories = sorted(categories.values(), key=lambda x: x["order"])

    return {
        "categories": sorted_categories,
        "total_installed": len(installed_items),
        "total_active": sum(1 for i in installed_items if i.get("active")),
    }


app.include_router(router)
