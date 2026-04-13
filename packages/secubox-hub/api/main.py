"""secubox-hub — Dashboard central SecuBox"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_board_info, get_config
from secubox_core.logger import get_logger
from secubox_core.kiosk import (
    detect_board_type, get_board_profile, get_board_capabilities,
    get_interface_classification,
)
import subprocess
import json
import asyncio
import time
from pathlib import Path

app = FastAPI(title="secubox-hub", version="1.6.7.2", root_path="/api/v1/hub")
# Auth router - prefix applied here
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("hub")

# ══════════════════════════════════════════════════════════════════
# Performance Cache — Avoid repeated subprocess calls
# ══════════════════════════════════════════════════════════════════
_cache = {
    "services": {},       # module_id -> {name, active, socket}
    "menu": None,         # Full menu response
    "system_stats": {},   # CPU, memory, disk
    "last_refresh": 0,
}
CACHE_TTL = 5  # seconds - cache valid for 5 seconds

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


def _refresh_services_cache():
    """Refresh all service statuses in one batch (called by background task)."""
    # Get all service statuses in parallel using a single systemctl call
    all_services = list(MODULES.values())
    try:
        # Single call to get all service states
        r = subprocess.run(
            ["systemctl", "is-active", "--"] + all_services,
            capture_output=True, text=True, timeout=5
        )
        states = r.stdout.strip().split("\n")
        for i, svc in enumerate(all_services):
            state = states[i] if i < len(states) else "unknown"
            sock = Path(f"/run/secubox/{svc.replace('secubox-','')}.sock")
            _cache["services"][svc] = {
                "name": svc,
                "active": state == "active",
                "socket": sock.exists()
            }
    except Exception as e:
        log.warning("Cache refresh failed: %s", e)


def _refresh_system_stats():
    """Refresh system stats (CPU, memory, disk)."""
    try:
        import psutil
        _cache["system_stats"] = {
            "cpu_percent": psutil.cpu_percent(interval=None),  # Non-blocking
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
            "load_avg": list(psutil.getloadavg()),
        }
    except Exception as e:
        log.warning("System stats refresh failed: %s", e)


async def _background_cache_refresh():
    """Background task to refresh cache every CACHE_TTL seconds."""
    while True:
        try:
            _refresh_services_cache()
            _refresh_system_stats()
            _cache["last_refresh"] = time.time()
        except Exception as e:
            log.error("Background cache error: %s", e)
        await asyncio.sleep(CACHE_TTL)


@app.on_event("startup")
async def startup():
    """Start background cache refresh task."""
    # Initial sync refresh
    _refresh_services_cache()
    _refresh_system_stats()
    _cache["last_refresh"] = time.time()
    # Start background task
    asyncio.create_task(_background_cache_refresh())


def _svc(name: str) -> dict:
    """Get service status from cache (fast) or direct call (fallback)."""
    if name in _cache["services"] and (time.time() - _cache["last_refresh"]) < CACHE_TTL * 2:
        return _cache["services"][name]
    # Fallback to direct call if cache miss
    r = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=2)
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
    # Use cached stats (non-blocking)
    stats = _cache.get("system_stats", {})
    return {
        "cpu": stats.get("cpu_percent", 0),
        "mem": stats.get("memory_percent", 0),
        "load": stats.get("load_avg", [0, 0, 0])
    }

@router.get("/settings")
async def settings(user=Depends(require_jwt)):
    return get_config()


def _get_build_info() -> dict:
    """Get build metadata from /etc/secubox/build-info.json."""
    build_file = Path("/etc/secubox/build-info.json")
    if build_file.exists():
        try:
            return json.loads(build_file.read_text())
        except Exception:
            pass
    return {"build_timestamp": None, "version": "dev"}


@router.get("/dashboard")
async def dashboard(user=Depends(require_jwt)):
    """Données complètes du dashboard (uses cached stats for speed)."""
    board = get_board_info()
    modules_status = {k: _svc(v) for k, v in MODULES.items()}
    active = sum(1 for m in modules_status.values() if m["active"])
    build_info = _get_build_info()

    # Use cached system stats (non-blocking)
    stats = _cache.get("system_stats", {})

    return {
        "board": board,
        "modules": modules_status,
        "active_modules": active,
        "total_modules": len(MODULES),
        "cpu_percent": stats.get("cpu_percent", 0),
        "memory_percent": stats.get("memory_percent", 0),
        "disk_percent": stats.get("disk_percent", 0),
        "load_avg": stats.get("load_avg", [0, 0, 0]),
        "uptime": int(float(Path("/proc/uptime").read_text().split()[0])),
        "build_info": build_info,
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
        "build_date": "2026-04",
    }


@router.get("/about")
async def about(user=Depends(require_jwt)):
    board = get_board_info()
    return {
        "product": "SecuBox",
        "version": "1.6.7.2",
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
    # Use cached CPU percent (non-blocking)
    stats = _cache.get("system_stats", {})
    return {
        "percent": stats.get("cpu_percent", 0),
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
    """Score de santé système (uses cached stats)."""
    # Use cached stats (non-blocking)
    stats = _cache.get("system_stats", {})
    cpu = stats.get("cpu_percent", 0)
    mem = stats.get("memory_percent", 0)
    disk = stats.get("disk_percent", 0)

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
    return {"status": "ok", "module": "hub", "version": "1.6.7.2"}


# ══════════════════════════════════════════════════════════════════
# Network Mode Selection (integrates with secubox-netmodes)
# ══════════════════════════════════════════════════════════════════

NETMODES_STATE_FILE = Path("/var/lib/secubox/netmodes-state.json")

AVAILABLE_NETWORK_MODES = {
    "router": {
        "name": "Router",
        "desc": "Full NAT router with DHCP, NAC, DPI",
        "icon": "🔀",
        "recommended_for": ["home", "office", "smb"],
    },
    "sniffer-inline": {
        "name": "Inline Sniffer",
        "desc": "Transparent bridge with dual-stream DPI (tc mirred)",
        "icon": "🔍",
        "recommended_for": ["security_audit", "monitoring"],
    },
    "sniffer-passive": {
        "name": "Passive Sniffer",
        "desc": "Out-of-band monitoring via SPAN/TAP port",
        "icon": "👁️",
        "recommended_for": ["readonly_monitoring", "compliance"],
    },
    "access-point": {
        "name": "Access Point",
        "desc": "WiFi AP 802.11r/k/v with band steering",
        "icon": "📡",
        "recommended_for": ["wireless_extension"],
    },
    "relay": {
        "name": "VPN Relay",
        "desc": "Network relay with WireGuard VPN and optimized MTU",
        "icon": "🔗",
        "recommended_for": ["remote_site", "vpn_gateway"],
    },
}


def _get_netmodes_state() -> dict:
    """Read current network mode state."""
    if NETMODES_STATE_FILE.exists():
        try:
            return json.loads(NETMODES_STATE_FILE.read_text())
        except Exception:
            pass
    return {"current_mode": "router", "pending_mode": None, "last_change": None}


@router.get("/network_mode")
async def get_network_mode(user=Depends(require_jwt)):
    """
    Get current network mode and available modes.
    Used by dashboard to display network mode widget.
    """
    state = _get_netmodes_state()
    current_mode = state.get("current_mode", "router")
    mode_info = AVAILABLE_NETWORK_MODES.get(current_mode, {})

    # Get board info for recommendations
    board_type = detect_board_type()
    board_profile = get_board_profile(board_type)
    iface_class = get_interface_classification(board_type)

    return {
        "current_mode": current_mode,
        "mode_name": mode_info.get("name", current_mode),
        "mode_desc": mode_info.get("desc", ""),
        "mode_icon": mode_info.get("icon", "🔀"),
        "pending_mode": state.get("pending_mode"),
        "last_change": state.get("last_change"),
        "board_type": board_type,
        "board_profile": board_profile,
        "interfaces": {
            "wan": iface_class.get("wan", []),
            "lan": iface_class.get("lan", []),
            "sfp": iface_class.get("sfp", []),
        },
        "available_modes": [
            {"id": k, **v} for k, v in AVAILABLE_NETWORK_MODES.items()
        ],
    }


class NetworkModeRequest(BaseModel):
    mode: str
    dry_run: bool = False


@router.post("/network_mode")
async def set_network_mode(req: NetworkModeRequest, user=Depends(require_jwt)):
    """
    Change network mode (requires authentication).
    Proxies to secubox-netmodes API.
    """
    if req.mode not in AVAILABLE_NETWORK_MODES:
        raise HTTPException(400, f"Invalid mode: {req.mode}")

    # Call secubox-netmodes API via socket
    netmodes_sock = Path("/run/secubox/netmodes.sock")
    if not netmodes_sock.exists():
        return {"success": False, "error": "secubox-netmodes not running"}

    try:
        import httpx

        async with httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=str(netmodes_sock))
        ) as client:
            if req.dry_run:
                # Preview changes
                resp = await client.get(
                    f"http://localhost/preview_changes?mode={req.mode}",
                    timeout=30
                )
            else:
                # Apply mode
                resp = await client.post(
                    "http://localhost/apply_mode",
                    json={"mode": req.mode},
                    timeout=60
                )

            if resp.status_code == 200:
                result = resp.json()
                log.info("Network mode change: %s -> %s", req.mode, result.get("success", "unknown"))
                return result
            else:
                return {"success": False, "error": f"API error: {resp.status_code}"}

    except ImportError:
        # Fallback: direct subprocess call to netplan
        log.warning("httpx not available, using fallback")
        return {"success": False, "error": "httpx not installed for socket communication"}
    except Exception as e:
        log.error("network_mode error: %s", e)
        return {"success": False, "error": str(e)}


@router.get("/network_mode/preview")
async def preview_network_mode(mode: str, user=Depends(require_jwt)):
    """Preview what configuration would be applied for a mode."""
    if mode not in AVAILABLE_NETWORK_MODES:
        raise HTTPException(400, f"Invalid mode: {mode}")

    board_type = detect_board_type()
    iface_class = get_interface_classification(board_type)

    wan = iface_class.get("wan", ["eth0"])[0] if iface_class.get("wan") else "eth0"
    lan = iface_class.get("lan", [])
    lan_str = ", ".join(lan) if lan else ""

    # Generate preview YAML based on mode
    if mode == "router":
        yaml_preview = f"""network:
  version: 2
  renderer: networkd

  ethernets:
    {wan}:
      dhcp4: true
      optional: true
"""
        for iface in lan:
            yaml_preview += f"""    {iface}:
      optional: true
"""
        if lan:
            yaml_preview += f"""
  bridges:
    br-lan:
      interfaces: [{lan_str}]
      addresses: [192.168.1.1/24]
      dhcp4: false
"""
    elif mode in ("sniffer-inline", "sniffer-passive"):
        yaml_preview = f"""network:
  version: 2
  renderer: networkd

  ethernets:
    {wan}:
      dhcp4: false
      optional: true
"""
        for iface in lan:
            yaml_preview += f"""    {iface}:
      dhcp4: false
      optional: true
"""
        yaml_preview += f"""
  bridges:
    br0:
      interfaces: [{wan}, {lan_str}]
      dhcp4: true
      parameters:
        stp: false
"""
    else:
        yaml_preview = f"""network:
  version: 2
  renderer: networkd

  ethernets:
    {wan}:
      dhcp4: true
"""

    return {
        "mode": mode,
        "mode_info": AVAILABLE_NETWORK_MODES.get(mode, {}),
        "board_type": board_type,
        "interfaces": iface_class,
        "yaml_preview": yaml_preview,
    }


@router.get("/board_summary")
async def board_summary(user=Depends(require_jwt)):
    """
    Quick board summary for dashboard widgets.
    Uses secubox_core.kiosk functions.
    """
    board_type = detect_board_type()
    profile = get_board_profile(board_type)
    caps = get_board_capabilities(board_type)
    ifaces = get_interface_classification(board_type)

    return {
        "board_type": board_type,
        "profile": profile,
        "capabilities": caps,
        "interfaces": ifaces,
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
    """Check if a module is installed (uses cache for service check)."""
    # Check for socket first (fast)
    sock = Path(f"/run/secubox/{module_id}.sock")
    if sock.exists():
        return True

    # Check cache for service
    svc_name = f"secubox-{module_id}"
    if svc_name in _cache["services"]:
        return True  # If in cache, it was found during refresh

    # Check for www directory (static modules)
    www_path = Path(f"/var/www/secubox/{module_id}")
    if www_path.exists():
        return True

    return False


def _check_module_active(module_id: str) -> bool:
    """Check if a module's service is active (uses cache)."""
    # Check for socket first (fast)
    sock = Path(f"/run/secubox/{module_id}.sock")
    if sock.exists():
        return True

    # Check cache
    svc_name = f"secubox-{module_id}"
    if svc_name in _cache["services"]:
        return _cache["services"][svc_name].get("active", False)

    # Fallback - but this shouldn't be called often
    result = subprocess.run(
        ["systemctl", "is-active", svc_name],
        capture_output=True, text=True
    )
    return result.stdout.strip() == "active"


@router.get("/menu")
async def menu(user=Depends(require_jwt)):
    """
    Dynamic menu endpoint.
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
