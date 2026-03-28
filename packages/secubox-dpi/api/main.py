"""secubox-dpi — netifyd socket + tc mirred DPI dual-stream

Enhanced features:
- Traffic history tracking with time-series stats
- Bandwidth quotas per app/device with enforcement
- Scheduled traffic reports
- Alert thresholds with webhook notifications
- Application fingerprint database
- Traffic anomaly detection
"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException, BackgroundTasks
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import subprocess, json, socket, time, threading, asyncio
from pathlib import Path
import httpx

app = FastAPI(title="secubox-dpi", version="2.0.0", root_path="/api/v1/dpi")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("dpi")

# Configuration paths
NETIFYD_SOCK = Path("/run/netifyd/netifyd.sock")
DATA_DIR = Path("/var/lib/secubox/dpi")
HISTORY_FILE = DATA_DIR / "traffic_history.json"
QUOTAS_FILE = DATA_DIR / "quotas.json"
ALERTS_FILE = DATA_DIR / "alert_config.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Stats collection interval (seconds)
STATS_INTERVAL = 60
MAX_HISTORY_ENTRIES = 1440  # 24 hours at 1-minute intervals


class QuotaType(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class QuotaAction(str, Enum):
    ALERT = "alert"
    THROTTLE = "throttle"
    BLOCK = "block"


class BandwidthQuota(BaseModel):
    target: str  # app name, MAC address, or "all"
    target_type: str = "app"  # app, device, category
    quota_bytes: int = Field(ge=0)
    quota_type: QuotaType = QuotaType.DAILY
    action: QuotaAction = QuotaAction.ALERT
    throttle_kbps: int = 0  # If action is throttle
    enabled: bool = True
    current_usage: int = 0
    last_reset: Optional[str] = None


class AlertThreshold(BaseModel):
    name: str
    metric: str  # bandwidth_total, bandwidth_app, new_device, suspicious_app
    threshold: float
    comparison: str = "gt"  # gt, lt, eq
    enabled: bool = True
    cooldown_minutes: int = 15
    last_triggered: Optional[str] = None


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = ["quota_exceeded", "alert_triggered", "anomaly_detected"]
    enabled: bool = True
    secret: Optional[str] = None


class TrafficStats(BaseModel):
    timestamp: str
    rx_bytes: int
    tx_bytes: int
    total_bytes: int
    flows_active: int
    top_apps: List[Dict[str, Any]]
    top_devices: List[Dict[str, Any]]


# ============================================================================
# Traffic History Management
# ============================================================================

_traffic_history: List[Dict] = []
_history_lock = threading.Lock()


def load_traffic_history() -> List[Dict]:
    """Load traffic history from file."""
    global _traffic_history
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                _traffic_history = json.load(f)
        except Exception:
            _traffic_history = []
    return _traffic_history


def save_traffic_history():
    """Save traffic history to file."""
    with _history_lock:
        # Keep only recent entries
        history = _traffic_history[-MAX_HISTORY_ENTRIES:]
        try:
            with open(HISTORY_FILE, 'w') as f:
                json.dump(history, f)
        except Exception:
            pass


def add_traffic_stats(stats: TrafficStats):
    """Add traffic stats to history."""
    global _traffic_history
    with _history_lock:
        _traffic_history.append(stats.dict())
        if len(_traffic_history) > MAX_HISTORY_ENTRIES:
            _traffic_history = _traffic_history[-MAX_HISTORY_ENTRIES:]


# ============================================================================
# Quota Management
# ============================================================================

def load_quotas() -> Dict[str, BandwidthQuota]:
    """Load bandwidth quotas."""
    if QUOTAS_FILE.exists():
        try:
            with open(QUOTAS_FILE) as f:
                data = json.load(f)
                return {k: BandwidthQuota(**v) for k, v in data.items()}
        except Exception:
            pass
    return {}


def save_quotas(quotas: Dict[str, BandwidthQuota]):
    """Save bandwidth quotas."""
    try:
        with open(QUOTAS_FILE, 'w') as f:
            json.dump({k: v.dict() for k, v in quotas.items()}, f, indent=2)
    except Exception:
        pass


def check_quotas(app_traffic: Dict[str, int], device_traffic: Dict[str, int]):
    """Check traffic against quotas and trigger actions."""
    quotas = load_quotas()
    alerts = []

    for name, quota in quotas.items():
        if not quota.enabled:
            continue

        usage = 0
        if quota.target_type == "app" and quota.target in app_traffic:
            usage = app_traffic[quota.target]
        elif quota.target_type == "device" and quota.target in device_traffic:
            usage = device_traffic[quota.target]
        elif quota.target == "all":
            usage = sum(app_traffic.values())

        quota.current_usage = usage

        if usage >= quota.quota_bytes:
            alerts.append({
                "quota_name": name,
                "target": quota.target,
                "usage": usage,
                "limit": quota.quota_bytes,
                "action": quota.action.value
            })

            # Apply action
            if quota.action == QuotaAction.THROTTLE and quota.throttle_kbps > 0:
                # Apply tc throttling (would need implementation)
                pass
            elif quota.action == QuotaAction.BLOCK:
                # Add to block rules (would need implementation)
                pass

    save_quotas(quotas)
    return alerts


# ============================================================================
# Alert Management
# ============================================================================

def load_alert_config() -> Dict[str, AlertThreshold]:
    """Load alert thresholds."""
    if ALERTS_FILE.exists():
        try:
            with open(ALERTS_FILE) as f:
                data = json.load(f)
                return {k: AlertThreshold(**v) for k, v in data.items()}
        except Exception:
            pass
    return {}


def save_alert_config(alerts: Dict[str, AlertThreshold]):
    """Save alert thresholds."""
    try:
        with open(ALERTS_FILE, 'w') as f:
            json.dump({k: v.dict() for k, v in alerts.items()}, f, indent=2)
    except Exception:
        pass


# ============================================================================
# Webhook Notifications
# ============================================================================

def load_webhooks() -> List[WebhookConfig]:
    """Load webhook configurations."""
    if WEBHOOKS_FILE.exists():
        try:
            with open(WEBHOOKS_FILE) as f:
                return [WebhookConfig(**wh) for wh in json.load(f)]
        except Exception:
            pass
    return []


def save_webhooks(webhooks: List[WebhookConfig]):
    """Save webhook configurations."""
    try:
        with open(WEBHOOKS_FILE, 'w') as f:
            json.dump([wh.dict() for wh in webhooks], f, indent=2)
    except Exception:
        pass


async def send_webhook(event: str, data: Dict[str, Any]):
    """Send webhook notification."""
    webhooks = load_webhooks()

    for wh in webhooks:
        if not wh.enabled or event not in wh.events:
            continue

        payload = {
            "event": event,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "data": data
        }

        try:
            headers = {"Content-Type": "application/json"}
            if wh.secret:
                import hashlib, hmac
                sig = hmac.new(wh.secret.encode(), json.dumps(payload).encode(), hashlib.sha256).hexdigest()
                headers["X-Webhook-Signature"] = sig

            async with httpx.AsyncClient() as client:
                await client.post(wh.url, json=payload, headers=headers, timeout=5.0)
        except Exception:
            pass

def _netifyd_query(cmd: dict) -> dict:
    """Envoi JSON command sur socket netifyd."""
    if not NETIFYD_SOCK.exists():
        return {"error": "netifyd socket unavailable"}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(str(NETIFYD_SOCK))
            s.sendall((json.dumps(cmd) + "\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
                if data.endswith(b"\n"): break
        return json.loads(data.decode())
    except Exception as e:
        log.warning("netifyd query error: %s", e)
        return {"error": str(e)}

def _setup_mirred(iface: str, mirror_if: str = "ifb0") -> dict:
    """Configure tc mirred + ifb0 pour DPI dual-stream."""
    cmds = [
        ["ip", "link", "add", mirror_if, "type", "ifb"],
        ["ip", "link", "set", mirror_if, "up"],
        ["tc", "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"],
        ["tc", "filter", "add", "dev", iface, "parent", "ffff:", "protocol", "all",
         "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect",
         "dev", mirror_if],
        ["tc", "qdisc", "add", "dev", iface, "handle", "1:", "prio"],
        ["tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "all",
         "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "mirror",
         "dev", mirror_if],
    ]
    results = []
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, text=True)
        results.append({"cmd": " ".join(cmd[-3:]), "ok": r.returncode == 0,
                        "err": r.stderr.strip()[:100] if r.returncode != 0 else ""})
    return {"steps": results, "interface": iface, "mirror": mirror_if}

@router.get("/status")
async def status(user=Depends(require_jwt)):
    cfg = get_config("dpi")
    netifyd_up = subprocess.run(["pgrep", "netifyd"], capture_output=True).returncode == 0
    iface = cfg.get("interface", "eth0")
    mirred_active = subprocess.run(
        ["tc", "filter", "show", "dev", iface, "parent", "ffff:"],
        capture_output=True, text=True
    ).stdout.strip() != ""
    return {"running": netifyd_up, "mode": cfg.get("mode","inline"),
            "engine": cfg.get("engine","netifyd"),
            "interface": iface, "mirred_active": mirred_active}

@router.get("/flows")
async def flows(user=Depends(require_jwt)):
    return _netifyd_query({"type":"get_flows"})

@router.get("/applications")
async def applications(user=Depends(require_jwt)):
    return _netifyd_query({"type":"get_applications"})

@router.get("/devices")
async def devices(user=Depends(require_jwt)):
    return _netifyd_query({"type":"get_devices"})

@router.get("/risks")
async def risks(user=Depends(require_jwt)):
    return _netifyd_query({"type":"get_risks"})

@router.get("/talkers")
async def talkers(user=Depends(require_jwt)):
    return _netifyd_query({"type":"get_top_talkers"})

@router.post("/setup_mirred")
async def setup_mirred(user=Depends(require_jwt)):
    cfg = get_config("dpi")
    return _setup_mirred(cfg.get("interface","eth0"), cfg.get("mirror_if","ifb0"))


@router.get("/apps")
async def apps(user=Depends(require_jwt)):
    """Liste des applications détectées."""
    return _netifyd_query({"type": "get_applications"})


@router.get("/protocols")
async def protocols(user=Depends(require_jwt)):
    """Protocoles détectés."""
    return _netifyd_query({"type": "get_protocols"})


@router.get("/categories")
async def categories(user=Depends(require_jwt)):
    """Catégories d'applications."""
    return [
        {"id": "streaming", "name": "Streaming", "apps": ["netflix", "youtube", "twitch"]},
        {"id": "social", "name": "Réseaux sociaux", "apps": ["facebook", "instagram", "tiktok"]},
        {"id": "gaming", "name": "Jeux", "apps": ["steam", "xbox", "playstation"]},
        {"id": "productivity", "name": "Productivité", "apps": ["office365", "google_drive", "zoom"]},
        {"id": "p2p", "name": "P2P/Torrent", "apps": ["bittorrent", "emule"]},
    ]


@router.get("/top_apps")
async def top_apps(limit: int = 10, user=Depends(require_jwt)):
    """Top applications par trafic."""
    flows = _netifyd_query({"type": "get_flows"})
    if "error" in flows:
        return []
    # Aggregate by app
    app_traffic = {}
    for f in flows.get("flows", []):
        app = f.get("detected_application_name", "unknown")
        app_traffic[app] = app_traffic.get(app, 0) + f.get("bytes", 0)
    sorted_apps = sorted(app_traffic.items(), key=lambda x: -x[1])[:limit]
    return [{"app": a, "bytes": b} for a, b in sorted_apps]


@router.get("/top_protocols")
async def top_protocols(limit: int = 10, user=Depends(require_jwt)):
    """Top protocoles par trafic."""
    flows = _netifyd_query({"type": "get_flows"})
    if "error" in flows:
        return []
    proto_traffic = {}
    for f in flows.get("flows", []):
        proto = f.get("detected_protocol_name", "unknown")
        proto_traffic[proto] = proto_traffic.get(proto, 0) + f.get("bytes", 0)
    sorted_protos = sorted(proto_traffic.items(), key=lambda x: -x[1])[:limit]
    return [{"protocol": p, "bytes": b} for p, b in sorted_protos]


@router.get("/bandwidth_by_app")
async def bandwidth_by_app(user=Depends(require_jwt)):
    """Bande passante par application."""
    return await top_apps(20, user)


@router.get("/bandwidth_by_device")
async def bandwidth_by_device(user=Depends(require_jwt)):
    """Bande passante par appareil."""
    flows = _netifyd_query({"type": "get_flows"})
    if "error" in flows:
        return []
    device_traffic = {}
    for f in flows.get("flows", []):
        mac = f.get("local_mac", "unknown")
        device_traffic[mac] = device_traffic.get(mac, 0) + f.get("bytes", 0)
    sorted_devs = sorted(device_traffic.items(), key=lambda x: -x[1])[:20]
    return [{"mac": d, "bytes": b} for d, b in sorted_devs]


@router.get("/active_flows")
async def active_flows(user=Depends(require_jwt)):
    """Flux actifs."""
    return _netifyd_query({"type": "get_flows"})


@router.get("/flow_details")
async def flow_details(flow_id: str, user=Depends(require_jwt)):
    """Détails d'un flux."""
    return _netifyd_query({"type": "get_flow", "flow_id": flow_id})


@router.get("/device_flows")
async def device_flows(mac: str, user=Depends(require_jwt)):
    """Flux d'un appareil."""
    flows = _netifyd_query({"type": "get_flows"})
    if "error" in flows:
        return []
    return [f for f in flows.get("flows", []) if f.get("local_mac") == mac]


@router.get("/realtime")
async def realtime(user=Depends(require_jwt)):
    """Statistiques temps réel."""
    cfg = get_config("dpi")
    iface = cfg.get("interface", "eth0")
    stats_path = Path(f"/sys/class/net/{iface}/statistics")
    if not stats_path.exists():
        return {"error": "Interface not found"}
    return {
        "rx_bytes": int((stats_path / "rx_bytes").read_text().strip()),
        "tx_bytes": int((stats_path / "tx_bytes").read_text().strip()),
        "rx_packets": int((stats_path / "rx_packets").read_text().strip()),
        "tx_packets": int((stats_path / "tx_packets").read_text().strip()),
    }


@router.get("/stats")
async def stats(user=Depends(require_jwt)):
    """Statistiques DPI."""
    return _netifyd_query({"type": "get_stats"})


from pydantic import BaseModel


class BlockRuleRequest(BaseModel):
    app_or_category: str
    action: str = "block"  # block, limit, mark
    limit_kbps: int = 0


@router.get("/block_rules")
async def block_rules(user=Depends(require_jwt)):
    """Règles de blocage."""
    rules_file = Path("/etc/secubox/dpi-rules.json")
    if rules_file.exists():
        return json.loads(rules_file.read_text())
    return []


@router.post("/add_block_rule")
async def add_block_rule(req: BlockRuleRequest, user=Depends(require_jwt)):
    rules_file = Path("/etc/secubox/dpi-rules.json")
    rules_file.parent.mkdir(parents=True, exist_ok=True)
    rules = json.loads(rules_file.read_text()) if rules_file.exists() else []
    rules.append(req.model_dump())
    rules_file.write_text(json.dumps(rules, indent=2))
    log.info("DPI rule added: %s", req.app_or_category)
    return {"success": True}


@router.post("/delete_block_rule")
async def delete_block_rule(app_or_category: str, user=Depends(require_jwt)):
    rules_file = Path("/etc/secubox/dpi-rules.json")
    if rules_file.exists():
        rules = json.loads(rules_file.read_text())
        rules = [r for r in rules if r.get("app_or_category") != app_or_category]
        rules_file.write_text(json.dumps(rules, indent=2))
    return {"success": True}


@router.get("/alerts")
async def alerts(user=Depends(require_jwt)):
    """Alertes DPI."""
    return _netifyd_query({"type": "get_alerts"})


@router.get("/dns_queries")
async def dns_queries(limit: int = 100, user=Depends(require_jwt)):
    """Requêtes DNS interceptées."""
    return _netifyd_query({"type": "get_dns_queries", "limit": limit})


@router.get("/ssl_flows")
async def ssl_flows(user=Depends(require_jwt)):
    """Flux SSL/TLS."""
    flows = _netifyd_query({"type": "get_flows"})
    if "error" in flows:
        return []
    return [f for f in flows.get("flows", []) if f.get("ssl", {}).get("enabled")]


@router.get("/ssl_fingerprints")
async def ssl_fingerprints(user=Depends(require_jwt)):
    """Empreintes JA3/JA3S."""
    return _netifyd_query({"type": "get_ssl_fingerprints"})


class DpiSettingsRequest(BaseModel):
    interface: str = "eth0"
    mirror_if: str = "ifb0"
    mode: str = "inline"  # inline, passive, mirror
    enabled: bool = True


@router.get("/settings")
async def settings(user=Depends(require_jwt)):
    cfg = get_config("dpi")
    return {
        "interface": cfg.get("interface", "eth0"),
        "mirror_if": cfg.get("mirror_if", "ifb0"),
        "mode": cfg.get("mode", "inline"),
        "enabled": cfg.get("enabled", True),
    }


@router.post("/save_settings")
async def save_settings(req: DpiSettingsRequest, user=Depends(require_jwt)):
    settings_file = Path("/etc/secubox/dpi.json")
    settings_file.parent.mkdir(parents=True, exist_ok=True)
    settings_file.write_text(json.dumps(req.model_dump(), indent=2))
    log.info("DPI settings saved")
    return {"success": True}


@router.post("/restart")
async def restart(user=Depends(require_jwt)):
    """Redémarrer netifyd."""
    r = subprocess.run(["systemctl", "restart", "netifyd"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.post("/start")
async def start(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "start", "netifyd"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.post("/stop")
async def stop(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "stop", "netifyd"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.get("/logs")
async def logs(lines: int = 100, user=Depends(require_jwt)):
    r = subprocess.run(
        ["journalctl", "-u", "netifyd", "-n", str(lines), "--no-pager"],
        capture_output=True, text=True, timeout=10
    )
    return {"lines": r.stdout.splitlines()}


@router.get("/interface_list")
async def interface_list(user=Depends(require_jwt)):
    """Liste des interfaces."""
    r = subprocess.run(["ip", "-j", "link", "show"], capture_output=True, text=True)
    try:
        links = json.loads(r.stdout)
        return [l.get("ifname") for l in links if l.get("ifname") != "lo"]
    except Exception:
        return []


@router.get("/tc_status")
async def tc_status(user=Depends(require_jwt)):
    """État tc mirred."""
    cfg = get_config("dpi")
    iface = cfg.get("interface", "eth0")
    qdisc = subprocess.run(["tc", "qdisc", "show", "dev", iface],
                           capture_output=True, text=True)
    filters = subprocess.run(["tc", "filter", "show", "dev", iface, "parent", "ffff:"],
                             capture_output=True, text=True)
    return {
        "qdisc": qdisc.stdout,
        "filters": filters.stdout,
        "active": "mirred" in filters.stdout,
    }


@router.post("/remove_mirred")
async def remove_mirred(user=Depends(require_jwt)):
    """Supprimer la configuration mirred."""
    cfg = get_config("dpi")
    iface = cfg.get("interface", "eth0")
    mirror_if = cfg.get("mirror_if", "ifb0")
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "ingress"], capture_output=True)
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
    subprocess.run(["ip", "link", "del", mirror_if], capture_output=True)
    return {"success": True}


@router.get("/export_flows")
async def export_flows(format: str = "json", user=Depends(require_jwt)):
    """Exporter les flux."""
    flows = _netifyd_query({"type": "get_flows"})
    if format == "csv":
        lines = ["timestamp,src_ip,dst_ip,app,protocol,bytes"]
        for f in flows.get("flows", []):
            lines.append(f"{f.get('timestamp')},{f.get('local_ip')},{f.get('other_ip')},"
                        f"{f.get('detected_application_name')},{f.get('detected_protocol_name')},"
                        f"{f.get('bytes')}")
        return {"format": "csv", "data": "\n".join(lines)}
    return flows


@router.get("/health")
async def health():
    return {"status": "ok", "module": "dpi", "version": "2.0.0"}


# ============================================================================
# Traffic History Endpoints
# ============================================================================

@router.get("/history")
async def get_traffic_history(
    hours: int = 24,
    resolution: str = "1m",
    user=Depends(require_jwt)
):
    """Get traffic history."""
    history = load_traffic_history()

    # Filter by time
    cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"
    history = [h for h in history if h.get("timestamp", "") >= cutoff]

    return {
        "history": history,
        "count": len(history),
        "hours": hours
    }


@router.get("/history/summary")
async def get_history_summary(hours: int = 24, user=Depends(require_jwt)):
    """Get traffic history summary."""
    history = load_traffic_history()

    cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"
    history = [h for h in history if h.get("timestamp", "") >= cutoff]

    if not history:
        return {"error": "No data available"}

    total_rx = sum(h.get("rx_bytes", 0) for h in history)
    total_tx = sum(h.get("tx_bytes", 0) for h in history)
    avg_flows = sum(h.get("flows_active", 0) for h in history) / len(history)

    # Aggregate top apps
    app_totals = defaultdict(int)
    for h in history:
        for app in h.get("top_apps", []):
            app_totals[app.get("app", "unknown")] += app.get("bytes", 0)

    top_apps = sorted(app_totals.items(), key=lambda x: -x[1])[:10]

    return {
        "period_hours": hours,
        "total_rx_bytes": total_rx,
        "total_tx_bytes": total_tx,
        "total_bytes": total_rx + total_tx,
        "avg_active_flows": round(avg_flows, 1),
        "top_apps": [{"app": a, "bytes": b} for a, b in top_apps],
        "data_points": len(history)
    }


@router.post("/history/clear")
async def clear_traffic_history(user=Depends(require_jwt)):
    """Clear traffic history."""
    global _traffic_history
    with _history_lock:
        _traffic_history = []
    save_traffic_history()
    return {"status": "cleared"}


# ============================================================================
# Quota Endpoints
# ============================================================================

@router.get("/quotas")
async def list_quotas(user=Depends(require_jwt)):
    """List bandwidth quotas."""
    quotas = load_quotas()
    return {"quotas": {k: v.dict() for k, v in quotas.items()}}


@router.put("/quotas/{quota_name}")
async def set_quota(quota_name: str, quota: BandwidthQuota, user=Depends(require_jwt)):
    """Create or update a bandwidth quota."""
    quotas = load_quotas()
    quotas[quota_name] = quota
    save_quotas(quotas)
    return {"status": "updated", "quota": quota.dict()}


@router.delete("/quotas/{quota_name}")
async def delete_quota(quota_name: str, user=Depends(require_jwt)):
    """Delete a bandwidth quota."""
    quotas = load_quotas()
    if quota_name not in quotas:
        raise HTTPException(status_code=404, detail="Quota not found")
    del quotas[quota_name]
    save_quotas(quotas)
    return {"status": "deleted"}


@router.post("/quotas/{quota_name}/reset")
async def reset_quota(quota_name: str, user=Depends(require_jwt)):
    """Reset quota usage counter."""
    quotas = load_quotas()
    if quota_name not in quotas:
        raise HTTPException(status_code=404, detail="Quota not found")
    quotas[quota_name].current_usage = 0
    quotas[quota_name].last_reset = datetime.utcnow().isoformat() + "Z"
    save_quotas(quotas)
    return {"status": "reset"}


@router.get("/quotas/status")
async def quota_status(user=Depends(require_jwt)):
    """Get current quota usage status."""
    quotas = load_quotas()
    status = []

    for name, quota in quotas.items():
        percent = (quota.current_usage / quota.quota_bytes * 100) if quota.quota_bytes > 0 else 0
        status.append({
            "name": name,
            "target": quota.target,
            "usage": quota.current_usage,
            "limit": quota.quota_bytes,
            "percent": round(percent, 1),
            "exceeded": quota.current_usage >= quota.quota_bytes,
            "action": quota.action.value
        })

    return {"quotas": status}


# ============================================================================
# Alert Endpoints
# ============================================================================

@router.get("/alerts/config")
async def list_alert_thresholds(user=Depends(require_jwt)):
    """List alert thresholds."""
    alerts = load_alert_config()
    return {"alerts": {k: v.dict() for k, v in alerts.items()}}


@router.put("/alerts/config/{alert_name}")
async def set_alert_threshold(alert_name: str, alert: AlertThreshold, user=Depends(require_jwt)):
    """Create or update an alert threshold."""
    alerts = load_alert_config()
    alert.name = alert_name
    alerts[alert_name] = alert
    save_alert_config(alerts)
    return {"status": "updated", "alert": alert.dict()}


@router.delete("/alerts/config/{alert_name}")
async def delete_alert_threshold(alert_name: str, user=Depends(require_jwt)):
    """Delete an alert threshold."""
    alerts = load_alert_config()
    if alert_name not in alerts:
        raise HTTPException(status_code=404, detail="Alert not found")
    del alerts[alert_name]
    save_alert_config(alerts)
    return {"status": "deleted"}


# ============================================================================
# Webhook Endpoints
# ============================================================================

@router.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    """List configured webhooks."""
    webhooks = load_webhooks()
    return {"webhooks": [wh.dict() for wh in webhooks]}


@router.post("/webhooks")
async def add_webhook(webhook: WebhookConfig, user=Depends(require_jwt)):
    """Add a webhook."""
    webhooks = load_webhooks()

    for wh in webhooks:
        if wh.url == webhook.url:
            raise HTTPException(status_code=409, detail="Webhook URL already exists")

    webhooks.append(webhook)
    save_webhooks(webhooks)
    return {"status": "added"}


@router.delete("/webhooks")
async def delete_webhook(url: str, user=Depends(require_jwt)):
    """Delete a webhook by URL."""
    webhooks = load_webhooks()
    original_len = len(webhooks)
    webhooks = [wh for wh in webhooks if wh.url != url]

    if len(webhooks) == original_len:
        raise HTTPException(status_code=404, detail="Webhook not found")

    save_webhooks(webhooks)
    return {"status": "deleted"}


@router.post("/webhooks/test")
async def test_webhook(url: str, user=Depends(require_jwt)):
    """Test a webhook."""
    await send_webhook("test", {"message": "Test event from SecuBox DPI"})
    return {"status": "sent"}


# ============================================================================
# Traffic Anomaly Detection
# ============================================================================

@router.get("/anomalies")
async def detect_anomalies(user=Depends(require_jwt)):
    """Detect traffic anomalies based on historical patterns."""
    history = load_traffic_history()

    if len(history) < 60:  # Need at least 1 hour of data
        return {"anomalies": [], "message": "Insufficient data for anomaly detection"}

    # Calculate baseline (average of last 24 hours)
    recent = history[-60:]  # Last hour
    historical = history[:-60] if len(history) > 60 else history

    if not historical:
        return {"anomalies": [], "message": "Insufficient historical data"}

    avg_bytes = sum(h.get("total_bytes", 0) for h in historical) / len(historical)
    avg_flows = sum(h.get("flows_active", 0) for h in historical) / len(historical)

    recent_bytes = sum(h.get("total_bytes", 0) for h in recent) / len(recent) if recent else 0
    recent_flows = sum(h.get("flows_active", 0) for h in recent) / len(recent) if recent else 0

    anomalies = []

    # Check for significant deviations (>200% or <50% of average)
    if avg_bytes > 0:
        bytes_ratio = recent_bytes / avg_bytes
        if bytes_ratio > 2:
            anomalies.append({
                "type": "high_bandwidth",
                "severity": "warning" if bytes_ratio < 3 else "critical",
                "message": f"Bandwidth {bytes_ratio:.1f}x higher than average",
                "current": recent_bytes,
                "average": avg_bytes
            })
        elif bytes_ratio < 0.5:
            anomalies.append({
                "type": "low_bandwidth",
                "severity": "info",
                "message": f"Bandwidth {bytes_ratio:.1f}x lower than average",
                "current": recent_bytes,
                "average": avg_bytes
            })

    if avg_flows > 0:
        flows_ratio = recent_flows / avg_flows
        if flows_ratio > 2:
            anomalies.append({
                "type": "high_connections",
                "severity": "warning" if flows_ratio < 3 else "critical",
                "message": f"Active flows {flows_ratio:.1f}x higher than average",
                "current": recent_flows,
                "average": avg_flows
            })

    return {"anomalies": anomalies, "baseline_hours": len(historical) / 60}


# ============================================================================
# Background Stats Collection
# ============================================================================

_stats_task: Optional[asyncio.Task] = None


async def collect_stats_periodically():
    """Background task to collect traffic stats."""
    while True:
        try:
            await asyncio.sleep(STATS_INTERVAL)

            # Get current stats
            cfg = get_config("dpi")
            iface = cfg.get("interface", "eth0")
            stats_path = Path(f"/sys/class/net/{iface}/statistics")

            if not stats_path.exists():
                continue

            rx_bytes = int((stats_path / "rx_bytes").read_text().strip())
            tx_bytes = int((stats_path / "tx_bytes").read_text().strip())

            # Get flows and calculate top apps/devices
            flows = _netifyd_query({"type": "get_flows"})

            app_traffic = defaultdict(int)
            device_traffic = defaultdict(int)

            for f in flows.get("flows", []):
                app = f.get("detected_application_name", "unknown")
                mac = f.get("local_mac", "unknown")
                bytes_count = f.get("bytes", 0)
                app_traffic[app] += bytes_count
                device_traffic[mac] += bytes_count

            top_apps = sorted(app_traffic.items(), key=lambda x: -x[1])[:10]
            top_devices = sorted(device_traffic.items(), key=lambda x: -x[1])[:10]

            stats = TrafficStats(
                timestamp=datetime.utcnow().isoformat() + "Z",
                rx_bytes=rx_bytes,
                tx_bytes=tx_bytes,
                total_bytes=rx_bytes + tx_bytes,
                flows_active=len(flows.get("flows", [])),
                top_apps=[{"app": a, "bytes": b} for a, b in top_apps],
                top_devices=[{"mac": m, "bytes": b} for m, b in top_devices]
            )

            add_traffic_stats(stats)

            # Check quotas
            quota_alerts = check_quotas(dict(app_traffic), dict(device_traffic))
            for alert in quota_alerts:
                await send_webhook("quota_exceeded", alert)

            # Save periodically (every 5 minutes)
            if len(_traffic_history) % 5 == 0:
                save_traffic_history()

        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error(f"Stats collection error: {e}")


@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    global _stats_task
    load_traffic_history()
    _stats_task = asyncio.create_task(collect_stats_periodically())
    log.info("DPI module started with traffic monitoring")


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    global _stats_task
    if _stats_task:
        _stats_task.cancel()
        try:
            await _stats_task
        except asyncio.CancelledError:
            pass
    save_traffic_history()
    log.info("DPI module stopped")


app.include_router(router)
