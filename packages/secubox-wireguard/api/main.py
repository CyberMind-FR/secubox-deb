"""
secubox-wireguard - FastAPI application
Port de luci-app-wireguard-dashboard vers Debian

Three-fold architecture:
  - /components : what is this module made of
  - /status     : health and runtime state
  - /access     : how to connect

Enhanced features (v2.0.0):
  - Connection stats and traffic monitoring
  - Peer activity history
  - Handshake monitoring
  - Bandwidth tracking per peer
  - Webhook notifications
  - Background health monitoring
  - Config backup/restore
"""
import asyncio
import json
import subprocess
import base64
import os
import time
import threading
import hashlib
import hmac
import httpx
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

log = get_logger("wireguard")

# Data paths
DATA_DIR = Path("/var/lib/secubox/wireguard")
STATS_HISTORY_FILE = DATA_DIR / "stats_history.json"
PEER_HISTORY_FILE = DATA_DIR / "peer_history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
CONFIG_BACKUP_DIR = DATA_DIR / "config_backups"

DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_BACKUP_DIR.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════

class PeerStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class PeerStats(BaseModel):
    name: str
    public_key: str
    status: PeerStatus
    last_handshake: Optional[str] = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    endpoint: Optional[str] = None
    allowed_ips: List[str] = []


class TrafficSnapshot(BaseModel):
    timestamp: str
    interface: str
    total_rx_bytes: int = 0
    total_tx_bytes: int = 0
    peer_count: int = 0
    online_peers: int = 0


class WebhookConfig(BaseModel):
    id: str
    url: str
    events: List[str] = ["peer_connected", "peer_disconnected", "handshake_timeout"]
    secret: Optional[str] = None
    enabled: bool = True
    created_at: str
    last_triggered: Optional[str] = None
    failure_count: int = 0


# ═══════════════════════════════════════════════════════════════════════
# Stats Cache
# ═══════════════════════════════════════════════════════════════════════

class StatsCache:
    """Thread-safe stats cache with TTL."""
    def __init__(self, ttl_seconds: int = 30):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps[key] < self.ttl:
                    return self._cache[key]
                del self._cache[key]
                del self._timestamps[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()


stats_cache = StatsCache(ttl_seconds=30)


# ═══════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════

def _load_json(path: Path, default=None) -> Any:
    if default is None:
        default = {}
    try:
        if path.exists():
            return json.loads(path.read_text())
    except (json.JSONDecodeError, IOError):
        pass
    return default


def _save_json(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def _human_bytes(b: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def _parse_wg_show() -> Dict[str, Any]:
    """Parse wg show output for all interfaces."""
    result = {"interfaces": {}}
    try:
        proc = subprocess.run(
            ["wg", "show", "all", "dump"],
            capture_output=True, text=True, timeout=5
        )
        if proc.returncode != 0:
            return result

        current_iface = None
        for line in proc.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split("\t")

            if len(parts) >= 4 and parts[1] != "(none)":
                # Interface line
                iface = parts[0]
                current_iface = iface
                result["interfaces"][iface] = {
                    "private_key": parts[1][:8] + "...",
                    "public_key": parts[2],
                    "listen_port": int(parts[3]) if parts[3] != "(none)" else None,
                    "peers": []
                }
            elif len(parts) >= 8 and current_iface:
                # Peer line
                peer = {
                    "public_key": parts[0],
                    "preshared_key": parts[1] != "(none)",
                    "endpoint": parts[2] if parts[2] != "(none)" else None,
                    "allowed_ips": parts[3].split(",") if parts[3] != "(none)" else [],
                    "last_handshake": int(parts[4]) if parts[4] != "0" else None,
                    "rx_bytes": int(parts[5]),
                    "tx_bytes": int(parts[6]),
                    "persistent_keepalive": int(parts[7]) if parts[7] != "off" else None
                }
                result["interfaces"][current_iface]["peers"].append(peer)
    except Exception as e:
        log.error("Error parsing wg show: %s", e)

    return result


async def _trigger_webhooks(event: str, payload: dict):
    """Trigger webhooks for events."""
    webhooks = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    for hook in webhooks.get("webhooks", []):
        if not hook.get("enabled", True):
            continue
        if event not in hook.get("events", []):
            continue

        try:
            data = {
                "event": event,
                "timestamp": datetime.now().isoformat(),
                "payload": payload,
                "source": "secubox-wireguard"
            }

            headers = {"Content-Type": "application/json"}
            if hook.get("secret"):
                sig = hmac.new(
                    hook["secret"].encode(),
                    json.dumps(data).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers["X-SecuBox-Signature"] = f"sha256={sig}"

            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(hook["url"], json=data, headers=headers)

            hook["last_triggered"] = datetime.now().isoformat()
            hook["failure_count"] = 0
        except Exception:
            hook["failure_count"] = hook.get("failure_count", 0) + 1

    _save_json(WEBHOOKS_FILE, webhooks)


# ═══════════════════════════════════════════════════════════════════════
# Background Tasks
# ═══════════════════════════════════════════════════════════════════════

_stats_collector_task: Optional[asyncio.Task] = None
_previous_peer_status: Dict[str, bool] = {}


async def _periodic_stats_collector():
    """Collect WireGuard stats periodically."""
    global _previous_peer_status

    while True:
        try:
            await asyncio.sleep(60)  # Collect every minute

            wg_data = _parse_wg_show()
            history = _load_json(STATS_HISTORY_FILE, {"records": []})

            for iface, iface_data in wg_data.get("interfaces", {}).items():
                total_rx = sum(p.get("rx_bytes", 0) for p in iface_data.get("peers", []))
                total_tx = sum(p.get("tx_bytes", 0) for p in iface_data.get("peers", []))

                # Count online peers (handshake within 3 minutes)
                now = time.time()
                online = 0
                for peer in iface_data.get("peers", []):
                    last_hs = peer.get("last_handshake")
                    is_online = last_hs and (now - last_hs) < 180

                    # Track status changes for webhooks
                    peer_key = peer.get("public_key", "")[:16]
                    was_online = _previous_peer_status.get(peer_key, False)

                    if is_online and not was_online:
                        await _trigger_webhooks("peer_connected", {
                            "interface": iface,
                            "public_key": peer_key,
                            "endpoint": peer.get("endpoint")
                        })
                    elif not is_online and was_online:
                        await _trigger_webhooks("peer_disconnected", {
                            "interface": iface,
                            "public_key": peer_key
                        })

                    _previous_peer_status[peer_key] = is_online
                    if is_online:
                        online += 1

                history["records"].append({
                    "timestamp": datetime.now().isoformat(),
                    "interface": iface,
                    "total_rx_bytes": total_rx,
                    "total_tx_bytes": total_tx,
                    "peer_count": len(iface_data.get("peers", [])),
                    "online_peers": online
                })

            # Keep last 1440 records (24h)
            history["records"] = history["records"][-1440:]
            _save_json(STATS_HISTORY_FILE, history)

        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("Stats collector error: %s", e)


app = FastAPI(
    title="secubox-wireguard",
    version="2.0.0",
    root_path="/api/v1/wireguard",
)

app.include_router(auth_router, prefix="/auth")


@app.on_event("startup")
async def startup_event():
    """Start background tasks."""
    global _stats_collector_task
    _stats_collector_task = asyncio.create_task(_periodic_stats_collector())


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks."""
    global _stats_collector_task
    if _stats_collector_task:
        _stats_collector_task.cancel()


# === Helper: run wgctl ===
async def _run_ctl(*args, timeout: int = 30) -> dict:
    """Run wgctl and return JSON output."""
    cmd = ["/usr/sbin/wgctl"] + list(args)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode().strip()
        if proc.returncode == 0 and output:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                return {"output": output, "success": True}
        return {"success": proc.returncode == 0, "output": output, "error": stderr.decode().strip()}
    except asyncio.TimeoutError:
        return {"success": False, "error": "Command timeout"}
    except Exception as e:
        log.error("wgctl error: %s", e)
        return {"success": False, "error": str(e)}


# === Three-Fold Architecture Endpoints ===

@app.get("/components")
async def components():
    """List system components (public, three-fold: what)."""
    return await _run_ctl("components")


@app.get("/status")
async def status():
    """Show health status (public, three-fold: health)."""
    return await _run_ctl("status")


@app.get("/access")
async def access():
    """Show connection endpoints (public, three-fold: how)."""
    return await _run_ctl("access")


# === Interface Management ===

@app.get("/interfaces")
async def list_interfaces():
    """List all WireGuard interfaces (public)."""
    return await _run_ctl("interfaces")


@app.post("/interface/{name}/up")
async def interface_up(name: str, user=Depends(require_jwt)):
    """Bring interface up."""
    log.info("Bringing up interface: %s", name)
    return await _run_ctl("interface", "up", name)


@app.post("/interface/{name}/down")
async def interface_down(name: str, user=Depends(require_jwt)):
    """Bring interface down."""
    log.info("Bringing down interface: %s", name)
    return await _run_ctl("interface", "down", name)


# === Peer Management ===

@app.get("/peers")
async def list_peers(interface: Optional[str] = None):
    """List all peers (public)."""
    if interface:
        return await _run_ctl("peers", interface)
    return await _run_ctl("peers")


class PeerAddRequest(BaseModel):
    name: str
    interface: str = "wg0"


@app.post("/peer")
async def add_peer(req: PeerAddRequest, user=Depends(require_jwt)):
    """Add new peer with auto-generated config."""
    log.info("Adding peer: %s to %s", req.name, req.interface)
    return await _run_ctl("peer", "add", req.name, req.interface)


class PeerRemoveRequest(BaseModel):
    identifier: str
    interface: Optional[str] = None


@app.delete("/peer")
async def remove_peer(req: PeerRemoveRequest, user=Depends(require_jwt)):
    """Remove peer by name or public key."""
    log.info("Removing peer: %s", req.identifier)
    if req.interface:
        return await _run_ctl("peer", "remove", req.identifier, req.interface)
    return await _run_ctl("peer", "remove", req.identifier)


@app.get("/peer/{name}/config")
async def peer_config(name: str, user=Depends(require_jwt)):
    """Get peer config file content."""
    result = await _run_ctl("peer", "config", name)
    if "output" in result:
        return {"config": result["output"]}
    return result


@app.get("/peer/{name}/qr")
async def peer_qr(name: str, user=Depends(require_jwt)):
    """Get peer QR code as base64 PNG."""
    import os
    qr_path = f"/var/lib/secubox/wireguard/peers/{name}.png"
    if os.path.exists(qr_path):
        with open(qr_path, "rb") as f:
            qr_data = base64.b64encode(f.read()).decode()
        return {"qr_base64": qr_data, "name": name}
    return {"error": "QR code not found", "name": name}


# === Key Generation ===

@app.post("/genkey")
async def generate_keypair(user=Depends(require_jwt)):
    """Generate new WireGuard key pair."""
    return await _run_ctl("genkey")


@app.post("/genpsk")
async def generate_psk(user=Depends(require_jwt)):
    """Generate new preshared key."""
    return await _run_ctl("genpsk")


# === Migration ===

class MigrateRequest(BaseModel):
    source: str = "192.168.255.1"
    dry_run: bool = False


@app.post("/migrate")
async def migrate(req: MigrateRequest, user=Depends(require_jwt)):
    """Migrate WireGuard configuration from OpenWrt."""
    log.info("Migration requested from %s (dry_run=%s)", req.source, req.dry_run)
    args = ["migrate", req.source]
    if req.dry_run:
        args.append("--dry-run")
    return await _run_ctl(*args, timeout=120)


# === Health Check ===

@app.get("/health")
async def health():
    """Health check endpoint."""
    try:
        result = subprocess.run(["wg", "show", "interfaces"], capture_output=True, timeout=2)
        interfaces = result.stdout.decode().strip().split() if result.returncode == 0 else []
        return {
            "status": "ok",
            "module": "wireguard",
            "version": "2.0.0",
            "interfaces": len(interfaces),
        }
    except Exception as e:
        return {"status": "error", "module": "wireguard", "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# TRAFFIC STATISTICS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/stats")
async def get_stats(user=Depends(require_jwt)):
    """Get current traffic statistics for all interfaces."""
    cached = stats_cache.get("traffic_stats")
    if cached:
        return cached

    wg_data = _parse_wg_show()
    stats = {"interfaces": {}, "totals": {"rx_bytes": 0, "tx_bytes": 0, "peers": 0, "online": 0}}

    now = time.time()
    for iface, iface_data in wg_data.get("interfaces", {}).items():
        iface_stats = {
            "listen_port": iface_data.get("listen_port"),
            "peers": [],
            "totals": {"rx_bytes": 0, "tx_bytes": 0}
        }

        for peer in iface_data.get("peers", []):
            last_hs = peer.get("last_handshake")
            is_online = last_hs and (now - last_hs) < 180

            peer_stats = {
                "public_key": peer.get("public_key", "")[:16] + "...",
                "status": "online" if is_online else "offline",
                "endpoint": peer.get("endpoint"),
                "last_handshake": datetime.fromtimestamp(last_hs).isoformat() if last_hs else None,
                "rx_bytes": peer.get("rx_bytes", 0),
                "tx_bytes": peer.get("tx_bytes", 0),
                "rx_human": _human_bytes(peer.get("rx_bytes", 0)),
                "tx_human": _human_bytes(peer.get("tx_bytes", 0)),
                "allowed_ips": peer.get("allowed_ips", [])
            }
            iface_stats["peers"].append(peer_stats)
            iface_stats["totals"]["rx_bytes"] += peer.get("rx_bytes", 0)
            iface_stats["totals"]["tx_bytes"] += peer.get("tx_bytes", 0)

            stats["totals"]["peers"] += 1
            if is_online:
                stats["totals"]["online"] += 1

        iface_stats["totals"]["rx_human"] = _human_bytes(iface_stats["totals"]["rx_bytes"])
        iface_stats["totals"]["tx_human"] = _human_bytes(iface_stats["totals"]["tx_bytes"])

        stats["totals"]["rx_bytes"] += iface_stats["totals"]["rx_bytes"]
        stats["totals"]["tx_bytes"] += iface_stats["totals"]["tx_bytes"]

        stats["interfaces"][iface] = iface_stats

    stats["totals"]["rx_human"] = _human_bytes(stats["totals"]["rx_bytes"])
    stats["totals"]["tx_human"] = _human_bytes(stats["totals"]["tx_bytes"])
    stats["timestamp"] = datetime.now().isoformat()

    stats_cache.set("traffic_stats", stats)
    return stats


@app.get("/stats/history")
async def get_stats_history(
    interface: Optional[str] = None,
    hours: int = Query(default=24, le=168),
    user=Depends(require_jwt)
):
    """Get traffic statistics history."""
    history = _load_json(STATS_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    # Filter by time
    cutoff = datetime.now() - timedelta(hours=hours)
    cutoff_str = cutoff.isoformat()
    records = [r for r in records if r.get("timestamp", "") >= cutoff_str]

    # Filter by interface
    if interface:
        records = [r for r in records if r.get("interface") == interface]

    return {
        "records": records,
        "period_hours": hours,
        "interface": interface
    }


# ═══════════════════════════════════════════════════════════════════════
# PEER MONITORING
# ═══════════════════════════════════════════════════════════════════════

@app.get("/peers/status")
async def get_peers_status(user=Depends(require_jwt)):
    """Get detailed status of all peers."""
    wg_data = _parse_wg_show()
    peers = []
    now = time.time()

    for iface, iface_data in wg_data.get("interfaces", {}).items():
        for peer in iface_data.get("peers", []):
            last_hs = peer.get("last_handshake")
            is_online = last_hs and (now - last_hs) < 180
            time_since_hs = int(now - last_hs) if last_hs else None

            peers.append({
                "interface": iface,
                "public_key": peer.get("public_key", "")[:16] + "...",
                "full_key": peer.get("public_key"),
                "status": "online" if is_online else "offline",
                "endpoint": peer.get("endpoint"),
                "allowed_ips": peer.get("allowed_ips", []),
                "last_handshake": datetime.fromtimestamp(last_hs).isoformat() if last_hs else None,
                "seconds_since_handshake": time_since_hs,
                "rx_bytes": peer.get("rx_bytes", 0),
                "tx_bytes": peer.get("tx_bytes", 0),
                "persistent_keepalive": peer.get("persistent_keepalive")
            })

    online = sum(1 for p in peers if p["status"] == "online")

    return {
        "peers": peers,
        "total": len(peers),
        "online": online,
        "offline": len(peers) - online
    }


@app.get("/peers/history")
async def get_peers_history(
    limit: int = Query(default=100, le=1000),
    user=Depends(require_jwt)
):
    """Get peer activity history."""
    history = _load_json(PEER_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    records = sorted(records, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "records": records[:limit],
        "total": len(records)
    }


# ═══════════════════════════════════════════════════════════════════════
# CONFIG BACKUP
# ═══════════════════════════════════════════════════════════════════════

@app.get("/config/backups")
async def list_config_backups(user=Depends(require_jwt)):
    """List configuration backups."""
    backups = []

    for f in sorted(CONFIG_BACKUP_DIR.glob("*.conf"), reverse=True):
        stat = f.stat()
        backups.append({
            "name": f.name,
            "interface": f.stem.split("_")[0] if "_" in f.stem else f.stem,
            "size": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat()
        })

    return {
        "backups": backups[:50],
        "count": len(backups)
    }


@app.post("/config/backup/{interface}")
async def create_config_backup(interface: str, user=Depends(require_jwt)):
    """Create a backup of interface configuration."""
    conf_path = Path(f"/etc/wireguard/{interface}.conf")
    if not conf_path.exists():
        raise HTTPException(404, f"Interface {interface} config not found")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"{interface}_{timestamp}.conf"
    backup_path = CONFIG_BACKUP_DIR / backup_name

    backup_path.write_text(conf_path.read_text())

    log.info("Created config backup: %s", backup_name)

    return {
        "status": "success",
        "backup": {
            "name": backup_name,
            "interface": interface,
            "path": str(backup_path),
            "created_at": datetime.now().isoformat()
        }
    }


@app.post("/config/restore/{backup_name}")
async def restore_config_backup(backup_name: str, user=Depends(require_jwt)):
    """Restore configuration from backup."""
    backup_path = CONFIG_BACKUP_DIR / backup_name
    if not backup_path.exists():
        raise HTTPException(404, "Backup not found")

    # Extract interface name
    interface = backup_name.split("_")[0]
    conf_path = Path(f"/etc/wireguard/{interface}.conf")

    # Backup current config first
    if conf_path.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pre_restore = CONFIG_BACKUP_DIR / f"{interface}_pre_restore_{timestamp}.conf"
        pre_restore.write_text(conf_path.read_text())

    # Restore
    conf_path.write_text(backup_path.read_text())

    log.info("Restored config from backup: %s", backup_name)

    return {
        "status": "success",
        "backup": backup_name,
        "interface": interface
    }


# ═══════════════════════════════════════════════════════════════════════
# WEBHOOKS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    """List configured webhooks."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})
    return {
        "webhooks": data.get("webhooks", []),
        "available_events": [
            "peer_connected", "peer_disconnected", "handshake_timeout",
            "interface_up", "interface_down", "config_changed"
        ]
    }


class WebhookCreate(BaseModel):
    url: str
    events: List[str] = ["peer_connected", "peer_disconnected"]
    secret: Optional[str] = None
    enabled: bool = True


@app.post("/webhooks")
async def add_webhook(config: WebhookCreate, user=Depends(require_jwt)):
    """Add a webhook."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    webhook_id = hashlib.sha256(f"{config.url}{time.time()}".encode()).hexdigest()[:12]

    webhook = {
        "id": webhook_id,
        "url": config.url,
        "events": config.events,
        "secret": config.secret,
        "enabled": config.enabled,
        "created_at": datetime.now().isoformat(),
        "last_triggered": None,
        "failure_count": 0
    }

    data["webhooks"].append(webhook)
    _save_json(WEBHOOKS_FILE, data)

    return {"status": "success", "webhook": webhook}


@app.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Delete a webhook."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    original_len = len(data["webhooks"])
    data["webhooks"] = [w for w in data["webhooks"] if w.get("id") != webhook_id]

    if len(data["webhooks"]) == original_len:
        raise HTTPException(status_code=404, detail="Webhook not found")

    _save_json(WEBHOOKS_FILE, data)
    return {"status": "success"}


@app.post("/webhooks/{webhook_id}/test")
async def test_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Test a webhook with a sample payload."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    webhook = next((w for w in data["webhooks"] if w.get("id") == webhook_id), None)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    test_payload = {
        "event": "test",
        "timestamp": datetime.now().isoformat(),
        "payload": {"message": "This is a test webhook from SecuBox WireGuard"}
    }

    try:
        headers = {"Content-Type": "application/json"}
        if webhook.get("secret"):
            sig = hmac.new(
                webhook["secret"].encode(),
                json.dumps(test_payload).encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-SecuBox-Signature"] = f"sha256={sig}"

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook["url"], json=test_payload, headers=headers)
            return {
                "status": "success",
                "response_code": resp.status_code,
                "response_body": resp.text[:500]
            }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════

@app.get("/summary")
async def get_wireguard_summary(user=Depends(require_jwt)):
    """Get comprehensive WireGuard summary."""
    wg_data = _parse_wg_show()
    now = time.time()

    interfaces = []
    total_peers = 0
    total_online = 0
    total_rx = 0
    total_tx = 0

    for iface, iface_data in wg_data.get("interfaces", {}).items():
        online = 0
        rx = 0
        tx = 0

        for peer in iface_data.get("peers", []):
            last_hs = peer.get("last_handshake")
            if last_hs and (now - last_hs) < 180:
                online += 1
            rx += peer.get("rx_bytes", 0)
            tx += peer.get("tx_bytes", 0)

        interfaces.append({
            "name": iface,
            "listen_port": iface_data.get("listen_port"),
            "peers": len(iface_data.get("peers", [])),
            "online": online,
            "rx_bytes": rx,
            "tx_bytes": tx
        })

        total_peers += len(iface_data.get("peers", []))
        total_online += online
        total_rx += rx
        total_tx += tx

    return {
        "interfaces": interfaces,
        "totals": {
            "interface_count": len(interfaces),
            "total_peers": total_peers,
            "online_peers": total_online,
            "offline_peers": total_peers - total_online,
            "rx_bytes": total_rx,
            "tx_bytes": total_tx,
            "rx_human": _human_bytes(total_rx),
            "tx_human": _human_bytes(total_tx)
        },
        "timestamp": datetime.now().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════
# EXPORT
# ═══════════════════════════════════════════════════════════════════════

@app.get("/export/peers")
async def export_peers(
    format: str = Query(default="json", enum=["json", "csv"]),
    user=Depends(require_jwt)
):
    """Export peer list."""
    peers_result = await get_peers_status(user)
    peers = peers_result.get("peers", [])

    if format == "csv":
        lines = ["interface,public_key,status,endpoint,allowed_ips,rx_bytes,tx_bytes"]
        for p in peers:
            lines.append(",".join([
                p.get("interface", ""),
                p.get("public_key", ""),
                p.get("status", ""),
                p.get("endpoint", "") or "",
                "|".join(p.get("allowed_ips", [])),
                str(p.get("rx_bytes", 0)),
                str(p.get("tx_bytes", 0))
            ]))
        return {"format": "csv", "data": "\n".join(lines)}

    return {
        "format": "json",
        "exported_at": datetime.now().isoformat(),
        "peers": peers
    }
