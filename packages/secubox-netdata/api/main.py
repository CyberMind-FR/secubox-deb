"""SecuBox Netdata API - Netdata REST v2 Proxy with Enhanced Monitoring"""
import subprocess
import psutil
import time
import threading
import asyncio
import json
import hashlib
import hmac
import httpx
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, APIRouter, Depends, Query
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-netdata", version="2.0.0", root_path="/api/v1/netdata")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("netdata")

# Configuration
DATA_DIR = Path("/var/lib/secubox/netdata")
DATA_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_FILE = DATA_DIR / "history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
STATS_HISTORY_FILE = DATA_DIR / "stats_history.json"

# Track previous network counters for rate calculation
_prev_net = {"rx": 0, "tx": 0, "time": 0}


class StatsCache:
    """Thread-safe stats cache with TTL."""

    def __init__(self, ttl_seconds: int = 5):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps[key] < self.ttl:
                    return self._cache[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._timestamps.clear()


stats_cache = StatsCache(ttl_seconds=5)


# Pydantic Models
class AlertThreshold(BaseModel):
    metric: str = Field(..., pattern="^(cpu|memory|disk|load)$")
    warning: float
    critical: float
    enabled: bool = True


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = Field(default=["alert_triggered", "service_down", "threshold_exceeded"])
    secret: Optional[str] = None
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


# State
_monitoring_task: Optional[asyncio.Task] = None
_previous_netdata_running: Optional[bool] = None
_alert_thresholds: Dict[str, Dict[str, float]] = {
    "cpu": {"warning": 80, "critical": 95},
    "memory": {"warning": 85, "critical": 95},
    "disk": {"warning": 85, "critical": 95},
    "load": {"warning": 5.0, "critical": 10.0}
}


def _format_bytes(size: float) -> str:
    """Format bytes to human readable string."""
    for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB/s"


def _load_json(filepath: Path, default=None):
    """Load JSON file safely."""
    if filepath.exists():
        try:
            return json.loads(filepath.read_text())
        except Exception:
            pass
    return default if default is not None else []


def _save_json(filepath: Path, data):
    """Save JSON file safely."""
    filepath.write_text(json.dumps(data, indent=2))


def _load_history() -> List[Dict[str, Any]]:
    return _load_json(HISTORY_FILE, [])


def _save_history(history: List[Dict[str, Any]]):
    history = history[-1000:]
    _save_json(HISTORY_FILE, history)


def _load_webhooks() -> List[Dict[str, Any]]:
    return _load_json(WEBHOOKS_FILE, [])


def _save_webhooks(webhooks: List[Dict[str, Any]]):
    _save_json(WEBHOOKS_FILE, webhooks)


def _load_stats_history() -> List[Dict[str, Any]]:
    return _load_json(STATS_HISTORY_FILE, [])


def _save_stats_history(history: List[Dict[str, Any]]):
    history = history[-1440:]  # Keep ~24h at 1-min intervals
    _save_json(STATS_HISTORY_FILE, history)


def _record_event(event: str, details: Optional[Dict] = None):
    """Record an event in history."""
    history = _load_history()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "details": details or {}
    }
    history.append(entry)
    _save_history(history)


async def _send_webhook(url: str, payload: Dict[str, Any], secret: Optional[str] = None):
    """Send webhook notification."""
    try:
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload)

        if secret:
            signature = hmac.new(
                secret.encode(),
                body.encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-SecuBox-Signature"] = f"sha256={signature}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, content=body, headers=headers)
    except Exception:
        pass


async def _notify_webhooks(event: str, data: Dict[str, Any]):
    """Send notifications to all webhooks for event."""
    webhooks = _load_webhooks()
    for webhook in webhooks:
        if webhook.get("enabled", True) and event in webhook.get("events", []):
            await _send_webhook(
                webhook["url"],
                {"event": event, "data": data, "timestamp": datetime.now().isoformat()},
                webhook.get("secret")
            )


def _base():
    """Get Netdata base URL."""
    cfg = get_config("netdata")
    return cfg.get("url", "http://127.0.0.1:19999") if cfg else "http://127.0.0.1:19999"


async def _nd(path: str, params: dict = None):
    """Make request to Netdata."""
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"{_base()}{path}", params=params or {})
        r.raise_for_status()
        return r.json()


def _get_system_stats() -> Dict[str, Any]:
    """Get current system stats using psutil."""
    global _prev_net

    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        load = psutil.getloadavg()

        # Network I/O rate calculation
        net = psutil.net_io_counters()
        now = time.time()
        elapsed = now - _prev_net["time"] if _prev_net["time"] > 0 else 1
        if elapsed < 0.1:
            elapsed = 1

        rx_rate = (net.bytes_recv - _prev_net["rx"]) / elapsed if _prev_net["rx"] > 0 else 0
        tx_rate = (net.bytes_sent - _prev_net["tx"]) / elapsed if _prev_net["tx"] > 0 else 0

        _prev_net = {"rx": net.bytes_recv, "tx": net.bytes_sent, "time": now}

        return {
            "cpu_percent": round(cpu, 1),
            "memory_percent": round(mem.percent, 1),
            "memory_used_gb": round(mem.used / (1024**3), 2),
            "memory_total_gb": round(mem.total / (1024**3), 2),
            "disk_percent": round(disk.percent, 1),
            "disk_used_gb": round(disk.used / (1024**3), 2),
            "disk_total_gb": round(disk.total / (1024**3), 2),
            "net_rx": round(max(0, rx_rate)),
            "net_rx_human": _format_bytes(max(0, rx_rate)),
            "net_tx": round(max(0, tx_rate)),
            "net_tx_human": _format_bytes(max(0, tx_rate)),
            "load_avg": [round(load[0], 2), round(load[1], 2), round(load[2], 2)],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        log.warning("stats error: %s", e)
        return {
            "cpu_percent": 0,
            "memory_percent": 0,
            "disk_percent": 0,
            "net_rx": 0,
            "net_tx": 0,
            "load_avg": [0, 0, 0],
            "error": str(e)
        }


async def _check_thresholds(stats: Dict[str, Any]):
    """Check if any thresholds are exceeded."""
    alerts = []

    for metric, thresholds in _alert_thresholds.items():
        if metric == "cpu":
            value = stats.get("cpu_percent", 0)
        elif metric == "memory":
            value = stats.get("memory_percent", 0)
        elif metric == "disk":
            value = stats.get("disk_percent", 0)
        elif metric == "load":
            value = stats.get("load_avg", [0])[0]
        else:
            continue

        if value >= thresholds.get("critical", 100):
            alerts.append({
                "metric": metric,
                "value": value,
                "threshold": thresholds["critical"],
                "severity": "critical"
            })
        elif value >= thresholds.get("warning", 100):
            alerts.append({
                "metric": metric,
                "value": value,
                "threshold": thresholds["warning"],
                "severity": "warning"
            })

    if alerts:
        for alert in alerts:
            await _notify_webhooks("threshold_exceeded", alert)


async def _monitor_system():
    """Background task to monitor system and collect stats."""
    global _previous_netdata_running
    stats_counter = 0

    while True:
        try:
            # Check Netdata service
            try:
                info = await _nd("/api/v1/info")
                running = True
            except Exception:
                running = False

            if _previous_netdata_running is not None and _previous_netdata_running != running:
                event = "service_up" if running else "service_down"
                _record_event(event, {"service": "netdata"})
                await _notify_webhooks(event, {"service": "netdata"})

            _previous_netdata_running = running

            # Collect stats every minute
            stats_counter += 1
            if stats_counter >= 2:  # Every 60 seconds (30 * 2)
                stats_counter = 0
                stats = _get_system_stats()

                # Save to history
                history = _load_stats_history()
                history.append(stats)
                _save_stats_history(history)

                # Check thresholds
                await _check_thresholds(stats)

        except Exception as e:
            log.warning("monitor error: %s", e)

        await asyncio.sleep(30)


@app.on_event("startup")
async def startup():
    """Start background monitoring."""
    global _monitoring_task
    _monitoring_task = asyncio.create_task(_monitor_system())


@app.on_event("shutdown")
async def shutdown():
    """Stop background monitoring."""
    global _monitoring_task
    if _monitoring_task:
        _monitoring_task.cancel()


# Public endpoints
@router.get("/health")
async def health():
    return {"status": "ok", "module": "netdata", "version": "2.0.0"}


@router.get("/status")
async def status():
    """Netdata status for dashboard (public)."""
    cached = stats_cache.get("status")
    if cached:
        return cached

    try:
        info = await _nd("/api/v1/info")
        result = {
            "running": True,
            "version": info.get("version", ""),
            "hostname": info.get("hostname", ""),
            "os": info.get("os_name", ""),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        result = {"running": False, "error": str(e)}

    stats_cache.set("status", result)
    return result


@router.get("/stats")
async def stats():
    """System stats for dashboard (public)."""
    cached = stats_cache.get("stats")
    if cached:
        return cached

    result = _get_system_stats()
    stats_cache.set("stats", result)
    return result


@router.get("/stats/history")
async def stats_history(hours: int = 1, user=Depends(require_jwt)):
    """Get historical stats."""
    history = _load_stats_history()
    cutoff = datetime.now() - timedelta(hours=hours)

    filtered = []
    for entry in history:
        try:
            entry_time = datetime.fromisoformat(entry.get("timestamp", "2000-01-01"))
            if entry_time >= cutoff:
                filtered.append(entry)
        except ValueError:
            continue

    return {
        "history": filtered,
        "count": len(filtered),
        "hours": hours
    }


@router.get("/processes")
async def processes():
    """Top processes for dashboard (public)."""
    cached = stats_cache.get("processes")
    if cached:
        return cached

    try:
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                info = p.info
                if info['cpu_percent'] is not None and info['memory_percent'] is not None:
                    procs.append({
                        "pid": info['pid'],
                        "name": info['name'] or "unknown",
                        "cpu_percent": round(info['cpu_percent'], 1),
                        "memory_percent": round(info['memory_percent'], 1),
                        "status": info.get('status', 'unknown')
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        procs.sort(key=lambda x: (x['cpu_percent'], x['memory_percent']), reverse=True)
        result = {"processes": procs[:20], "total": len(procs)}
        stats_cache.set("processes", result)
        return result
    except Exception as e:
        log.warning("processes: %s", e)
        return {"processes": [], "error": str(e)}


@router.get("/alerts")
async def alerts():
    """Alerts for dashboard (public)."""
    cached = stats_cache.get("alerts")
    if cached:
        return cached

    try:
        data = await _nd("/api/v1/alarms")
        alerts_list = []
        alarms_dict = data.get("alarms", {}) if isinstance(data, dict) else {}

        for name, alarm in alarms_dict.items():
            if isinstance(alarm, dict) and alarm.get("status", "").upper() not in ("OK", "UNDEFINED"):
                severity = "critical" if alarm.get("status", "").upper() == "CRITICAL" else "warning"
                alerts_list.append({
                    "name": alarm.get("name", name),
                    "chart": alarm.get("chart", ""),
                    "severity": severity,
                    "status": alarm.get("status", ""),
                    "message": alarm.get("info", alarm.get("value_string", "Alert triggered")),
                    "value": alarm.get("value", 0)
                })

        result = {
            "alerts": alerts_list,
            "count": len(alerts_list),
            "timestamp": datetime.now().isoformat()
        }
        stats_cache.set("alerts", result)
        return result
    except Exception as e:
        log.warning("alerts: %s", e)
        return {"alerts": [], "error": str(e)}


# Protected endpoints
@router.get("/info")
async def info(user=Depends(require_jwt)):
    return await _nd("/api/v1/info")


@router.get("/charts")
async def charts(user=Depends(require_jwt)):
    return await _nd("/api/v1/charts")


@router.get("/data")
async def data(chart: str = "system.cpu", after: int = -60, user=Depends(require_jwt)):
    return await _nd("/api/v2/data", {"contexts": chart, "after": after, "format": "json2"})


@router.get("/cpu")
async def cpu(after: int = -60, user=Depends(require_jwt)):
    return await _nd("/api/v2/data", {"contexts": "system.cpu", "after": after, "format": "json2"})


@router.get("/memory")
async def memory(after: int = -60, user=Depends(require_jwt)):
    return await _nd("/api/v2/data", {"contexts": "system.ram,mem.available", "after": after, "format": "json2"})


@router.get("/disk")
async def disk(after: int = -60, user=Depends(require_jwt)):
    return await _nd("/api/v2/data", {"contexts": "system.io,disk.io", "after": after, "format": "json2"})


@router.get("/network")
async def network(after: int = -60, user=Depends(require_jwt)):
    return await _nd("/api/v2/data", {"contexts": "system.net", "after": after, "format": "json2"})


@router.get("/sensors")
async def sensors(user=Depends(require_jwt)):
    try:
        return await _nd("/api/v2/data", {"contexts": "sensors.*", "after": -60, "format": "json2"})
    except Exception:
        return {"sensors": []}


@router.get("/system")
async def system(user=Depends(require_jwt)):
    return await _nd("/api/v2/data", {
        "contexts": "system.cpu,system.ram,system.load,system.uptime",
        "after": -60,
        "format": "json2"
    })


@router.get("/alarms")
async def alarms(user=Depends(require_jwt)):
    return await _nd("/api/v1/alarms")


# Service control
@router.post("/start")
async def start_netdata(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "start", "netdata"], capture_output=True, text=True, timeout=15)
    success = r.returncode == 0
    if success:
        _record_event("service_start", {"by": user.get("sub")})
        stats_cache.clear()
    return {"success": success, "output": r.stderr[:200] if r.stderr else ""}


@router.post("/stop")
async def stop_netdata(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "stop", "netdata"], capture_output=True, text=True, timeout=15)
    success = r.returncode == 0
    if success:
        _record_event("service_stop", {"by": user.get("sub")})
        stats_cache.clear()
    return {"success": success, "output": r.stderr[:200] if r.stderr else ""}


@router.post("/restart")
async def restart_netdata(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "restart", "netdata"], capture_output=True, text=True, timeout=30)
    success = r.returncode == 0
    if success:
        _record_event("service_restart", {"by": user.get("sub")})
        stats_cache.clear()
    log.info("restart_netdata: %s", r.returncode)
    return {"success": success, "output": r.stderr[:200] if r.stderr else ""}


# Thresholds
@router.get("/thresholds")
async def get_thresholds(user=Depends(require_jwt)):
    """Get alert thresholds."""
    return {"thresholds": _alert_thresholds}


@router.post("/thresholds")
async def set_threshold(threshold: AlertThreshold, user=Depends(require_jwt)):
    """Set an alert threshold."""
    _alert_thresholds[threshold.metric] = {
        "warning": threshold.warning,
        "critical": threshold.critical,
        "enabled": threshold.enabled
    }
    _record_event("threshold_set", {
        "metric": threshold.metric,
        "warning": threshold.warning,
        "critical": threshold.critical,
        "by": user.get("sub")
    })
    return {"success": True, "threshold": _alert_thresholds[threshold.metric]}


# History and logs
@router.get("/history")
async def get_history(limit: int = 100, user=Depends(require_jwt)):
    """Get event history."""
    history = _load_history()
    return {
        "events": history[-limit:],
        "total": len(history)
    }


@router.get("/logs")
async def get_logs(lines: int = Query(100, ge=1, le=1000), user=Depends(require_jwt)):
    """Get Netdata service logs."""
    r = subprocess.run(
        ["journalctl", "-u", "netdata", "-n", str(lines), "--no-pager"],
        capture_output=True, text=True, timeout=10
    )
    return {"lines": r.stdout.splitlines(), "count": len(r.stdout.splitlines())}


@router.get("/debug")
async def collect_debug(user=Depends(require_jwt)):
    """Collect debug information."""
    debug_info = {}

    try:
        debug_info["info"] = await _nd("/api/v1/info")
    except Exception as e:
        debug_info["info_error"] = str(e)

    r = subprocess.run(
        ["systemctl", "status", "netdata"],
        capture_output=True, text=True, timeout=10
    )
    debug_info["service_status"] = r.stdout[:1000]
    debug_info["system_stats"] = _get_system_stats()

    return debug_info


# Webhooks
@router.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    """List configured webhooks."""
    return {"webhooks": _load_webhooks()}


@router.post("/webhooks")
async def add_webhook(webhook: WebhookConfig, user=Depends(require_jwt)):
    """Add a new webhook."""
    webhooks = _load_webhooks()
    webhook_data = webhook.model_dump()
    webhook_data["id"] = hashlib.md5(webhook.url.encode()).hexdigest()[:8]
    webhook_data["created_at"] = datetime.now().isoformat()
    webhooks.append(webhook_data)
    _save_webhooks(webhooks)
    return {"success": True, "webhook": webhook_data}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Delete a webhook."""
    webhooks = _load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    _save_webhooks(webhooks)
    return {"success": True}


@router.get("/summary")
async def summary():
    """Get netdata summary."""
    status_info = await status()
    stats_info = await stats()
    alerts_info = await alerts()

    return {
        "netdata_running": status_info.get("running", False),
        "version": status_info.get("version", ""),
        "system": {
            "cpu": stats_info.get("cpu_percent", 0),
            "memory": stats_info.get("memory_percent", 0),
            "disk": stats_info.get("disk_percent", 0),
            "load": stats_info.get("load_avg", [0, 0, 0])[0],
            "net_rx": stats_info.get("net_rx_human", "0 B/s"),
            "net_tx": stats_info.get("net_tx_human", "0 B/s")
        },
        "alerts": {
            "count": alerts_info.get("count", 0),
            "critical": sum(1 for a in alerts_info.get("alerts", []) if a.get("severity") == "critical"),
            "warning": sum(1 for a in alerts_info.get("alerts", []) if a.get("severity") == "warning")
        },
        "thresholds": _alert_thresholds,
        "webhooks_configured": len(_load_webhooks()),
        "timestamp": datetime.now().isoformat()
    }


# Aliases for compatibility
@router.get("/netdata_status")
async def netdata_status():
    return await status()


@router.get("/netdata_info")
async def netdata_info(user=Depends(require_jwt)):
    return await info(user)


@router.get("/netdata_alarms")
async def netdata_alarms(user=Depends(require_jwt)):
    return await alarms(user)


@router.get("/secubox_logs")
async def secubox_logs(lines: int = Query(100, ge=1, le=1000), user=Depends(require_jwt)):
    return await get_logs(lines, user)


@router.post("/restart_netdata")
async def restart_netdata_alias(user=Depends(require_jwt)):
    return await restart_netdata(user)


@router.post("/start_netdata")
async def start_netdata_alias(user=Depends(require_jwt)):
    return await start_netdata(user)


@router.post("/stop_netdata")
async def stop_netdata_alias(user=Depends(require_jwt)):
    return await stop_netdata(user)


app.include_router(router)
