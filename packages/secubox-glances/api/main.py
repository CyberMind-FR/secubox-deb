"""
SecuBox-Deb :: secubox-glances
CyberMind - https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

Glances system monitoring module - wraps the Glances monitoring tool.
"""
import subprocess
import psutil
import time
import threading
import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-glances", version="1.0.0", root_path="/api/v1/glances")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("glances")

# Configuration
DATA_DIR = Path("/var/lib/secubox/glances")
DATA_DIR.mkdir(parents=True, exist_ok=True)
HISTORY_FILE = DATA_DIR / "history.json"
CONFIG_FILE = Path("/etc/secubox/glances.toml")
GLANCES_CONFIG = Path("/etc/glances/glances.conf")

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
class GlancesConfig(BaseModel):
    """Glances configuration model."""
    refresh_interval: int = Field(default=3, ge=1, le=60)
    enable_history: bool = True
    history_size: int = Field(default=1440, ge=60, le=10080)
    process_top_n: int = Field(default=15, ge=5, le=50)
    sensors_enabled: bool = True
    network_interfaces: List[str] = []
    disk_paths: List[str] = ["/"]


class ServiceAction(BaseModel):
    """Service action request."""
    action: str = Field(..., pattern="^(start|stop|restart)$")


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
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(json.dumps(data, indent=2))


def _load_history() -> List[Dict[str, Any]]:
    return _load_json(HISTORY_FILE, [])


def _save_history(history: List[Dict[str, Any]]):
    history = history[-1440:]  # Keep ~24h at 1-min intervals
    _save_json(HISTORY_FILE, history)


def _format_bytes(size: float) -> str:
    """Format bytes to human readable string."""
    for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB/s"


def _format_size(size: float) -> str:
    """Format bytes to human readable size."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def _glances_running() -> bool:
    """Check if glances daemon is running."""
    result = subprocess.run(
        ["pgrep", "-f", "glances"],
        capture_output=True
    )
    return result.returncode == 0


def _get_glances_version() -> str:
    """Get glances version."""
    try:
        result = subprocess.run(
            ["glances", "--version"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # First line usually contains version
            for line in result.stdout.splitlines():
                if "Glances" in line:
                    return line.strip()
            return result.stdout.splitlines()[0].strip() if result.stdout else ""
    except Exception:
        pass
    return ""


def _get_system_stats() -> Dict[str, Any]:
    """Get current system stats using psutil."""
    global _prev_net

    try:
        cpu = psutil.cpu_percent(interval=0.5)
        cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = psutil.disk_usage("/")
        load = psutil.getloadavg()
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time

        # Network I/O rate calculation
        net = psutil.net_io_counters()
        now = time.time()
        elapsed = now - _prev_net["time"] if _prev_net["time"] > 0 else 1
        if elapsed < 0.1:
            elapsed = 1

        rx_rate = (net.bytes_recv - _prev_net["rx"]) / elapsed if _prev_net["rx"] > 0 else 0
        tx_rate = (net.bytes_sent - _prev_net["tx"]) / elapsed if _prev_net["tx"] > 0 else 0

        _prev_net = {"rx": net.bytes_recv, "tx": net.bytes_sent, "time": now}

        # CPU frequency
        cpu_freq = psutil.cpu_freq()
        freq_current = cpu_freq.current if cpu_freq else 0
        freq_max = cpu_freq.max if cpu_freq else 0

        return {
            "cpu": {
                "percent": round(cpu, 1),
                "per_core": [round(c, 1) for c in cpu_per_core],
                "count": psutil.cpu_count(),
                "count_logical": psutil.cpu_count(logical=True),
                "freq_current": round(freq_current, 0),
                "freq_max": round(freq_max, 0)
            },
            "memory": {
                "percent": round(mem.percent, 1),
                "used": mem.used,
                "used_human": _format_size(mem.used),
                "total": mem.total,
                "total_human": _format_size(mem.total),
                "available": mem.available,
                "available_human": _format_size(mem.available),
                "cached": getattr(mem, 'cached', 0),
                "buffers": getattr(mem, 'buffers', 0)
            },
            "swap": {
                "percent": round(swap.percent, 1),
                "used": swap.used,
                "used_human": _format_size(swap.used),
                "total": swap.total,
                "total_human": _format_size(swap.total)
            },
            "disk": {
                "percent": round(disk.percent, 1),
                "used": disk.used,
                "used_human": _format_size(disk.used),
                "total": disk.total,
                "total_human": _format_size(disk.total),
                "free": disk.free,
                "free_human": _format_size(disk.free)
            },
            "network": {
                "rx_rate": round(max(0, rx_rate)),
                "rx_rate_human": _format_bytes(max(0, rx_rate)),
                "tx_rate": round(max(0, tx_rate)),
                "tx_rate_human": _format_bytes(max(0, tx_rate)),
                "bytes_recv": net.bytes_recv,
                "bytes_sent": net.bytes_sent,
                "packets_recv": net.packets_recv,
                "packets_sent": net.packets_sent
            },
            "load": {
                "avg_1": round(load[0], 2),
                "avg_5": round(load[1], 2),
                "avg_15": round(load[2], 2)
            },
            "uptime": {
                "seconds": int(uptime.total_seconds()),
                "human": str(uptime).split('.')[0],
                "boot_time": boot_time.isoformat()
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        log.warning("stats error: %s", e)
        return {
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


def _get_processes() -> Dict[str, Any]:
    """Get top processes."""
    try:
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username', 'num_threads', 'create_time']):
            try:
                info = p.info
                if info['cpu_percent'] is not None and info['memory_percent'] is not None:
                    procs.append({
                        "pid": info['pid'],
                        "name": info['name'] or "unknown",
                        "cpu_percent": round(info['cpu_percent'], 1),
                        "memory_percent": round(info['memory_percent'], 1),
                        "status": info.get('status', 'unknown'),
                        "user": info.get('username', 'unknown'),
                        "threads": info.get('num_threads', 0),
                        "started": datetime.fromtimestamp(info.get('create_time', 0)).isoformat() if info.get('create_time') else None
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        procs.sort(key=lambda x: (x['cpu_percent'], x['memory_percent']), reverse=True)
        return {
            "processes": procs[:20],
            "total": len(procs),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        log.warning("processes error: %s", e)
        return {"processes": [], "error": str(e)}


def _get_sensors() -> Dict[str, Any]:
    """Get hardware sensors (temperature, fans)."""
    result = {
        "temperatures": [],
        "fans": [],
        "battery": None,
        "timestamp": datetime.now().isoformat()
    }

    try:
        # Temperature sensors
        temps = psutil.sensors_temperatures()
        for name, entries in temps.items():
            for entry in entries:
                result["temperatures"].append({
                    "name": f"{name}_{entry.label}" if entry.label else name,
                    "current": round(entry.current, 1),
                    "high": entry.high if entry.high else None,
                    "critical": entry.critical if entry.critical else None,
                    "unit": "C"
                })
    except Exception:
        pass

    try:
        # Fan sensors
        fans = psutil.sensors_fans()
        for name, entries in fans.items():
            for entry in entries:
                result["fans"].append({
                    "name": f"{name}_{entry.label}" if entry.label else name,
                    "current": entry.current,
                    "unit": "RPM"
                })
    except Exception:
        pass

    try:
        # Battery
        battery = psutil.sensors_battery()
        if battery:
            result["battery"] = {
                "percent": round(battery.percent, 1),
                "plugged": battery.power_plugged,
                "secsleft": battery.secsleft if battery.secsleft != psutil.POWER_TIME_UNLIMITED else -1
            }
    except Exception:
        pass

    return result


def _get_disk_io() -> Dict[str, Any]:
    """Get disk I/O stats."""
    try:
        io = psutil.disk_io_counters(perdisk=True)
        disks = []
        for name, counters in io.items():
            disks.append({
                "name": name,
                "read_bytes": counters.read_bytes,
                "write_bytes": counters.write_bytes,
                "read_count": counters.read_count,
                "write_count": counters.write_count,
                "read_time": counters.read_time,
                "write_time": counters.write_time
            })
        return {"disks": disks, "timestamp": datetime.now().isoformat()}
    except Exception as e:
        return {"disks": [], "error": str(e)}


def _get_network_interfaces() -> Dict[str, Any]:
    """Get network interface details."""
    try:
        interfaces = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        io = psutil.net_io_counters(pernic=True)

        for name, stat in stats.items():
            iface = {
                "name": name,
                "is_up": stat.isup,
                "speed": stat.speed,
                "mtu": stat.mtu,
                "addresses": [],
                "bytes_recv": 0,
                "bytes_sent": 0
            }

            if name in addrs:
                for addr in addrs[name]:
                    iface["addresses"].append({
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast
                    })

            if name in io:
                iface["bytes_recv"] = io[name].bytes_recv
                iface["bytes_sent"] = io[name].bytes_sent

            interfaces.append(iface)

        return {"interfaces": interfaces, "timestamp": datetime.now().isoformat()}
    except Exception as e:
        return {"interfaces": [], "error": str(e)}


# Background monitoring task
_monitoring_task: Optional[asyncio.Task] = None


async def _monitor_system():
    """Background task to collect stats history."""
    while True:
        try:
            stats = _get_system_stats()
            if "error" not in stats:
                history = _load_history()
                history.append({
                    "cpu": stats["cpu"]["percent"],
                    "memory": stats["memory"]["percent"],
                    "disk": stats["disk"]["percent"],
                    "net_rx": stats["network"]["rx_rate"],
                    "net_tx": stats["network"]["tx_rate"],
                    "load": stats["load"]["avg_1"],
                    "timestamp": stats["timestamp"]
                })
                _save_history(history)
        except Exception as e:
            log.warning("monitor error: %s", e)

        await asyncio.sleep(60)  # Collect every minute


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


# Public endpoints (no auth for dashboard widgets)
@router.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "module": "glances", "version": "1.0.0"}


@router.get("/status")
async def status():
    """Service status (public for dashboard)."""
    cached = stats_cache.get("status")
    if cached:
        return cached

    result = {
        "running": _glances_running(),
        "version": _get_glances_version(),
        "timestamp": datetime.now().isoformat()
    }
    stats_cache.set("status", result)
    return result


@router.get("/stats")
async def stats():
    """Current system stats (public for dashboard)."""
    cached = stats_cache.get("stats")
    if cached:
        return cached

    result = _get_system_stats()
    stats_cache.set("stats", result)
    return result


# Protected endpoints
@router.get("/processes")
async def processes(user=Depends(require_jwt)):
    """Get top processes."""
    cached = stats_cache.get("processes")
    if cached:
        return cached

    result = _get_processes()
    stats_cache.set("processes", result)
    return result


@router.get("/sensors")
async def sensors(user=Depends(require_jwt)):
    """Get hardware sensors."""
    cached = stats_cache.get("sensors")
    if cached:
        return cached

    result = _get_sensors()
    stats_cache.set("sensors", result)
    return result


@router.get("/history")
async def history(hours: int = Query(1, ge=1, le=24), user=Depends(require_jwt)):
    """Get historical stats."""
    hist = _load_history()
    cutoff = datetime.now() - timedelta(hours=hours)

    filtered = []
    for entry in hist:
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


@router.get("/disk_io")
async def disk_io(user=Depends(require_jwt)):
    """Get disk I/O stats."""
    return _get_disk_io()


@router.get("/network_interfaces")
async def network_interfaces(user=Depends(require_jwt)):
    """Get network interface details."""
    return _get_network_interfaces()


# Service control
@router.post("/start")
async def start_glances(user=Depends(require_jwt)):
    """Start glances daemon."""
    try:
        # Start glances in web server mode
        result = subprocess.run(
            ["systemctl", "start", "glances"],
            capture_output=True, text=True, timeout=15
        )
        success = result.returncode == 0
        if success:
            stats_cache.clear()
            log.info("glances started by %s", user.get("sub"))
        return {"success": success, "output": result.stderr[:200] if result.stderr else ""}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/stop")
async def stop_glances(user=Depends(require_jwt)):
    """Stop glances daemon."""
    try:
        result = subprocess.run(
            ["systemctl", "stop", "glances"],
            capture_output=True, text=True, timeout=15
        )
        success = result.returncode == 0
        if success:
            stats_cache.clear()
            log.info("glances stopped by %s", user.get("sub"))
        return {"success": success, "output": result.stderr[:200] if result.stderr else ""}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/restart")
async def restart_glances(user=Depends(require_jwt)):
    """Restart glances daemon."""
    try:
        result = subprocess.run(
            ["systemctl", "restart", "glances"],
            capture_output=True, text=True, timeout=30
        )
        success = result.returncode == 0
        if success:
            stats_cache.clear()
            log.info("glances restarted by %s", user.get("sub"))
        return {"success": success, "output": result.stderr[:200] if result.stderr else ""}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# Configuration
@router.get("/config")
async def get_config_endpoint(user=Depends(require_jwt)):
    """Get glances configuration."""
    config = {
        "refresh_interval": 3,
        "enable_history": True,
        "history_size": 1440,
        "process_top_n": 15,
        "sensors_enabled": True,
        "network_interfaces": [],
        "disk_paths": ["/"]
    }

    # Read from TOML config if exists
    try:
        cfg = get_config("glances")
        if cfg:
            config.update(cfg)
    except Exception:
        pass

    # Check if glances.conf exists
    config["glances_config_exists"] = GLANCES_CONFIG.exists()

    return config


@router.post("/config")
async def update_config(config: GlancesConfig, user=Depends(require_jwt)):
    """Update glances configuration."""
    try:
        # Save to TOML config
        import tomllib
        config_data = config.model_dump()

        # Write to secubox config dir
        secubox_config = Path("/etc/secubox/glances.toml")
        secubox_config.parent.mkdir(parents=True, exist_ok=True)

        toml_content = "[glances]\n"
        for key, value in config_data.items():
            if isinstance(value, bool):
                toml_content += f"{key} = {'true' if value else 'false'}\n"
            elif isinstance(value, list):
                toml_content += f"{key} = {json.dumps(value)}\n"
            else:
                toml_content += f"{key} = {value}\n"

        secubox_config.write_text(toml_content)

        log.info("config updated by %s", user.get("sub"))
        return {"success": True, "config": config_data}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/logs")
async def get_logs(lines: int = Query(100, ge=1, le=1000), user=Depends(require_jwt)):
    """Get glances service logs."""
    try:
        result = subprocess.run(
            ["journalctl", "-u", "glances", "-n", str(lines), "--no-pager"],
            capture_output=True, text=True, timeout=10
        )
        return {"lines": result.stdout.splitlines(), "count": len(result.stdout.splitlines())}
    except Exception as e:
        return {"lines": [], "error": str(e)}


@router.get("/summary")
async def summary():
    """Get glances summary for dashboard widget."""
    status_info = await status()
    stats_info = await stats()

    cpu_data = stats_info.get("cpu", {})
    mem_data = stats_info.get("memory", {})
    disk_data = stats_info.get("disk", {})
    net_data = stats_info.get("network", {})
    load_data = stats_info.get("load", {})

    return {
        "glances_running": status_info.get("running", False),
        "version": status_info.get("version", ""),
        "system": {
            "cpu": cpu_data.get("percent", 0),
            "memory": mem_data.get("percent", 0),
            "disk": disk_data.get("percent", 0),
            "load": load_data.get("avg_1", 0),
            "net_rx": net_data.get("rx_rate_human", "0 B/s"),
            "net_tx": net_data.get("tx_rate_human", "0 B/s")
        },
        "timestamp": datetime.now().isoformat()
    }


app.include_router(router)
