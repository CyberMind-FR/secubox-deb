"""secubox-netdata — proxy Netdata REST v2"""
import subprocess
import psutil
from fastapi import FastAPI, APIRouter, Depends, Query
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger
import httpx

app = FastAPI(title="secubox-netdata", version="1.0.0", root_path="/api/v1/netdata")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("netdata")

# Track previous network counters for rate calculation
_prev_net = {"rx": 0, "tx": 0, "time": 0}


def _base():
    cfg = get_config("netdata")
    return cfg.get("url", "http://127.0.0.1:19999") if cfg else "http://127.0.0.1:19999"


async def _nd(path: str, params: dict = None):
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(f"{_base()}{path}", params=params or {})
        r.raise_for_status()
        return r.json()


# ── Status & Info ─────────────────────────────────────────────────

@router.get("/status")
async def status():
    """Netdata status for dashboard (public)."""
    try:
        info = await _nd("/api/v1/info")
        return {"running": True, "version": info.get("version", ""), "hostname": info.get("hostname", "")}
    except Exception as e:
        return {"running": False, "error": str(e)}


@router.get("/netdata_status")
async def netdata_status():
    """Alias for status (public)."""
    return await status()


@router.get("/info")
async def info(user=Depends(require_jwt)):
    return await _nd("/api/v1/info")


@router.get("/netdata_info")
async def netdata_info(user=Depends(require_jwt)):
    """Alias for info."""
    return await info(user)


# ── Charts & Data ─────────────────────────────────────────────────

@router.get("/charts")
async def charts(user=Depends(require_jwt)):
    return await _nd("/api/v1/charts")


@router.get("/data")
async def data(chart: str = "system.cpu", after: int = -60, user=Depends(require_jwt)):
    return await _nd("/api/v2/data", {"contexts": chart, "after": after, "format": "json2"})


# ── System metrics shortcuts ──────────────────────────────────────

@router.get("/stats")
async def stats():
    """System stats for dashboard (public)."""
    import time
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
            "disk_percent": round(disk.percent, 1),
            "net_rx": round(max(0, rx_rate)),
            "net_tx": round(max(0, tx_rate)),
            "load_avg": [round(load[0], 2), round(load[1], 2), round(load[2], 2)]
        }
    except Exception as e:
        log.warning("stats: %s", e)
        return {
            "cpu_percent": 0,
            "memory_percent": 0,
            "disk_percent": 0,
            "net_rx": 0,
            "net_tx": 0,
            "load_avg": [0, 0, 0]
        }


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


@router.get("/processes")
async def processes():
    """Top processes for dashboard (public)."""
    try:
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = p.info
                if info['cpu_percent'] is not None and info['memory_percent'] is not None:
                    procs.append({
                        "pid": info['pid'],
                        "name": info['name'] or "unknown",
                        "cpu_percent": round(info['cpu_percent'], 1),
                        "memory_percent": round(info['memory_percent'], 1)
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort by CPU usage, then memory
        procs.sort(key=lambda x: (x['cpu_percent'], x['memory_percent']), reverse=True)
        return {"processes": procs[:20]}
    except Exception as e:
        log.warning("processes: %s", e)
        return {"processes": []}


@router.get("/sensors")
async def sensors(user=Depends(require_jwt)):
    try:
        return await _nd("/api/v2/data", {"contexts": "sensors.*", "after": -60, "format": "json2"})
    except Exception:
        return {"sensors": []}


@router.get("/system")
async def system(user=Depends(require_jwt)):
    """Métriques système consolidées."""
    return await _nd("/api/v2/data", {
        "contexts": "system.cpu,system.ram,system.load,system.uptime",
        "after": -60,
        "format": "json2"
    })


# ── Alarms / Alerts ──────────────────────────────────────────────

@router.get("/alerts")
async def alerts():
    """Alerts for dashboard (public)."""
    try:
        data = await _nd("/api/v1/alarms")
        alerts_list = []
        alarms_dict = data.get("alarms", {}) if isinstance(data, dict) else {}
        for name, alarm in alarms_dict.items():
            if isinstance(alarm, dict) and alarm.get("status", "").upper() != "OK":
                severity = "critical" if alarm.get("status", "").upper() == "CRITICAL" else "warning"
                alerts_list.append({
                    "type": alarm.get("name", name),
                    "severity": severity,
                    "message": alarm.get("info", alarm.get("value_string", "Alert triggered"))
                })
        return {"alerts": alerts_list}
    except Exception as e:
        log.warning("alerts: %s", e)
        return {"alerts": []}


@router.get("/alarms")
async def alarms(user=Depends(require_jwt)):
    return await _nd("/api/v1/alarms")


@router.get("/netdata_alarms")
async def netdata_alarms(user=Depends(require_jwt)):
    """Alias for alarms."""
    return await alarms(user)


# ── Service control ───────────────────────────────────────────────

@router.post("/restart_netdata")
async def restart_netdata(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "restart", "netdata"], capture_output=True, text=True, timeout=30)
    log.info("restart_netdata: %s", r.returncode)
    return {"success": r.returncode == 0, "output": r.stderr[:200]}


@router.post("/start_netdata")
async def start_netdata(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "start", "netdata"], capture_output=True, text=True, timeout=15)
    return {"success": r.returncode == 0, "output": r.stderr[:200]}


@router.post("/stop_netdata")
async def stop_netdata(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "stop", "netdata"], capture_output=True, text=True, timeout=15)
    return {"success": r.returncode == 0, "output": r.stderr[:200]}


# ── Logs & Debug ──────────────────────────────────────────────────

@router.get("/secubox_logs")
async def secubox_logs(lines: int = Query(100, ge=1, le=1000), user=Depends(require_jwt)):
    """Dernières lignes du log Netdata."""
    r = subprocess.run(
        ["journalctl", "-u", "netdata", "-n", str(lines), "--no-pager"],
        capture_output=True, text=True, timeout=10
    )
    return {"lines": r.stdout.splitlines()}


@router.get("/collect_debug")
async def collect_debug(user=Depends(require_jwt)):
    """Collecte d'informations de debug."""
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
    return debug_info


@router.get("/health")
async def health():
    return {"status": "ok", "module": "netdata"}


app.include_router(router)
