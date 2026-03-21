"""
secubox_core.system — Helpers système pour SecuBox
===================================================
- board_info()       → Infos hardware/board
- uptime()           → Uptime du système
- service_status()   → État des services systemd
- disk_usage()       → Usage disque
"""
from __future__ import annotations
import os
import subprocess
from pathlib import Path
from typing import Literal

from .logger import get_logger

log = get_logger("system")


def board_info() -> dict:
    """
    Retourne les infos hardware du board courant.
    Lit /proc/device-tree/model (DTS node name sur ARM).
    """
    from .config import get_config

    model = "unknown"
    model_path = Path("/proc/device-tree/model")
    if model_path.exists():
        model = model_path.read_text(errors="replace").strip().rstrip("\x00")

    # CPU / RAM
    cpu_count = os.cpu_count() or 1
    mem = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":")
            mem[k.strip()] = int(v.strip().split()[0])  # kB
    except Exception:
        pass

    return {
        "model":        model,
        "board":        get_config("global").get("board", "unknown"),
        "hostname":     get_config("global").get("hostname", "secubox"),
        "cpu_count":    cpu_count,
        "mem_total_mb": mem.get("MemTotal", 0) // 1024,
        "mem_free_mb":  mem.get("MemAvailable", 0) // 1024,
    }


def uptime() -> dict:
    """
    Retourne l'uptime système.
    """
    uptime_sec = 0.0
    try:
        uptime_sec = float(Path("/proc/uptime").read_text().split()[0])
    except Exception:
        pass

    days = int(uptime_sec // 86400)
    hours = int((uptime_sec % 86400) // 3600)
    minutes = int((uptime_sec % 3600) // 60)

    return {
        "seconds": int(uptime_sec),
        "days": days,
        "hours": hours,
        "minutes": minutes,
        "human": f"{days}d {hours}h {minutes}m",
    }


def service_status(service: str) -> dict:
    """
    Retourne l'état d'un service systemd.

    Args:
        service: Nom du service (ex: "secubox-crowdsec", "nginx")

    Returns:
        {"name": "...", "running": bool, "enabled": bool, "status": "active|inactive|failed"}
    """
    result = {
        "name": service,
        "running": False,
        "enabled": False,
        "status": "unknown",
    }

    # is-active
    try:
        r = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True,
            text=True,
            timeout=5,
        )
        status_str = r.stdout.strip()
        result["status"] = status_str
        result["running"] = status_str == "active"
    except Exception as e:
        log.warning("systemctl is-active %s: %s", service, e)

    # is-enabled
    try:
        r = subprocess.run(
            ["systemctl", "is-enabled", service],
            capture_output=True,
            text=True,
            timeout=5,
        )
        result["enabled"] = r.stdout.strip() == "enabled"
    except Exception as e:
        log.warning("systemctl is-enabled %s: %s", service, e)

    return result


def service_control(
    service: str,
    action: Literal["start", "stop", "restart", "reload"],
) -> dict:
    """
    Contrôle un service systemd.

    Args:
        service: Nom du service
        action: start, stop, restart, ou reload

    Returns:
        {"success": bool, "output": str, "returncode": int}
    """
    if action not in ("start", "stop", "restart", "reload"):
        return {"success": False, "output": f"Action invalide: {action}", "returncode": -1}

    try:
        r = subprocess.run(
            ["systemctl", action, service],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "success": r.returncode == 0,
            "output": r.stderr.strip() or r.stdout.strip(),
            "returncode": r.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "output": "Timeout", "returncode": -1}
    except Exception as e:
        return {"success": False, "output": str(e), "returncode": -1}


def disk_usage(path: str = "/") -> dict:
    """
    Retourne l'usage disque d'un point de montage.
    """
    try:
        st = os.statvfs(path)
        total = st.f_blocks * st.f_frsize
        free = st.f_bfree * st.f_frsize
        used = total - free
        pct = (used / total * 100) if total > 0 else 0

        return {
            "path": path,
            "total_mb": total // (1024 * 1024),
            "used_mb": used // (1024 * 1024),
            "free_mb": free // (1024 * 1024),
            "percent_used": round(pct, 1),
        }
    except Exception as e:
        log.warning("disk_usage %s: %s", path, e)
        return {"path": path, "error": str(e)}


def load_average() -> dict:
    """
    Retourne le load average (1, 5, 15 minutes).
    """
    try:
        load1, load5, load15 = os.getloadavg()
        return {
            "load_1min": round(load1, 2),
            "load_5min": round(load5, 2),
            "load_15min": round(load15, 2),
        }
    except Exception:
        return {"load_1min": 0.0, "load_5min": 0.0, "load_15min": 0.0}
