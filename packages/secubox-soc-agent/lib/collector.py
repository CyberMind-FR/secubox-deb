"""
SecuBox-Deb :: SOC Agent Collector
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Collects local system metrics, service status, and security alerts.
"""

import subprocess
import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger("secubox.soc-agent.collector")

# Paths
CROWDSEC_ALERTS_CMD = ["cscli", "alerts", "list", "-l", "50", "-o", "json"]
SURICATA_EVE_LOG = Path("/var/log/suricata/eve.json")
WAF_ALERTS_DIR = Path("/var/log/secubox/waf")
NETDATA_SOCK = Path("/run/netdata/netdata.sock")

# Cache for expensive operations
_alert_cache: Dict[str, Any] = {}
_cache_time: float = 0
CACHE_TTL = 30  # seconds


def run_cmd(cmd: List[str], timeout: int = 10) -> tuple:
    """Run command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except FileNotFoundError:
        return False, "", "Command not found"
    except Exception as e:
        return False, "", str(e)


def get_hostname() -> str:
    """Get system hostname."""
    try:
        return subprocess.check_output(["hostname"], text=True).strip()
    except Exception:
        return "unknown"


def get_machine_id() -> str:
    """Get unique machine identifier."""
    machine_id_file = Path("/etc/machine-id")
    if machine_id_file.exists():
        return machine_id_file.read_text().strip()[:16]
    return get_hostname()[:16]


def get_cpu_usage() -> float:
    """Get current CPU usage percentage."""
    try:
        with open("/proc/stat", "r") as f:
            line = f.readline()
        values = line.split()[1:8]
        idle = int(values[3])
        total = sum(int(v) for v in values)

        # Get previous values from cache
        prev = _alert_cache.get("_cpu_prev")
        _alert_cache["_cpu_prev"] = (idle, total)

        if prev:
            prev_idle, prev_total = prev
            idle_delta = idle - prev_idle
            total_delta = total - prev_total
            if total_delta > 0:
                return round(100 * (1 - idle_delta / total_delta), 1)
        return 0.0
    except Exception:
        return 0.0


def get_memory_usage() -> Dict[str, Any]:
    """Get memory usage statistics."""
    try:
        with open("/proc/meminfo", "r") as f:
            lines = f.readlines()

        info = {}
        for line in lines:
            parts = line.split()
            key = parts[0].rstrip(":")
            value = int(parts[1])
            info[key] = value

        total = info.get("MemTotal", 0)
        available = info.get("MemAvailable", 0)
        used = total - available

        return {
            "total_mb": round(total / 1024),
            "used_mb": round(used / 1024),
            "available_mb": round(available / 1024),
            "percent": round(100 * used / total, 1) if total > 0 else 0
        }
    except Exception:
        return {"total_mb": 0, "used_mb": 0, "available_mb": 0, "percent": 0}


def get_disk_usage(path: str = "/") -> Dict[str, Any]:
    """Get disk usage for given path."""
    try:
        import os
        stat = os.statvfs(path)
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        used = total - free

        return {
            "total_gb": round(total / (1024**3), 1),
            "used_gb": round(used / (1024**3), 1),
            "free_gb": round(free / (1024**3), 1),
            "percent": round(100 * used / total, 1) if total > 0 else 0
        }
    except Exception:
        return {"total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0}


def get_uptime() -> int:
    """Get system uptime in seconds."""
    try:
        with open("/proc/uptime", "r") as f:
            return int(float(f.readline().split()[0]))
    except Exception:
        return 0


def get_load_average() -> Dict[str, float]:
    """Get system load average."""
    try:
        with open("/proc/loadavg", "r") as f:
            parts = f.readline().split()
        return {
            "1min": float(parts[0]),
            "5min": float(parts[1]),
            "15min": float(parts[2])
        }
    except Exception:
        return {"1min": 0.0, "5min": 0.0, "15min": 0.0}


def get_services_status() -> List[Dict[str, Any]]:
    """Get status of key SecuBox services."""
    services = [
        "nginx", "haproxy", "crowdsec", "suricata",
        "secubox-hub", "secubox-watchdog", "netdata"
    ]

    results = []
    for service in services:
        success, out, _ = run_cmd(
            ["systemctl", "is-active", service], timeout=5
        )
        status = out.strip() if success else "unknown"

        results.append({
            "name": service,
            "status": status,
            "running": status == "active"
        })

    return results


def get_crowdsec_alerts(limit: int = 20) -> List[Dict[str, Any]]:
    """Get recent CrowdSec alerts."""
    try:
        success, out, _ = run_cmd(
            ["cscli", "alerts", "list", "-l", str(limit), "-o", "json"],
            timeout=15
        )
        if success and out.strip():
            alerts = json.loads(out)
            return [{
                "id": a.get("id"),
                "source": "crowdsec",
                "ip": a.get("source", {}).get("ip"),
                "scenario": a.get("scenario"),
                "created_at": a.get("created_at"),
                "severity": "high" if "brute" in a.get("scenario", "") else "medium"
            } for a in alerts[:limit]]
    except Exception as e:
        logger.warning(f"Failed to get CrowdSec alerts: {e}")
    return []


def get_suricata_alerts(limit: int = 20) -> List[Dict[str, Any]]:
    """Get recent Suricata alerts from eve.json."""
    alerts = []
    try:
        if not SURICATA_EVE_LOG.exists():
            return []

        # Read last N lines
        success, out, _ = run_cmd(
            ["tail", "-n", "500", str(SURICATA_EVE_LOG)],
            timeout=5
        )
        if not success:
            return []

        for line in out.strip().split("\n"):
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alerts.append({
                        "source": "suricata",
                        "ip": event.get("src_ip"),
                        "dest_ip": event.get("dest_ip"),
                        "signature": event.get("alert", {}).get("signature"),
                        "category": event.get("alert", {}).get("category"),
                        "severity": event.get("alert", {}).get("severity", 3),
                        "timestamp": event.get("timestamp")
                    })
            except json.JSONDecodeError:
                continue

        return alerts[-limit:]
    except Exception as e:
        logger.warning(f"Failed to get Suricata alerts: {e}")
    return []


def get_waf_alerts(limit: int = 20) -> List[Dict[str, Any]]:
    """Get recent WAF alerts."""
    alerts = []
    try:
        waf_log = WAF_ALERTS_DIR / "alerts.json"
        if not waf_log.exists():
            return []

        with open(waf_log, "r") as f:
            for line in f.readlines()[-limit:]:
                try:
                    alert = json.loads(line)
                    alerts.append({
                        "source": "waf",
                        "ip": alert.get("client_ip"),
                        "rule_id": alert.get("rule_id"),
                        "action": alert.get("action"),
                        "timestamp": alert.get("timestamp")
                    })
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.warning(f"Failed to get WAF alerts: {e}")
    return alerts


def get_network_stats() -> Dict[str, Any]:
    """Get network interface statistics."""
    interfaces = {}
    try:
        net_dev = Path("/proc/net/dev")
        if not net_dev.exists():
            return interfaces

        with open(net_dev, "r") as f:
            lines = f.readlines()[2:]  # Skip headers

        for line in lines:
            parts = line.split()
            iface = parts[0].rstrip(":")
            if iface in ("lo", "docker0") or iface.startswith("veth"):
                continue

            interfaces[iface] = {
                "rx_bytes": int(parts[1]),
                "rx_packets": int(parts[2]),
                "tx_bytes": int(parts[9]),
                "tx_packets": int(parts[10])
            }
    except Exception as e:
        logger.warning(f"Failed to get network stats: {e}")
    return interfaces


def calculate_health_score(
    cpu: float, mem: Dict, disk: Dict, services: List[Dict]
) -> str:
    """Calculate overall health score."""
    score = 100

    # CPU penalty
    if cpu > 90:
        score -= 30
    elif cpu > 75:
        score -= 15
    elif cpu > 50:
        score -= 5

    # Memory penalty
    mem_pct = mem.get("percent", 0)
    if mem_pct > 90:
        score -= 30
    elif mem_pct > 75:
        score -= 15
    elif mem_pct > 50:
        score -= 5

    # Disk penalty
    disk_pct = disk.get("percent", 0)
    if disk_pct > 95:
        score -= 40
    elif disk_pct > 85:
        score -= 20
    elif disk_pct > 75:
        score -= 10

    # Service penalty
    critical_services = {"nginx", "haproxy", "crowdsec"}
    for svc in services:
        if not svc.get("running"):
            if svc["name"] in critical_services:
                score -= 20
            else:
                score -= 5

    if score >= 80:
        return "healthy"
    elif score >= 50:
        return "degraded"
    else:
        return "critical"


async def collect_metrics() -> Dict[str, Any]:
    """Collect all system metrics for SOC report."""
    # Run collectors
    cpu = get_cpu_usage()
    memory = get_memory_usage()
    disk = get_disk_usage("/")
    load = get_load_average()
    uptime = get_uptime()
    services = get_services_status()
    network = get_network_stats()

    # Calculate health
    health = calculate_health_score(cpu, memory, disk, services)

    return {
        "node_id": get_machine_id(),
        "hostname": get_hostname(),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "resources": {
            "cpu": cpu,
            "memory": memory,
            "disk": disk,
            "load": load
        },
        "uptime": uptime,
        "services": services,
        "network": network,
        "health": health
    }


async def collect_alerts() -> List[Dict[str, Any]]:
    """Collect all security alerts."""
    alerts = []

    # Collect from all sources
    alerts.extend(get_crowdsec_alerts(20))
    alerts.extend(get_suricata_alerts(20))
    alerts.extend(get_waf_alerts(20))

    # Sort by timestamp (newest first)
    alerts.sort(
        key=lambda a: a.get("timestamp") or a.get("created_at") or "",
        reverse=True
    )

    return alerts[:50]  # Max 50 alerts per report


async def collect_full_report() -> Dict[str, Any]:
    """Collect complete node report for SOC."""
    metrics = await collect_metrics()
    alerts = await collect_alerts()

    return {
        **metrics,
        "alerts": alerts,
        "alert_count": len(alerts)
    }
