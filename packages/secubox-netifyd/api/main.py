"""SecuBox Netifyd - Network Intelligence Daemon Management
Deep Packet Inspection with netifyd for network flow analysis,
protocol detection, application classification, and device discovery.

netifyd communicates via Unix socket with JSON-RPC style messages.
This module provides a REST API wrapper for the web dashboard.
"""
import os
import json
import time
import socket
import asyncio
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from collections import defaultdict

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

# Configuration
CONFIG_PATH = Path("/etc/secubox/netifyd.toml")
DATA_DIR = Path("/var/lib/secubox/netifyd")
CACHE_FILE = DATA_DIR / "stats_cache.json"
ALERTS_FILE = DATA_DIR / "alerts.json"
NETIFYD_SOCKET = Path("/run/netifyd/netifyd.sock")

app = FastAPI(title="SecuBox Netifyd", version="1.0.0", root_path="/api/v1/netifyd")
log = get_logger("netifyd")


# =============================================================================
# Pydantic Models
# =============================================================================

class NetifydStatus(BaseModel):
    """netifyd daemon status."""
    running: bool
    version: str = ""
    uptime_seconds: int = 0
    interface: str = ""
    mode: str = ""
    socket_available: bool = False


class FlowInfo(BaseModel):
    """Network flow information."""
    flow_id: str
    local_ip: str
    local_port: int
    other_ip: str
    other_port: int
    protocol: str
    detected_application_name: str = "unknown"
    detected_protocol_name: str = "unknown"
    bytes: int = 0
    packets: int = 0
    local_mac: str = ""
    other_mac: str = ""
    first_seen: str = ""
    last_seen: str = ""


class ProtocolStats(BaseModel):
    """Protocol statistics."""
    name: str
    flow_count: int
    bytes_total: int


class ApplicationStats(BaseModel):
    """Application statistics."""
    name: str
    category: str = ""
    flow_count: int
    bytes_total: int


class HostInfo(BaseModel):
    """Host/device information."""
    mac: str
    ip: str = ""
    hostname: str = ""
    vendor: str = ""
    first_seen: str = ""
    last_seen: str = ""
    bytes_total: int = 0
    flow_count: int = 0


class AlertInfo(BaseModel):
    """DPI alert information."""
    id: str
    timestamp: str
    severity: str
    type: str
    message: str
    source_ip: str = ""
    destination_ip: str = ""
    dismissed: bool = False


class NetifydConfig(BaseModel):
    """netifyd configuration."""
    interface: str = "eth0"
    listen_address: str = "127.0.0.1"
    listen_port: int = 7150
    enable_socket: bool = True
    enable_sink: bool = False
    sink_url: str = ""
    update_interval: int = 60


# =============================================================================
# Netifyd Client
# =============================================================================

class NetifydClient:
    """Client for communicating with netifyd daemon."""

    def __init__(self, socket_path: Path = NETIFYD_SOCKET):
        self.socket_path = socket_path
        self._cache: Dict[str, Any] = {}
        self._cache_time = 0
        self._cache_ttl = 5  # seconds

    def is_available(self) -> bool:
        """Check if netifyd socket is available."""
        return self.socket_path.exists()

    def _send_command(self, cmd: dict, timeout: float = 5.0) -> dict:
        """Send JSON command to netifyd socket."""
        if not self.is_available():
            return {"error": "netifyd socket not available"}

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(str(self.socket_path))
                sock.sendall((json.dumps(cmd) + "\n").encode())

                data = b""
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    data += chunk
                    if data.endswith(b"\n"):
                        break

                return json.loads(data.decode()) if data else {}
        except socket.timeout:
            return {"error": "Socket timeout"}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON response"}
        except Exception as e:
            log.warning("netifyd command error: %s", e)
            return {"error": str(e)}

    def get_status(self) -> dict:
        """Get netifyd daemon status."""
        # Check if process is running
        result = subprocess.run(["pgrep", "-x", "netifyd"], capture_output=True)
        netifyd_running = result.returncode == 0

        version = ""
        if netifyd_running:
            try:
                ver_result = subprocess.run(
                    ["netifyd", "--version"],
                    capture_output=True, text=True, timeout=5
                )
                if ver_result.returncode == 0:
                    version = ver_result.stdout.strip().split('\n')[0]
            except Exception:
                pass

        return {
            "running": netifyd_running,
            "version": version,
            "socket_available": self.is_available(),
        }

    def get_flows(self) -> List[dict]:
        """Get current network flows."""
        now = time.time()
        if now - self._cache_time < self._cache_ttl and "flows" in self._cache:
            return self._cache.get("flows", [])

        response = self._send_command({"type": "get_flows"})
        flows = response.get("flows", [])

        self._cache["flows"] = flows
        self._cache_time = now
        return flows

    def get_applications(self) -> List[dict]:
        """Get detected applications."""
        response = self._send_command({"type": "get_applications"})
        return response.get("applications", [])

    def get_protocols(self) -> List[dict]:
        """Get detected protocols."""
        response = self._send_command({"type": "get_protocols"})
        return response.get("protocols", [])

    def get_devices(self) -> List[dict]:
        """Get discovered devices."""
        response = self._send_command({"type": "get_devices"})
        return response.get("devices", [])

    def get_stats(self) -> dict:
        """Get daemon statistics."""
        response = self._send_command({"type": "get_stats"})
        return response if "error" not in response else {}

    def get_risks(self) -> List[dict]:
        """Get detected risks/alerts."""
        response = self._send_command({"type": "get_risks"})
        return response.get("risks", [])

    def get_top_talkers(self) -> List[dict]:
        """Get top bandwidth consumers."""
        response = self._send_command({"type": "get_top_talkers"})
        return response.get("top_talkers", [])


# Global client instance
netifyd_client = NetifydClient()


# =============================================================================
# Alert Management
# =============================================================================

def load_alerts() -> List[dict]:
    """Load alerts from file."""
    if ALERTS_FILE.exists():
        try:
            return json.loads(ALERTS_FILE.read_text())
        except Exception:
            pass
    return []


def save_alerts(alerts: List[dict]):
    """Save alerts to file."""
    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    ALERTS_FILE.write_text(json.dumps(alerts, indent=2))


def add_alert(severity: str, alert_type: str, message: str,
              source_ip: str = "", destination_ip: str = ""):
    """Add a new alert."""
    alerts = load_alerts()
    alert = {
        "id": f"alert_{int(time.time() * 1000)}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": severity,
        "type": alert_type,
        "message": message,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "dismissed": False,
    }
    alerts.insert(0, alert)
    # Keep only last 500 alerts
    alerts = alerts[:500]
    save_alerts(alerts)
    return alert


# =============================================================================
# Statistics Cache
# =============================================================================

_stats_cache: Dict[str, Any] = {}
_stats_task: Optional[asyncio.Task] = None


async def refresh_stats_cache():
    """Background task to refresh stats cache."""
    global _stats_cache
    while True:
        try:
            cfg = get_config("netifyd")
            interface = cfg.get("interface", "eth0")

            # Get interface statistics
            stats_path = Path(f"/sys/class/net/{interface}/statistics")
            if stats_path.exists():
                rx_bytes = int((stats_path / "rx_bytes").read_text().strip())
                tx_bytes = int((stats_path / "tx_bytes").read_text().strip())
                rx_packets = int((stats_path / "rx_packets").read_text().strip())
                tx_packets = int((stats_path / "tx_packets").read_text().strip())
            else:
                rx_bytes = tx_bytes = rx_packets = tx_packets = 0

            # Get flows and aggregate
            flows = netifyd_client.get_flows()

            # Aggregate by application
            app_traffic = defaultdict(lambda: {"bytes": 0, "flows": 0})
            for f in flows:
                app = f.get("detected_application_name", "unknown")
                app_traffic[app]["bytes"] += f.get("bytes", 0)
                app_traffic[app]["flows"] += 1

            # Aggregate by protocol
            proto_traffic = defaultdict(lambda: {"bytes": 0, "flows": 0})
            for f in flows:
                proto = f.get("detected_protocol_name", "unknown")
                proto_traffic[proto]["bytes"] += f.get("bytes", 0)
                proto_traffic[proto]["flows"] += 1

            # Aggregate by device (MAC)
            device_traffic = defaultdict(lambda: {"bytes": 0, "flows": 0})
            for f in flows:
                mac = f.get("local_mac", "unknown")
                device_traffic[mac]["bytes"] += f.get("bytes", 0)
                device_traffic[mac]["flows"] += 1

            # Sort and get top entries
            top_apps = sorted(app_traffic.items(), key=lambda x: -x[1]["bytes"])[:20]
            top_protos = sorted(proto_traffic.items(), key=lambda x: -x[1]["bytes"])[:20]
            top_devices = sorted(device_traffic.items(), key=lambda x: -x[1]["bytes"])[:20]

            _stats_cache = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "interface": interface,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "rx_packets": rx_packets,
                "tx_packets": tx_packets,
                "active_flows": len(flows),
                "top_applications": [{"name": a, **d} for a, d in top_apps],
                "top_protocols": [{"name": p, **d} for p, d in top_protos],
                "top_devices": [{"mac": m, **d} for m, d in top_devices],
                "unique_apps": len(app_traffic),
                "unique_protocols": len(proto_traffic),
                "unique_devices": len(device_traffic),
            }

            # Save cache to disk
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps(_stats_cache, indent=2))

        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error(f"Stats cache refresh error: {e}")

        await asyncio.sleep(60)


# =============================================================================
# API Endpoints - Health & Status
# =============================================================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "module": "netifyd", "version": "1.0.0"}


@app.get("/status")
async def get_status():
    """Get netifyd daemon status."""
    status = netifyd_client.get_status()
    cfg = get_config("netifyd")

    return {
        "running": status.get("running", False),
        "version": status.get("version", ""),
        "socket_available": status.get("socket_available", False),
        "interface": cfg.get("interface", "eth0"),
        "mode": cfg.get("mode", "inline"),
    }


# =============================================================================
# API Endpoints - Service Control
# =============================================================================

@app.post("/start", dependencies=[Depends(require_jwt)])
async def start_service():
    """Start netifyd daemon."""
    result = subprocess.run(
        ["systemctl", "start", "netifyd"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log.error(f"Failed to start netifyd: {result.stderr}")
        raise HTTPException(status_code=500, detail=result.stderr)
    log.info("netifyd started")
    return {"success": True, "message": "netifyd started"}


@app.post("/stop", dependencies=[Depends(require_jwt)])
async def stop_service():
    """Stop netifyd daemon."""
    result = subprocess.run(
        ["systemctl", "stop", "netifyd"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log.error(f"Failed to stop netifyd: {result.stderr}")
        raise HTTPException(status_code=500, detail=result.stderr)
    log.info("netifyd stopped")
    return {"success": True, "message": "netifyd stopped"}


@app.post("/restart", dependencies=[Depends(require_jwt)])
async def restart_service():
    """Restart netifyd daemon."""
    result = subprocess.run(
        ["systemctl", "restart", "netifyd"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log.error(f"Failed to restart netifyd: {result.stderr}")
        raise HTTPException(status_code=500, detail=result.stderr)
    log.info("netifyd restarted")
    return {"success": True, "message": "netifyd restarted"}


# =============================================================================
# API Endpoints - Configuration
# =============================================================================

@app.get("/config", dependencies=[Depends(require_jwt)])
async def get_config_endpoint():
    """Get current netifyd configuration."""
    cfg = get_config("netifyd")
    return {
        "interface": cfg.get("interface", "eth0"),
        "listen_address": cfg.get("listen_address", "127.0.0.1"),
        "listen_port": cfg.get("listen_port", 7150),
        "enable_socket": cfg.get("enable_socket", True),
        "enable_sink": cfg.get("enable_sink", False),
        "sink_url": cfg.get("sink_url", ""),
        "update_interval": cfg.get("update_interval", 60),
    }


@app.post("/config", dependencies=[Depends(require_jwt)])
async def save_config_endpoint(config: NetifydConfig):
    """Update netifyd configuration."""
    config_file = Path("/etc/secubox/netifyd.json")
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text(json.dumps(config.model_dump(), indent=2))
    log.info("netifyd configuration saved")
    return {"success": True, "message": "Configuration saved"}


# =============================================================================
# API Endpoints - Flows
# =============================================================================

@app.get("/flows", dependencies=[Depends(require_jwt)])
async def get_flows(limit: int = 100):
    """Get active network flows."""
    flows = netifyd_client.get_flows()
    return {
        "flows": flows[:limit],
        "total": len(flows),
    }


@app.get("/flows/top", dependencies=[Depends(require_jwt)])
async def get_top_flows(limit: int = 20):
    """Get top flows by bandwidth."""
    flows = netifyd_client.get_flows()

    # Sort by bytes descending
    sorted_flows = sorted(flows, key=lambda x: x.get("bytes", 0), reverse=True)

    return {
        "flows": sorted_flows[:limit],
        "total": len(flows),
    }


# =============================================================================
# API Endpoints - Protocols & Applications
# =============================================================================

@app.get("/protocols", dependencies=[Depends(require_jwt)])
async def get_protocols():
    """Get detected protocols list."""
    protocols = netifyd_client.get_protocols()
    if not protocols:
        # Aggregate from flows if direct API not available
        flows = netifyd_client.get_flows()
        proto_stats = defaultdict(lambda: {"count": 0, "bytes": 0})
        for f in flows:
            proto = f.get("detected_protocol_name", "unknown")
            proto_stats[proto]["count"] += 1
            proto_stats[proto]["bytes"] += f.get("bytes", 0)
        protocols = [
            {"name": p, "flow_count": s["count"], "bytes_total": s["bytes"]}
            for p, s in sorted(proto_stats.items(), key=lambda x: -x[1]["bytes"])
        ]
    return {"protocols": protocols}


@app.get("/applications", dependencies=[Depends(require_jwt)])
async def get_applications():
    """Get detected applications list."""
    applications = netifyd_client.get_applications()
    if not applications:
        # Aggregate from flows if direct API not available
        flows = netifyd_client.get_flows()
        app_stats = defaultdict(lambda: {"count": 0, "bytes": 0})
        for f in flows:
            app = f.get("detected_application_name", "unknown")
            app_stats[app]["count"] += 1
            app_stats[app]["bytes"] += f.get("bytes", 0)
        applications = [
            {"name": a, "flow_count": s["count"], "bytes_total": s["bytes"]}
            for a, s in sorted(app_stats.items(), key=lambda x: -x[1]["bytes"])
        ]
    return {"applications": applications}


# =============================================================================
# API Endpoints - Hosts/Devices
# =============================================================================

@app.get("/hosts", dependencies=[Depends(require_jwt)])
async def get_hosts():
    """Get known hosts/devices."""
    devices = netifyd_client.get_devices()
    if not devices:
        # Aggregate from flows if direct API not available
        flows = netifyd_client.get_flows()
        host_stats = {}
        for f in flows:
            mac = f.get("local_mac", "")
            if not mac or mac == "unknown":
                continue
            if mac not in host_stats:
                host_stats[mac] = {
                    "mac": mac,
                    "ip": f.get("local_ip", ""),
                    "hostname": "",
                    "vendor": "",
                    "bytes_total": 0,
                    "flow_count": 0,
                }
            host_stats[mac]["bytes_total"] += f.get("bytes", 0)
            host_stats[mac]["flow_count"] += 1
        devices = list(host_stats.values())
    return {"hosts": sorted(devices, key=lambda x: -x.get("bytes_total", 0))}


# =============================================================================
# API Endpoints - Statistics
# =============================================================================

@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get traffic statistics."""
    if _stats_cache:
        return _stats_cache

    # Fallback if cache not ready
    daemon_stats = netifyd_client.get_stats()
    return {
        "daemon_stats": daemon_stats,
        "cache_ready": False,
    }


@app.get("/stats/realtime", dependencies=[Depends(require_jwt)])
async def get_realtime_stats():
    """Get real-time interface statistics."""
    cfg = get_config("netifyd")
    interface = cfg.get("interface", "eth0")

    stats_path = Path(f"/sys/class/net/{interface}/statistics")
    if not stats_path.exists():
        raise HTTPException(status_code=404, detail=f"Interface {interface} not found")

    return {
        "interface": interface,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "rx_bytes": int((stats_path / "rx_bytes").read_text().strip()),
        "tx_bytes": int((stats_path / "tx_bytes").read_text().strip()),
        "rx_packets": int((stats_path / "rx_packets").read_text().strip()),
        "tx_packets": int((stats_path / "tx_packets").read_text().strip()),
        "rx_errors": int((stats_path / "rx_errors").read_text().strip()),
        "tx_errors": int((stats_path / "tx_errors").read_text().strip()),
        "rx_dropped": int((stats_path / "rx_dropped").read_text().strip()),
        "tx_dropped": int((stats_path / "tx_dropped").read_text().strip()),
    }


# =============================================================================
# API Endpoints - Alerts
# =============================================================================

@app.get("/alerts", dependencies=[Depends(require_jwt)])
async def get_alerts(include_dismissed: bool = False, limit: int = 100):
    """Get DPI alerts."""
    alerts = load_alerts()
    if not include_dismissed:
        alerts = [a for a in alerts if not a.get("dismissed", False)]
    return {"alerts": alerts[:limit], "total": len(alerts)}


@app.post("/alerts/dismiss", dependencies=[Depends(require_jwt)])
async def dismiss_alert(alert_id: str):
    """Dismiss an alert."""
    alerts = load_alerts()
    for alert in alerts:
        if alert.get("id") == alert_id:
            alert["dismissed"] = True
            save_alerts(alerts)
            return {"success": True, "message": "Alert dismissed"}
    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/alerts/dismiss_all", dependencies=[Depends(require_jwt)])
async def dismiss_all_alerts():
    """Dismiss all alerts."""
    alerts = load_alerts()
    for alert in alerts:
        alert["dismissed"] = True
    save_alerts(alerts)
    return {"success": True, "message": "All alerts dismissed"}


@app.delete("/alerts/clear", dependencies=[Depends(require_jwt)])
async def clear_alerts():
    """Clear all dismissed alerts."""
    alerts = load_alerts()
    alerts = [a for a in alerts if not a.get("dismissed", False)]
    save_alerts(alerts)
    return {"success": True, "message": "Dismissed alerts cleared"}


# =============================================================================
# API Endpoints - Logs
# =============================================================================

@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = 100):
    """Get recent netifyd logs."""
    try:
        result = subprocess.run(
            ["journalctl", "-u", "netifyd", "-n", str(lines), "--no-pager", "-o", "short-iso"],
            capture_output=True, text=True, timeout=10
        )
        return {"lines": result.stdout.splitlines()}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Log retrieval timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# API Endpoints - Interfaces
# =============================================================================

@app.get("/interfaces", dependencies=[Depends(require_jwt)])
async def list_interfaces():
    """List available network interfaces."""
    result = subprocess.run(["ip", "-j", "link", "show"], capture_output=True, text=True)
    try:
        links = json.loads(result.stdout)
        return {
            "interfaces": [
                {
                    "name": l.get("ifname"),
                    "state": l.get("operstate", "unknown"),
                    "mtu": l.get("mtu", 1500),
                }
                for l in links if l.get("ifname") != "lo"
            ]
        }
    except Exception:
        return {"interfaces": []}


# =============================================================================
# API Endpoints - Three-fold Architecture
# =============================================================================

@app.get("/module/info")
async def get_module_info():
    """Get module information (three-fold architecture)."""
    return {
        "id": "netifyd",
        "name": "Netifyd DPI",
        "version": "1.0.0",
        "description": "Network Intelligence Daemon for Deep Packet Inspection",
        "category": "network",
        "dependencies": ["secubox-core"],
        "provides": ["dpi", "network-monitoring", "application-detection"],
    }


@app.get("/module/health")
async def get_module_health():
    """Get module health status (three-fold architecture)."""
    status = netifyd_client.get_status()
    return {
        "healthy": status.get("running", False),
        "checks": {
            "daemon": status.get("running", False),
            "socket": status.get("socket_available", False),
            "api": True,
        },
        "details": {
            "version": status.get("version", "unknown"),
        }
    }


@app.get("/module/capabilities")
async def get_module_capabilities():
    """Get module capabilities (three-fold architecture)."""
    return {
        "features": [
            "flow-analysis",
            "protocol-detection",
            "application-classification",
            "device-discovery",
            "bandwidth-monitoring",
            "real-time-stats",
        ],
        "api_version": "1.0",
        "socket_path": str(NETIFYD_SOCKET),
    }


# =============================================================================
# Export Endpoints
# =============================================================================

@app.get("/export/flows", dependencies=[Depends(require_jwt)])
async def export_flows(format: str = "json"):
    """Export current flows."""
    flows = netifyd_client.get_flows()

    if format == "csv":
        lines = ["timestamp,local_ip,local_port,other_ip,other_port,protocol,application,bytes"]
        for f in flows:
            lines.append(
                f"{f.get('last_seen', '')},"
                f"{f.get('local_ip', '')},"
                f"{f.get('local_port', '')},"
                f"{f.get('other_ip', '')},"
                f"{f.get('other_port', '')},"
                f"{f.get('detected_protocol_name', '')},"
                f"{f.get('detected_application_name', '')},"
                f"{f.get('bytes', 0)}"
            )
        return {"format": "csv", "data": "\n".join(lines)}

    return {"format": "json", "data": flows}


# =============================================================================
# Startup / Shutdown
# =============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    global _stats_task
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _stats_task = asyncio.create_task(refresh_stats_cache())
    log.info("Netifyd module started with stats caching")


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
    log.info("Netifyd module stopped")
