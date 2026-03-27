"""SecuBox nDPId - Deep Packet Inspection with nDPI
Interface with nDPId daemon for traffic classification, JA3/JA4 fingerprinting,
protocol detection, and flow analysis.

nDPId provides real-time DPI via:
- Unix socket (JSON-RPC)
- ZeroMQ publisher for flow events
- JA3/JA3S/JA4 TLS fingerprinting
- Application/protocol classification
- Risk scoring
"""
import os
import re
import json
import time
import socket
import asyncio
import logging
import sqlite3
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Set
from enum import Enum
from collections import defaultdict
from dataclasses import dataclass, asdict

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, WebSocket
from pydantic import BaseModel, Field
import zmq
import zmq.asyncio

from secubox_core.auth import require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

# Configuration
CONFIG_PATH = Path("/etc/secubox/ndpid.toml")
DATA_DIR = Path("/var/lib/secubox/ndpid")
DB_FILE = DATA_DIR / "ndpid.db"
NDPID_SOCKET = Path("/run/ndpid/ndpid.sock")
NDPID_ZMQ = "ipc:///run/ndpid/distributor.sock"

app = FastAPI(title="SecuBox nDPId", version="1.0.0", root_path="/api/v1/ndpid")
log = get_logger("ndpid")


class RiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FlowDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    LOCAL = "local"


class FlowState(str, Enum):
    NEW = "new"
    ESTABLISHED = "established"
    CLOSING = "closing"
    CLOSED = "closed"


class NDPIProtocol(BaseModel):
    """nDPI detected protocol."""
    id: int
    name: str
    category: str
    is_encrypted: bool = False
    is_cleartext: bool = False


class TLSInfo(BaseModel):
    """TLS/SSL connection information."""
    version: str
    cipher_suite: str
    server_name: Optional[str] = None
    ja3_client: Optional[str] = None
    ja3s_server: Optional[str] = None
    ja4: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_sha1: Optional[str] = None
    alpn: Optional[List[str]] = None


class FlowInfo(BaseModel):
    """Network flow information."""
    flow_id: str
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # TCP/UDP/ICMP
    l7_protocol: str  # HTTP, TLS, DNS, etc.
    application: str  # Netflix, YouTube, etc.
    category: str  # Streaming, Social, etc.
    direction: FlowDirection
    state: FlowState
    packets: int
    bytes_sent: int
    bytes_recv: int
    duration_ms: int
    risk_score: int = 0
    risk_reasons: List[str] = []
    tls: Optional[TLSInfo] = None
    http_host: Optional[str] = None
    http_url: Optional[str] = None
    dns_query: Optional[str] = None


class JA3Fingerprint(BaseModel):
    """JA3/JA3S/JA4 fingerprint."""
    fingerprint: str
    fingerprint_type: str  # ja3, ja3s, ja4
    first_seen: str
    last_seen: str
    hit_count: int
    known_app: Optional[str] = None
    threat_intel: Optional[str] = None  # Known malware, C2, etc.


class NDPIdStats(BaseModel):
    """nDPId daemon statistics."""
    running: bool
    uptime_seconds: int
    flows_active: int
    flows_total: int
    packets_processed: int
    bytes_processed: int
    protocols_detected: Dict[str, int]
    applications_detected: Dict[str, int]
    risks_detected: Dict[str, int]


class NDPIdClient:
    """Client for communicating with nDPId daemon."""

    def __init__(self, socket_path: Path = NDPID_SOCKET):
        self.socket_path = socket_path
        self._flows: Dict[str, FlowInfo] = {}
        self._ja3_cache: Dict[str, JA3Fingerprint] = {}
        self._stats = {
            "flows_total": 0,
            "packets_processed": 0,
            "bytes_processed": 0,
            "protocols": defaultdict(int),
            "applications": defaultdict(int),
            "risks": defaultdict(int),
        }

    def is_available(self) -> bool:
        """Check if nDPId socket is available."""
        return self.socket_path.exists()

    def _send_command(self, cmd: dict, timeout: float = 5.0) -> dict:
        """Send JSON command to nDPId socket."""
        if not self.is_available():
            return {"error": "nDPId socket not available"}

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

                return json.loads(data.decode())
        except socket.timeout:
            return {"error": "Socket timeout"}
        except Exception as e:
            log.warning("nDPId command error: %s", e)
            return {"error": str(e)}

    def get_status(self) -> dict:
        """Get nDPId daemon status."""
        # Check if process is running
        result = subprocess.run(["pgrep", "ndpiReader"], capture_output=True)
        ndpid_running = result.returncode == 0

        if not ndpid_running:
            result = subprocess.run(["pgrep", "ndpid"], capture_output=True)
            ndpid_running = result.returncode == 0

        return {
            "running": ndpid_running,
            "socket_available": self.is_available(),
            "zmq_endpoint": NDPID_ZMQ,
        }

    def get_flows(self, active_only: bool = True) -> List[dict]:
        """Get current flows from nDPId."""
        response = self._send_command({"jsonrpc": "2.0", "method": "get_flows", "id": 1})
        if "error" in response:
            return []

        flows = response.get("result", {}).get("flows", [])
        if active_only:
            flows = [f for f in flows if f.get("state") != "closed"]
        return flows

    def get_flow_by_id(self, flow_id: str) -> Optional[dict]:
        """Get specific flow details."""
        response = self._send_command({
            "jsonrpc": "2.0",
            "method": "get_flow",
            "params": {"flow_id": flow_id},
            "id": 1
        })
        return response.get("result")

    def get_protocols(self) -> List[dict]:
        """Get list of supported protocols."""
        response = self._send_command({"jsonrpc": "2.0", "method": "get_protocols", "id": 1})
        return response.get("result", {}).get("protocols", [])

    def get_applications(self) -> List[dict]:
        """Get detected applications."""
        response = self._send_command({"jsonrpc": "2.0", "method": "get_applications", "id": 1})
        return response.get("result", {}).get("applications", [])

    def get_risks(self) -> List[dict]:
        """Get detected risks."""
        response = self._send_command({"jsonrpc": "2.0", "method": "get_risks", "id": 1})
        return response.get("result", {}).get("risks", [])

    def get_stats(self) -> dict:
        """Get daemon statistics."""
        response = self._send_command({"jsonrpc": "2.0", "method": "get_stats", "id": 1})
        return response.get("result", {})


class FlowDatabase:
    """SQLite database for flow history and JA3 fingerprints."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Flow history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                flow_id TEXT PRIMARY KEY,
                timestamp TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                l7_protocol TEXT,
                application TEXT,
                category TEXT,
                direction TEXT,
                bytes_sent INTEGER,
                bytes_recv INTEGER,
                duration_ms INTEGER,
                risk_score INTEGER,
                ja3 TEXT,
                ja3s TEXT,
                ja4 TEXT,
                server_name TEXT
            )
        """)

        # JA3/JA4 fingerprint database
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fingerprints (
                fingerprint TEXT PRIMARY KEY,
                fingerprint_type TEXT,
                first_seen TEXT,
                last_seen TEXT,
                hit_count INTEGER DEFAULT 1,
                known_app TEXT,
                threat_intel TEXT,
                notes TEXT
            )
        """)

        # Risk events
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                flow_id TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                risk_type TEXT,
                risk_score INTEGER,
                description TEXT
            )
        """)

        # Protocol statistics (hourly aggregates)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS protocol_stats (
                hour TEXT,
                protocol TEXT,
                flow_count INTEGER,
                bytes_total INTEGER,
                PRIMARY KEY (hour, protocol)
            )
        """)

        # Application statistics (hourly aggregates)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_stats (
                hour TEXT,
                application TEXT,
                flow_count INTEGER,
                bytes_total INTEGER,
                PRIMARY KEY (hour, application)
            )
        """)

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_time ON flows(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_app ON flows(application)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risks_time ON risk_events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_fp_type ON fingerprints(fingerprint_type)")

        conn.commit()
        conn.close()

    def record_flow(self, flow: dict):
        """Record a flow to the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        tls = flow.get("tls", {}) or {}

        cursor.execute("""
            INSERT OR REPLACE INTO flows
            (flow_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
             l7_protocol, application, category, direction, bytes_sent, bytes_recv,
             duration_ms, risk_score, ja3, ja3s, ja4, server_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            flow.get("flow_id"),
            flow.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            flow.get("src_ip"),
            flow.get("src_port"),
            flow.get("dst_ip"),
            flow.get("dst_port"),
            flow.get("protocol"),
            flow.get("l7_protocol"),
            flow.get("application"),
            flow.get("category"),
            flow.get("direction"),
            flow.get("bytes_sent", 0),
            flow.get("bytes_recv", 0),
            flow.get("duration_ms", 0),
            flow.get("risk_score", 0),
            tls.get("ja3_client"),
            tls.get("ja3s_server"),
            tls.get("ja4"),
            tls.get("server_name"),
        ))

        conn.commit()
        conn.close()

    def record_fingerprint(self, fp: str, fp_type: str, known_app: str = None):
        """Record or update a JA3/JA4 fingerprint."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat() + "Z"

        cursor.execute("""
            INSERT INTO fingerprints (fingerprint, fingerprint_type, first_seen, last_seen, known_app)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                hit_count = hit_count + 1,
                last_seen = ?,
                known_app = COALESCE(known_app, ?)
        """, (fp, fp_type, now, now, known_app, now, known_app))

        conn.commit()
        conn.close()

    def record_risk(self, flow_id: str, src_ip: str, dst_ip: str,
                    risk_type: str, risk_score: int, description: str):
        """Record a risk event."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO risk_events (timestamp, flow_id, src_ip, dst_ip, risk_type, risk_score, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (datetime.utcnow().isoformat() + "Z", flow_id, src_ip, dst_ip,
              risk_type, risk_score, description))

        conn.commit()
        conn.close()

    def get_fingerprints(self, fp_type: str = None, limit: int = 100) -> List[dict]:
        """Get fingerprints from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        if fp_type:
            cursor.execute("""
                SELECT fingerprint, fingerprint_type, first_seen, last_seen, hit_count, known_app, threat_intel
                FROM fingerprints WHERE fingerprint_type = ?
                ORDER BY hit_count DESC LIMIT ?
            """, (fp_type, limit))
        else:
            cursor.execute("""
                SELECT fingerprint, fingerprint_type, first_seen, last_seen, hit_count, known_app, threat_intel
                FROM fingerprints
                ORDER BY hit_count DESC LIMIT ?
            """, (limit,))

        results = []
        for row in cursor.fetchall():
            results.append({
                "fingerprint": row[0],
                "fingerprint_type": row[1],
                "first_seen": row[2],
                "last_seen": row[3],
                "hit_count": row[4],
                "known_app": row[5],
                "threat_intel": row[6],
            })

        conn.close()
        return results

    def get_risk_events(self, hours: int = 24, limit: int = 100) -> List[dict]:
        """Get recent risk events."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"

        cursor.execute("""
            SELECT timestamp, flow_id, src_ip, dst_ip, risk_type, risk_score, description
            FROM risk_events WHERE timestamp >= ?
            ORDER BY timestamp DESC LIMIT ?
        """, (since, limit))

        results = []
        for row in cursor.fetchall():
            results.append({
                "timestamp": row[0],
                "flow_id": row[1],
                "src_ip": row[2],
                "dst_ip": row[3],
                "risk_type": row[4],
                "risk_score": row[5],
                "description": row[6],
            })

        conn.close()
        return results

    def get_top_protocols(self, hours: int = 24, limit: int = 20) -> List[dict]:
        """Get top protocols by traffic."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"

        cursor.execute("""
            SELECT l7_protocol, COUNT(*) as flow_count, SUM(bytes_sent + bytes_recv) as bytes_total
            FROM flows WHERE timestamp >= ?
            GROUP BY l7_protocol
            ORDER BY bytes_total DESC LIMIT ?
        """, (since, limit))

        results = []
        for row in cursor.fetchall():
            results.append({
                "protocol": row[0],
                "flow_count": row[1],
                "bytes_total": row[2],
            })

        conn.close()
        return results

    def get_top_applications(self, hours: int = 24, limit: int = 20) -> List[dict]:
        """Get top applications by traffic."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"

        cursor.execute("""
            SELECT application, COUNT(*) as flow_count, SUM(bytes_sent + bytes_recv) as bytes_total
            FROM flows WHERE timestamp >= ? AND application IS NOT NULL
            GROUP BY application
            ORDER BY bytes_total DESC LIMIT ?
        """, (since, limit))

        results = []
        for row in cursor.fetchall():
            results.append({
                "application": row[0],
                "flow_count": row[1],
                "bytes_total": row[2],
            })

        conn.close()
        return results

    def get_stats(self) -> dict:
        """Get database statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM flows")
        total_flows = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM fingerprints")
        total_fingerprints = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM risk_events")
        total_risks = cursor.fetchone()[0]

        # Last 24h stats
        since_24h = (datetime.utcnow() - timedelta(hours=24)).isoformat() + "Z"
        cursor.execute("SELECT COUNT(*) FROM flows WHERE timestamp >= ?", (since_24h,))
        flows_24h = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM risk_events WHERE timestamp >= ?", (since_24h,))
        risks_24h = cursor.fetchone()[0]

        conn.close()

        return {
            "total_flows": total_flows,
            "total_fingerprints": total_fingerprints,
            "total_risk_events": total_risks,
            "flows_24h": flows_24h,
            "risks_24h": risks_24h,
        }


# Known malicious JA3 fingerprints (sample - should be loaded from file)
MALICIOUS_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": "Cobalt Strike",
    "72a589da586844d7f0818ce684948eea": "Emotet",
    "51c64c77e60f3980eea90869b68c58a8": "TrickBot",
    "a0e9f5d64349fb13191bc781f81f42e1": "Metasploit",
}


# Global instances
ndpid_client = NDPIdClient()
flow_db = FlowDatabase(DB_FILE)


# ============================================================================
# Risk Scoring
# ============================================================================

def calculate_risk_score(flow: dict) -> tuple[int, List[str]]:
    """Calculate risk score for a flow."""
    score = 0
    reasons = []

    # Check for known malicious JA3
    tls = flow.get("tls", {}) or {}
    ja3 = tls.get("ja3_client")
    if ja3 and ja3 in MALICIOUS_JA3:
        score += 90
        reasons.append(f"Malicious JA3: {MALICIOUS_JA3[ja3]}")

    # Self-signed or missing certificate
    if tls.get("self_signed"):
        score += 30
        reasons.append("Self-signed certificate")

    # Non-standard TLS port
    if flow.get("l7_protocol") == "TLS" and flow.get("dst_port") not in [443, 8443, 993, 995, 465]:
        score += 20
        reasons.append(f"TLS on non-standard port {flow.get('dst_port')}")

    # Check for known risky categories
    risky_categories = ["Malware", "Phishing", "CnC", "Mining", "Gambling"]
    if flow.get("category") in risky_categories:
        score += 50
        reasons.append(f"Risky category: {flow.get('category')}")

    # Very long flows (potential C2)
    duration = flow.get("duration_ms", 0)
    if duration > 3600000:  # > 1 hour
        score += 10
        reasons.append("Long-lived connection")

    # Low traffic but persistent (beaconing pattern)
    bytes_total = flow.get("bytes_sent", 0) + flow.get("bytes_recv", 0)
    if duration > 60000 and bytes_total < 1000:  # > 1 min but < 1KB
        score += 15
        reasons.append("Potential beaconing (low traffic, long duration)")

    # DNS over non-standard ports
    if flow.get("l7_protocol") == "DNS" and flow.get("dst_port") not in [53, 5353]:
        score += 25
        reasons.append(f"DNS on non-standard port {flow.get('dst_port')}")

    # Clamp score
    score = min(100, max(0, score))

    return score, reasons


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    daemon_status = ndpid_client.get_status()
    db_stats = flow_db.get_stats()
    return {
        "module": "ndpid",
        "daemon": daemon_status,
        "database": db_stats,
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.get("/flows", dependencies=[Depends(require_jwt)])
async def get_flows(active_only: bool = True, limit: int = 100):
    """Get current network flows."""
    flows = ndpid_client.get_flows(active_only)[:limit]
    return {"flows": flows, "count": len(flows)}


@app.get("/flows/{flow_id}", dependencies=[Depends(require_jwt)])
async def get_flow(flow_id: str):
    """Get specific flow details."""
    flow = ndpid_client.get_flow_by_id(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow


@app.get("/protocols", dependencies=[Depends(require_jwt)])
async def get_protocols():
    """Get supported nDPI protocols."""
    return {"protocols": ndpid_client.get_protocols()}


@app.get("/applications", dependencies=[Depends(require_jwt)])
async def get_applications():
    """Get detected applications."""
    return {"applications": ndpid_client.get_applications()}


@app.get("/top/protocols", dependencies=[Depends(require_jwt)])
async def get_top_protocols(hours: int = 24, limit: int = 20):
    """Get top protocols by traffic."""
    return {"protocols": flow_db.get_top_protocols(hours, limit)}


@app.get("/top/applications", dependencies=[Depends(require_jwt)])
async def get_top_applications(hours: int = 24, limit: int = 20):
    """Get top applications by traffic."""
    return {"applications": flow_db.get_top_applications(hours, limit)}


@app.get("/fingerprints", dependencies=[Depends(require_jwt)])
async def get_fingerprints(fp_type: str = None, limit: int = 100):
    """Get JA3/JA4 fingerprints."""
    return {"fingerprints": flow_db.get_fingerprints(fp_type, limit)}


@app.get("/fingerprints/ja3", dependencies=[Depends(require_jwt)])
async def get_ja3_fingerprints(limit: int = 100):
    """Get JA3 client fingerprints."""
    return {"fingerprints": flow_db.get_fingerprints("ja3", limit)}


@app.get("/fingerprints/ja3s", dependencies=[Depends(require_jwt)])
async def get_ja3s_fingerprints(limit: int = 100):
    """Get JA3S server fingerprints."""
    return {"fingerprints": flow_db.get_fingerprints("ja3s", limit)}


@app.get("/fingerprints/ja4", dependencies=[Depends(require_jwt)])
async def get_ja4_fingerprints(limit: int = 100):
    """Get JA4 fingerprints."""
    return {"fingerprints": flow_db.get_fingerprints("ja4", limit)}


@app.post("/fingerprints/tag", dependencies=[Depends(require_jwt)])
async def tag_fingerprint(fingerprint: str, known_app: str = None, threat_intel: str = None):
    """Tag a fingerprint with application or threat intel."""
    conn = sqlite3.connect(flow_db.db_path)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE fingerprints SET known_app = ?, threat_intel = ?
        WHERE fingerprint = ?
    """, (known_app, threat_intel, fingerprint))
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Fingerprint not found")
    conn.commit()
    conn.close()
    return {"status": "tagged"}


@app.get("/risks", dependencies=[Depends(require_jwt)])
async def get_risks(hours: int = 24, limit: int = 100):
    """Get recent risk events."""
    return {"risks": flow_db.get_risk_events(hours, limit)}


@app.get("/risks/current", dependencies=[Depends(require_jwt)])
async def get_current_risks():
    """Get currently detected risks."""
    return {"risks": ndpid_client.get_risks()}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get nDPId statistics."""
    daemon_stats = ndpid_client.get_stats()
    db_stats = flow_db.get_stats()
    return {
        "daemon": daemon_stats,
        "database": db_stats,
    }


@app.get("/stats/realtime", dependencies=[Depends(require_jwt)])
async def get_realtime_stats():
    """Get real-time interface statistics."""
    cfg = get_config("ndpid")
    iface = cfg.get("interface", "eth0")
    stats_path = Path(f"/sys/class/net/{iface}/statistics")

    if not stats_path.exists():
        raise HTTPException(status_code=404, detail=f"Interface {iface} not found")

    return {
        "interface": iface,
        "rx_bytes": int((stats_path / "rx_bytes").read_text().strip()),
        "tx_bytes": int((stats_path / "tx_bytes").read_text().strip()),
        "rx_packets": int((stats_path / "rx_packets").read_text().strip()),
        "tx_packets": int((stats_path / "tx_packets").read_text().strip()),
        "rx_errors": int((stats_path / "rx_errors").read_text().strip()),
        "tx_errors": int((stats_path / "tx_errors").read_text().strip()),
    }


# ============================================================================
# Service Control
# ============================================================================

@app.post("/control/start", dependencies=[Depends(require_jwt)])
async def start_ndpid():
    """Start nDPId daemon."""
    result = subprocess.run(["systemctl", "start", "ndpid"], capture_output=True, text=True)
    return {"success": result.returncode == 0, "error": result.stderr if result.returncode != 0 else None}


@app.post("/control/stop", dependencies=[Depends(require_jwt)])
async def stop_ndpid():
    """Stop nDPId daemon."""
    result = subprocess.run(["systemctl", "stop", "ndpid"], capture_output=True, text=True)
    return {"success": result.returncode == 0}


@app.post("/control/restart", dependencies=[Depends(require_jwt)])
async def restart_ndpid():
    """Restart nDPId daemon."""
    result = subprocess.run(["systemctl", "restart", "ndpid"], capture_output=True, text=True)
    return {"success": result.returncode == 0, "error": result.stderr if result.returncode != 0 else None}


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = 100):
    """Get nDPId daemon logs."""
    result = subprocess.run(
        ["journalctl", "-u", "ndpid", "-n", str(lines), "--no-pager"],
        capture_output=True, text=True, timeout=10
    )
    return {"lines": result.stdout.splitlines()}


# ============================================================================
# Configuration
# ============================================================================

class NDPIdSettings(BaseModel):
    interface: str = "eth0"
    capture_mode: str = "pcap"  # pcap, dpdk, af_packet
    promisc: bool = True
    snaplen: int = 1600
    flow_timeout: int = 60
    enable_ja3: bool = True
    enable_ja4: bool = True
    enable_risks: bool = True
    zmq_enabled: bool = True


@app.get("/settings", dependencies=[Depends(require_jwt)])
async def get_settings():
    """Get current settings."""
    cfg = get_config("ndpid")
    return {
        "interface": cfg.get("interface", "eth0"),
        "capture_mode": cfg.get("capture_mode", "pcap"),
        "promisc": cfg.get("promisc", True),
        "snaplen": cfg.get("snaplen", 1600),
        "flow_timeout": cfg.get("flow_timeout", 60),
        "enable_ja3": cfg.get("enable_ja3", True),
        "enable_ja4": cfg.get("enable_ja4", True),
        "enable_risks": cfg.get("enable_risks", True),
        "zmq_enabled": cfg.get("zmq_enabled", True),
    }


@app.post("/settings", dependencies=[Depends(require_jwt)])
async def save_settings(settings: NDPIdSettings):
    """Save settings."""
    settings_file = Path("/etc/secubox/ndpid.json")
    settings_file.parent.mkdir(parents=True, exist_ok=True)
    settings_file.write_text(json.dumps(settings.model_dump(), indent=2))
    log.info("nDPId settings saved")
    return {"status": "saved"}


@app.get("/interfaces", dependencies=[Depends(require_jwt)])
async def list_interfaces():
    """List available network interfaces."""
    result = subprocess.run(["ip", "-j", "link", "show"], capture_output=True, text=True)
    try:
        links = json.loads(result.stdout)
        return {
            "interfaces": [
                {"name": l.get("ifname"), "state": l.get("operstate", "unknown")}
                for l in links if l.get("ifname") != "lo"
            ]
        }
    except Exception:
        return {"interfaces": []}


# ============================================================================
# TC Mirred Setup (DPI dual-stream)
# ============================================================================

@app.get("/mirred/status", dependencies=[Depends(require_jwt)])
async def mirred_status():
    """Get tc mirred status."""
    cfg = get_config("ndpid")
    iface = cfg.get("interface", "eth0")

    qdisc = subprocess.run(["tc", "qdisc", "show", "dev", iface], capture_output=True, text=True)
    filters = subprocess.run(["tc", "filter", "show", "dev", iface, "parent", "ffff:"], capture_output=True, text=True)

    return {
        "interface": iface,
        "qdisc": qdisc.stdout,
        "filters": filters.stdout,
        "active": "mirred" in filters.stdout,
    }


@app.post("/mirred/setup", dependencies=[Depends(require_jwt)])
async def setup_mirred():
    """Setup tc mirred for DPI."""
    cfg = get_config("ndpid")
    iface = cfg.get("interface", "eth0")
    mirror_if = cfg.get("mirror_if", "ifb0")

    commands = [
        ["ip", "link", "add", mirror_if, "type", "ifb"],
        ["ip", "link", "set", mirror_if, "up"],
        ["tc", "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"],
        ["tc", "filter", "add", "dev", iface, "parent", "ffff:", "protocol", "all",
         "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", mirror_if],
    ]

    results = []
    for cmd in commands:
        r = subprocess.run(cmd, capture_output=True, text=True)
        results.append({
            "cmd": " ".join(cmd),
            "success": r.returncode == 0,
            "error": r.stderr.strip() if r.returncode != 0 else None,
        })

    return {"results": results}


@app.post("/mirred/remove", dependencies=[Depends(require_jwt)])
async def remove_mirred():
    """Remove tc mirred configuration."""
    cfg = get_config("ndpid")
    iface = cfg.get("interface", "eth0")
    mirror_if = cfg.get("mirror_if", "ifb0")

    subprocess.run(["tc", "qdisc", "del", "dev", iface, "ingress"], capture_output=True)
    subprocess.run(["ip", "link", "del", mirror_if], capture_output=True)

    return {"status": "removed"}


# ============================================================================
# Export
# ============================================================================

@app.get("/export/flows", dependencies=[Depends(require_jwt)])
async def export_flows(hours: int = 24, format: str = "json"):
    """Export flow data."""
    conn = sqlite3.connect(flow_db.db_path)
    cursor = conn.cursor()

    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"
    cursor.execute("SELECT * FROM flows WHERE timestamp >= ?", (since,))

    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    conn.close()

    if format == "csv":
        lines = [",".join(columns)]
        for row in rows:
            lines.append(",".join(str(v) if v is not None else "" for v in row))
        return {"format": "csv", "data": "\n".join(lines)}

    return {"format": "json", "data": [dict(zip(columns, row)) for row in rows]}


@app.get("/export/fingerprints", dependencies=[Depends(require_jwt)])
async def export_fingerprints(format: str = "json"):
    """Export fingerprint database."""
    fps = flow_db.get_fingerprints(limit=10000)
    if format == "csv":
        lines = ["fingerprint,type,first_seen,last_seen,hit_count,known_app,threat_intel"]
        for fp in fps:
            lines.append(f"{fp['fingerprint']},{fp['fingerprint_type']},{fp['first_seen']},"
                        f"{fp['last_seen']},{fp['hit_count']},{fp.get('known_app', '')},"
                        f"{fp.get('threat_intel', '')}")
        return {"format": "csv", "data": "\n".join(lines)}
    return {"format": "json", "data": fps}


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    log.info("nDPId module started")
