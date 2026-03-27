"""SecuBox Network Anomaly - Statistical Anomaly Detection
Detects bandwidth spikes, connection floods, port scans, DNS anomalies,
and protocol anomalies using statistical analysis.

Features:
- Baseline establishment and comparison
- Real-time anomaly detection
- Alert management with acknowledgment
- Optional LocalAI integration for analysis
"""
import os
import json
import time
import logging
import subprocess
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from enum import Enum
from collections import defaultdict

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration
CONFIG_PATH = Path("/etc/secubox/network-anomaly.toml")
DATA_DIR = Path("/var/lib/secubox/network-anomaly")
BASELINES_FILE = DATA_DIR / "baselines.json"
ALERTS_FILE = DATA_DIR / "alerts.jsonl"

app = FastAPI(title="SecuBox Network Anomaly", version="1.0.0")
logger = logging.getLogger("secubox.network-anomaly")


class AnomalyType(str, Enum):
    BANDWIDTH_SPIKE = "bandwidth_spike"
    CONNECTION_FLOOD = "connection_flood"
    PORT_SCAN = "port_scan"
    DNS_ANOMALY = "dns_anomaly"
    PROTOCOL_ANOMALY = "protocol_anomaly"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Alert(BaseModel):
    id: str
    type: AnomalyType
    severity: Severity
    source_ip: Optional[str] = None
    description: str
    details: Dict[str, Any] = {}
    timestamp: str
    acknowledged: bool = False
    acknowledged_at: Optional[str] = None
    acknowledged_by: Optional[str] = None


class Baseline(BaseModel):
    metric: str
    mean: float
    std_dev: float
    min_val: float
    max_val: float
    sample_count: int
    last_updated: str


class MetricSample(BaseModel):
    metric: str
    value: float
    timestamp: Optional[str] = None


class AnomalyDetector:
    """Detects network anomalies using statistical analysis."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.baselines_file = data_dir / "baselines.json"
        self.alerts_file = data_dir / "alerts.jsonl"
        self.metrics_dir = data_dir / "metrics"
        self._ensure_dirs()
        self._load_baselines()

        # Detection thresholds (in standard deviations)
        self.thresholds = {
            "bandwidth_spike": 3.0,
            "connection_flood": 2.5,
            "port_scan": 2.0,
            "dns_anomaly": 2.5,
            "protocol_anomaly": 3.0
        }

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.metrics_dir.mkdir(parents=True, exist_ok=True)

    def _load_baselines(self):
        """Load baseline statistics."""
        self.baselines: Dict[str, Baseline] = {}
        if self.baselines_file.exists():
            try:
                data = json.loads(self.baselines_file.read_text())
                self.baselines = {k: Baseline(**v) for k, v in data.items()}
            except Exception:
                pass

    def _save_baselines(self):
        self.baselines_file.write_text(json.dumps(
            {k: v.model_dump() for k, v in self.baselines.items()},
            indent=2
        ))

    def _generate_alert_id(self) -> str:
        return f"anomaly-{int(time.time() * 1000)}"

    def record_alert(self, alert: Alert):
        """Record an anomaly alert."""
        with open(self.alerts_file, "a") as f:
            f.write(json.dumps(alert.model_dump()) + "\n")

    def get_alerts(
        self,
        hours: int = 24,
        acknowledged: Optional[bool] = None
    ) -> List[Alert]:
        """Get recent alerts."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        alerts = []

        if not self.alerts_file.exists():
            return alerts

        with open(self.alerts_file) as f:
            for line in f:
                try:
                    data = json.loads(line)
                    ts = datetime.fromisoformat(data["timestamp"].rstrip("Z"))
                    if ts < cutoff:
                        continue
                    if acknowledged is not None and data.get("acknowledged") != acknowledged:
                        continue
                    alerts.append(Alert(**data))
                except Exception:
                    continue

        return alerts

    def acknowledge_alert(self, alert_id: str, by: str = "admin") -> bool:
        """Acknowledge an alert."""
        # Read all alerts
        alerts = []
        found = False

        if not self.alerts_file.exists():
            return False

        with open(self.alerts_file) as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if data.get("id") == alert_id:
                        data["acknowledged"] = True
                        data["acknowledged_at"] = datetime.utcnow().isoformat() + "Z"
                        data["acknowledged_by"] = by
                        found = True
                    alerts.append(data)
                except Exception:
                    continue

        if found:
            # Rewrite file
            with open(self.alerts_file, "w") as f:
                for alert in alerts:
                    f.write(json.dumps(alert) + "\n")

        return found

    def update_baseline(self, metric: str, values: List[float]):
        """Update baseline statistics for a metric."""
        if len(values) < 5:
            return

        baseline = Baseline(
            metric=metric,
            mean=statistics.mean(values),
            std_dev=statistics.stdev(values) if len(values) > 1 else 0,
            min_val=min(values),
            max_val=max(values),
            sample_count=len(values),
            last_updated=datetime.utcnow().isoformat() + "Z"
        )

        self.baselines[metric] = baseline
        self._save_baselines()

    def check_anomaly(
        self,
        metric: str,
        value: float,
        anomaly_type: AnomalyType
    ) -> Optional[Alert]:
        """Check if a value is anomalous compared to baseline."""
        baseline = self.baselines.get(metric)
        if not baseline or baseline.std_dev == 0:
            return None

        # Calculate z-score
        z_score = abs(value - baseline.mean) / baseline.std_dev
        threshold = self.thresholds.get(anomaly_type.value, 3.0)

        if z_score > threshold:
            severity = Severity.CRITICAL if z_score > threshold * 2 else (
                Severity.HIGH if z_score > threshold * 1.5 else Severity.MEDIUM
            )

            alert = Alert(
                id=self._generate_alert_id(),
                type=anomaly_type,
                severity=severity,
                description=f"{metric} anomaly detected: {value:.2f} (baseline: {baseline.mean:.2f}, z-score: {z_score:.2f})",
                details={
                    "metric": metric,
                    "value": value,
                    "baseline_mean": baseline.mean,
                    "baseline_std": baseline.std_dev,
                    "z_score": z_score,
                    "threshold": threshold
                },
                timestamp=datetime.utcnow().isoformat() + "Z"
            )

            self.record_alert(alert)
            return alert

        return None

    def _get_tcp_connections(self) -> int:
        """Get TCP connection count with fallbacks."""
        # Try ss first
        try:
            result = subprocess.run(
                ["ss", "-tun", "state", "established"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return max(0, len(result.stdout.strip().split("\n")) - 1)
        except Exception:
            pass

        # Fallback to netstat
        try:
            result = subprocess.run(
                ["netstat", "-tn"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return sum(1 for line in result.stdout.split("\n") if "ESTABLISHED" in line)
        except Exception:
            pass

        # Fallback to /proc/net/tcp
        try:
            count = 0
            with open("/proc/net/tcp") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) > 3 and parts[3] == "01":  # 01 = ESTABLISHED
                        count += 1
            return count
        except Exception:
            return 0

    def _get_listening_ports(self) -> int:
        """Get listening port count with fallbacks."""
        try:
            result = subprocess.run(
                ["ss", "-tuln"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return max(0, len(result.stdout.strip().split("\n")) - 1)
        except Exception:
            pass

        # Fallback to netstat
        try:
            result = subprocess.run(
                ["netstat", "-tuln"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return sum(1 for line in result.stdout.split("\n") if "LISTEN" in line)
        except Exception:
            return 0

    def collect_metrics(self) -> Dict[str, float]:
        """Collect current network metrics."""
        metrics = {}
        now = datetime.utcnow().isoformat() + "Z"

        # TCP connections (with fallbacks)
        metrics["tcp_connections"] = self._get_tcp_connections()

        # Network interfaces - bytes in/out
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    # Match common interface names
                    for prefix in ["eth", "ens", "enp", "wlan", "br-"]:
                        if prefix in line:
                            parts = line.split()
                            if len(parts) >= 10:
                                iface = parts[0].rstrip(":")
                                metrics[f"{iface}_rx_bytes"] = int(parts[1])
                                metrics[f"{iface}_tx_bytes"] = int(parts[9])
                            break
        except Exception:
            pass

        # DNS queries (from dnsmasq if available)
        for log_path in ["/var/log/dnsmasq.log", "/var/log/syslog"]:
            try:
                result = subprocess.run(
                    ["grep", "-c", "query", log_path],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    metrics["dns_queries_total"] = int(result.stdout.strip())
                    break
            except Exception:
                pass

        # Active listening ports (with fallbacks)
        metrics["listening_ports"] = self._get_listening_ports()

        # Store metrics in history for proper baseline calculation
        self._store_metrics(metrics, now)

        return metrics

    def _store_metrics(self, metrics: Dict[str, float], timestamp: str):
        """Store metrics in history files for baseline calculation."""
        for metric, value in metrics.items():
            metric_file = self.metrics_dir / f"{metric}.jsonl"
            entry = {"value": value, "timestamp": timestamp}
            try:
                with open(metric_file, "a") as f:
                    f.write(json.dumps(entry) + "\n")

                # Trim old entries (keep last 1000)
                self._trim_metric_file(metric_file, 1000)
            except Exception as e:
                logger.warning(f"Failed to store metric {metric}: {e}")

    def _trim_metric_file(self, filepath: Path, max_lines: int):
        """Trim metric file to keep only recent entries."""
        try:
            with open(filepath) as f:
                lines = f.readlines()
            if len(lines) > max_lines:
                with open(filepath, "w") as f:
                    f.writelines(lines[-max_lines:])
        except Exception:
            pass

    def _get_metric_history(self, metric: str, hours: int = 24) -> List[float]:
        """Get metric values from history."""
        metric_file = self.metrics_dir / f"{metric}.jsonl"
        if not metric_file.exists():
            return []

        cutoff = datetime.utcnow() - timedelta(hours=hours)
        values = []

        try:
            with open(metric_file) as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        ts = datetime.fromisoformat(data["timestamp"].rstrip("Z"))
                        if ts >= cutoff:
                            values.append(data["value"])
                    except Exception:
                        continue
        except Exception:
            pass

        return values

    def detect_port_scan(self, connection_log: List[Dict]) -> Optional[Alert]:
        """Detect port scanning behavior."""
        # Group connections by source IP
        by_ip: Dict[str, set] = defaultdict(set)
        for conn in connection_log:
            src_ip = conn.get("src_ip")
            dst_port = conn.get("dst_port")
            if src_ip and dst_port:
                by_ip[src_ip].add(dst_port)

        # Check for IPs hitting many ports
        for ip, ports in by_ip.items():
            if len(ports) > 20:  # More than 20 ports = suspicious
                alert = Alert(
                    id=self._generate_alert_id(),
                    type=AnomalyType.PORT_SCAN,
                    severity=Severity.HIGH if len(ports) > 50 else Severity.MEDIUM,
                    source_ip=ip,
                    description=f"Port scan detected: {ip} probed {len(ports)} ports",
                    details={
                        "source_ip": ip,
                        "port_count": len(ports),
                        "ports_sample": list(ports)[:20]
                    },
                    timestamp=datetime.utcnow().isoformat() + "Z"
                )
                self.record_alert(alert)
                return alert

        return None

    def _collect_connection_log(self) -> List[Dict]:
        """Collect recent connections for port scan detection."""
        connections = []

        # Try conntrack first (best source)
        try:
            result = subprocess.run(
                ["conntrack", "-L", "-o", "extended"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "tcp" in line or "udp" in line:
                        # Parse conntrack output
                        parts = {}
                        for item in line.split():
                            if "=" in item:
                                k, v = item.split("=", 1)
                                parts[k] = v

                        if "src" in parts and "dport" in parts:
                            connections.append({
                                "src_ip": parts.get("src"),
                                "dst_ip": parts.get("dst"),
                                "dst_port": int(parts.get("dport", 0)),
                                "protocol": "tcp" if "tcp" in line else "udp"
                            })
                return connections
        except Exception:
            pass

        # Fallback to /proc/net/nf_conntrack
        try:
            with open("/proc/net/nf_conntrack") as f:
                for line in f:
                    parts = line.split()
                    conn = {}
                    for p in parts:
                        if "=" in p:
                            k, v = p.split("=", 1)
                            conn[k] = v

                    if "src" in conn and "dport" in conn:
                        connections.append({
                            "src_ip": conn.get("src"),
                            "dst_ip": conn.get("dst"),
                            "dst_port": int(conn.get("dport", 0)),
                            "protocol": parts[0] if parts else "unknown"
                        })
        except Exception:
            pass

        return connections

    def run_detection(self) -> List[Alert]:
        """Run all anomaly detections."""
        alerts = []
        metrics = self.collect_metrics()

        # Check each metric against baseline
        for metric, value in metrics.items():
            if "connections" in metric or "queries" in metric:
                alert = self.check_anomaly(metric, value, AnomalyType.CONNECTION_FLOOD)
            elif "bytes" in metric:
                alert = self.check_anomaly(metric, value, AnomalyType.BANDWIDTH_SPIKE)
            else:
                alert = self.check_anomaly(metric, value, AnomalyType.PROTOCOL_ANOMALY)

            if alert:
                alerts.append(alert)

        # Port scan detection
        connection_log = self._collect_connection_log()
        if connection_log:
            scan_alert = self.detect_port_scan(connection_log)
            if scan_alert:
                alerts.append(scan_alert)

        return alerts

    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics."""
        alerts = self.get_alerts(24)

        by_type = {}
        by_severity = {}
        for alert in alerts:
            by_type[alert.type.value] = by_type.get(alert.type.value, 0) + 1
            by_severity[alert.severity.value] = by_severity.get(alert.severity.value, 0) + 1

        unacknowledged = sum(1 for a in alerts if not a.acknowledged)

        return {
            "alerts_24h": len(alerts),
            "unacknowledged": unacknowledged,
            "by_type": by_type,
            "by_severity": by_severity,
            "baselines_count": len(self.baselines)
        }


# Global instance
detector = AnomalyDetector(DATA_DIR)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    stats = detector.get_stats()
    return {
        "module": "network-anomaly",
        "status": "ok",
        "version": "1.0.0",
        "alerts_24h": stats["alerts_24h"],
        "unacknowledged": stats["unacknowledged"]
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get detection statistics."""
    return detector.get_stats()


@app.get("/metrics", dependencies=[Depends(require_jwt)])
async def get_metrics():
    """Get current network metrics."""
    metrics = detector.collect_metrics()
    return {"metrics": metrics}


@app.post("/detect", dependencies=[Depends(require_jwt)])
async def run_detection():
    """Run anomaly detection."""
    alerts = detector.run_detection()
    return {"alerts": alerts, "count": len(alerts)}


@app.get("/alerts", dependencies=[Depends(require_jwt)])
async def list_alerts(
    hours: int = 24,
    acknowledged: Optional[bool] = None
):
    """List recent alerts."""
    alerts = detector.get_alerts(hours, acknowledged)
    return {"alerts": alerts, "count": len(alerts)}


@app.post("/alerts/{alert_id}/acknowledge", dependencies=[Depends(require_jwt)])
async def acknowledge_alert(alert_id: str):
    """Acknowledge an alert."""
    if not detector.acknowledge_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "acknowledged"}


@app.get("/baselines", dependencies=[Depends(require_jwt)])
async def list_baselines():
    """List all baselines."""
    return {"baselines": list(detector.baselines.values())}


@app.post("/baselines/update", dependencies=[Depends(require_jwt)])
async def update_baselines(hours: int = 24):
    """Update baselines from metric history (proper statistical calculation)."""
    # First collect current metrics to ensure we have recent data
    detector.collect_metrics()

    updated = 0
    metrics_updated = []

    # Get all metric files
    for metric_file in detector.metrics_dir.glob("*.jsonl"):
        metric = metric_file.stem
        values = detector._get_metric_history(metric, hours)

        if len(values) >= 5:  # Need at least 5 samples for meaningful stats
            detector.update_baseline(metric, values)
            updated += 1
            metrics_updated.append({
                "metric": metric,
                "samples": len(values),
                "mean": detector.baselines[metric].mean,
                "std_dev": detector.baselines[metric].std_dev
            })

    return {
        "updated": updated,
        "metrics": metrics_updated,
        "hours_analyzed": hours
    }


@app.post("/sample", dependencies=[Depends(require_jwt)])
async def add_sample(sample: MetricSample):
    """Add a metric sample for baseline calculation."""
    metric_file = detector.metrics_dir / f"{sample.metric}.jsonl"

    entry = {
        "value": sample.value,
        "timestamp": sample.timestamp or datetime.utcnow().isoformat() + "Z"
    }

    with open(metric_file, "a") as f:
        f.write(json.dumps(entry) + "\n")

    return {"status": "recorded"}


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Network Anomaly detector started")
