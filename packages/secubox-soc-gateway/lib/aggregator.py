"""
SecuBox-Deb :: SOC Gateway Aggregator
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Aggregates fleet-wide metrics and alerts from edge nodes.
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger("secubox.soc-gateway.aggregator")

# Storage
DATA_DIR = Path("/var/lib/secubox/soc-gateway")
CACHE_FILE = DATA_DIR / "aggregated_stats.json"

# Cache settings
CACHE_TTL = 30  # seconds


@dataclass
class NodeMetrics:
    """Cached metrics from a single node."""
    node_id: str
    hostname: str
    timestamp: str
    cpu: float
    memory_percent: float
    disk_percent: float
    health: str
    services_down: int
    alert_count: int


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
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def invalidate(self, key: str = None):
        with self._lock:
            if key:
                self._cache.pop(key, None)
                self._timestamps.pop(key, None)
            else:
                self._cache.clear()
                self._timestamps.clear()


class FleetAggregator:
    """Aggregates metrics and alerts from all edge nodes."""

    def __init__(self):
        self.cache = StatsCache(ttl_seconds=CACHE_TTL)
        self.node_metrics: Dict[str, NodeMetrics] = {}
        self.alerts: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

        # Persist aggregated data
        DATA_DIR.mkdir(parents=True, exist_ok=True)

    def ingest_metrics(
        self,
        node_id: str,
        hostname: str,
        metrics: Dict[str, Any]
    ):
        """Ingest metrics from an edge node."""
        with self._lock:
            # Extract key metrics
            resources = metrics.get("resources", {})
            services = metrics.get("services", [])

            services_down = sum(
                1 for s in services if not s.get("running", True)
            )

            node_metrics = NodeMetrics(
                node_id=node_id,
                hostname=hostname,
                timestamp=metrics.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                cpu=resources.get("cpu", 0),
                memory_percent=resources.get("memory", {}).get("percent", 0),
                disk_percent=resources.get("disk", {}).get("percent", 0),
                health=metrics.get("health", "unknown"),
                services_down=services_down,
                alert_count=metrics.get("alert_count", 0)
            )

            self.node_metrics[node_id] = node_metrics

            # Ingest alerts
            node_alerts = metrics.get("alerts", [])
            for alert in node_alerts:
                alert["node_id"] = node_id
                alert["node_hostname"] = hostname
                self._add_alert(alert)

            # Invalidate aggregated cache
            self.cache.invalidate("fleet_summary")

    def _add_alert(self, alert: Dict[str, Any]):
        """Add an alert to the unified stream."""
        # Deduplicate by creating a key
        alert_key = f"{alert.get('source')}:{alert.get('ip')}:{alert.get('node_id')}"
        alert["_key"] = alert_key

        # Check for existing
        existing = None
        for i, a in enumerate(self.alerts):
            if a.get("_key") == alert_key:
                existing = i
                break

        if existing is not None:
            # Update existing
            self.alerts[existing] = alert
        else:
            # Add new
            self.alerts.append(alert)

        # Keep only recent alerts (last 1000)
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-1000:]

    def get_fleet_summary(self) -> Dict[str, Any]:
        """Get aggregated fleet summary."""
        cached = self.cache.get("fleet_summary")
        if cached:
            return cached

        with self._lock:
            total_nodes = len(self.node_metrics)

            # Health breakdown
            health_counts = defaultdict(int)
            status_counts = {"online": 0, "offline": 0}

            # Resource aggregates
            total_cpu = 0
            total_memory = 0
            total_disk = 0
            total_services_down = 0
            total_alerts = 0

            critical_nodes = []
            degraded_nodes = []

            now = datetime.utcnow()

            for node in self.node_metrics.values():
                # Check if recent (within 3 minutes)
                try:
                    ts = datetime.fromisoformat(node.timestamp.rstrip("Z"))
                    if (now - ts).total_seconds() < 180:
                        status_counts["online"] += 1
                    else:
                        status_counts["offline"] += 1
                        continue  # Don't include in averages
                except:
                    status_counts["offline"] += 1
                    continue

                health_counts[node.health] += 1
                total_cpu += node.cpu
                total_memory += node.memory_percent
                total_disk += node.disk_percent
                total_services_down += node.services_down
                total_alerts += node.alert_count

                if node.health == "critical":
                    critical_nodes.append({
                        "node_id": node.node_id,
                        "hostname": node.hostname,
                        "cpu": node.cpu,
                        "memory": node.memory_percent
                    })
                elif node.health == "degraded":
                    degraded_nodes.append({
                        "node_id": node.node_id,
                        "hostname": node.hostname
                    })

            online = status_counts["online"]
            avg_cpu = total_cpu / online if online > 0 else 0
            avg_memory = total_memory / online if online > 0 else 0
            avg_disk = total_disk / online if online > 0 else 0

            summary = {
                "total_nodes": total_nodes,
                "nodes_online": online,
                "nodes_offline": status_counts["offline"],
                "health_breakdown": dict(health_counts),
                "resources": {
                    "avg_cpu": round(avg_cpu, 1),
                    "avg_memory": round(avg_memory, 1),
                    "avg_disk": round(avg_disk, 1)
                },
                "services_down": total_services_down,
                "total_alerts": total_alerts,
                "critical_nodes": critical_nodes[:10],
                "degraded_nodes": degraded_nodes[:10],
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

            self.cache.set("fleet_summary", summary)
            return summary

    def get_nodes_list(self) -> List[Dict[str, Any]]:
        """Get list of all nodes with their current metrics."""
        with self._lock:
            return [
                {
                    "node_id": m.node_id,
                    "hostname": m.hostname,
                    "timestamp": m.timestamp,
                    "cpu": m.cpu,
                    "memory": m.memory_percent,
                    "disk": m.disk_percent,
                    "health": m.health,
                    "services_down": m.services_down,
                    "alert_count": m.alert_count
                }
                for m in self.node_metrics.values()
            ]

    def get_node_detail(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed metrics for a specific node."""
        with self._lock:
            node = self.node_metrics.get(node_id)
            if not node:
                return None

            # Get node's alerts
            node_alerts = [
                a for a in self.alerts if a.get("node_id") == node_id
            ]

            return {
                "node_id": node.node_id,
                "hostname": node.hostname,
                "timestamp": node.timestamp,
                "metrics": {
                    "cpu": node.cpu,
                    "memory": node.memory_percent,
                    "disk": node.disk_percent
                },
                "health": node.health,
                "services_down": node.services_down,
                "alerts": node_alerts[-20:]  # Last 20
            }

    def get_alerts(
        self,
        limit: int = 50,
        source: Optional[str] = None,
        node_id: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get unified alert stream with optional filters."""
        with self._lock:
            alerts = self.alerts.copy()

        # Apply filters
        if source:
            alerts = [a for a in alerts if a.get("source") == source]
        if node_id:
            alerts = [a for a in alerts if a.get("node_id") == node_id]
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]

        # Sort by timestamp (newest first)
        alerts.sort(
            key=lambda a: a.get("timestamp") or a.get("created_at") or "",
            reverse=True
        )

        return alerts[:limit]

    def get_resources_history(
        self,
        node_id: Optional[str] = None,
        minutes: int = 60
    ) -> Dict[str, Any]:
        """Get resource usage history (placeholder for time-series data)."""
        # In production, this would query a time-series database
        # For now, return current snapshot
        if node_id:
            node = self.node_metrics.get(node_id)
            if node:
                return {
                    "node_id": node_id,
                    "points": [{
                        "timestamp": node.timestamp,
                        "cpu": node.cpu,
                        "memory": node.memory_percent,
                        "disk": node.disk_percent
                    }]
                }
            return {"node_id": node_id, "points": []}

        # Fleet-wide
        summary = self.get_fleet_summary()
        return {
            "fleet": True,
            "points": [{
                "timestamp": summary["timestamp"],
                "avg_cpu": summary["resources"]["avg_cpu"],
                "avg_memory": summary["resources"]["avg_memory"],
                "avg_disk": summary["resources"]["avg_disk"]
            }]
        }

    def persist_cache(self):
        """Persist aggregated data to disk."""
        try:
            data = {
                "nodes": self.get_nodes_list(),
                "summary": self.get_fleet_summary(),
                "saved_at": datetime.utcnow().isoformat() + "Z"
            }
            CACHE_FILE.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Failed to persist cache: {e}")


# Global instance
aggregator = FleetAggregator()
