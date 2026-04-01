"""
SecuBox-Deb :: SOC Gateway Alert Correlator
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Cross-node threat correlation and analysis.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from collections import defaultdict
from dataclasses import dataclass, asdict

logger = logging.getLogger("secubox.soc-gateway.correlator")

# Storage
DATA_DIR = Path("/var/lib/secubox/soc-gateway")
CORRELATED_FILE = DATA_DIR / "correlated_threats.json"

# Correlation thresholds
MIN_NODES_FOR_CORRELATION = 2
CORRELATION_WINDOW_MINUTES = 15
SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25
}


@dataclass
class CorrelatedThreat:
    """A threat observed across multiple nodes."""
    threat_id: str
    source_ip: str
    nodes_affected: List[str]
    first_seen: str
    last_seen: str
    total_hits: int
    scenarios: List[str]
    severity: str
    recommended_action: str


class AlertCorrelator:
    """Correlates alerts across multiple edge nodes to identify coordinated attacks."""

    def __init__(self):
        self.ip_hits: Dict[str, Dict] = {}  # IP -> hit info
        self.correlated_threats: List[CorrelatedThreat] = []
        self._load_data()

    def _load_data(self):
        """Load correlated threats from file."""
        if CORRELATED_FILE.exists():
            try:
                data = json.loads(CORRELATED_FILE.read_text())
                self.correlated_threats = [
                    CorrelatedThreat(**t) for t in data.get("threats", [])
                ]
            except Exception as e:
                logger.error(f"Failed to load correlated threats: {e}")

    def _save_data(self):
        """Save correlated threats to file."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "threats": [asdict(t) for t in self.correlated_threats],
            "updated_at": datetime.utcnow().isoformat() + "Z"
        }
        CORRELATED_FILE.write_text(json.dumps(data, indent=2))

    def process_alerts(
        self,
        node_id: str,
        alerts: List[Dict[str, Any]]
    ):
        """Process alerts from an edge node for correlation."""
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=CORRELATION_WINDOW_MINUTES)

        for alert in alerts:
            ip = alert.get("ip") or alert.get("source_ip")
            if not ip:
                continue

            # Skip private IPs
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                continue

            # Track this IP
            if ip not in self.ip_hits:
                self.ip_hits[ip] = {
                    "nodes": set(),
                    "scenarios": set(),
                    "hits": 0,
                    "first_seen": now.isoformat() + "Z",
                    "last_seen": now.isoformat() + "Z",
                    "severities": []
                }

            hit = self.ip_hits[ip]
            hit["nodes"].add(node_id)
            hit["hits"] += 1
            hit["last_seen"] = now.isoformat() + "Z"

            scenario = alert.get("scenario") or alert.get("signature") or "unknown"
            hit["scenarios"].add(scenario)

            severity = alert.get("severity", "medium")
            if isinstance(severity, int):
                # Suricata uses numeric severity
                if severity <= 1:
                    severity = "critical"
                elif severity == 2:
                    severity = "high"
                elif severity == 3:
                    severity = "medium"
                else:
                    severity = "low"
            hit["severities"].append(severity)

        # Run correlation
        self._correlate()

    def _correlate(self):
        """Run correlation analysis on collected IP hits."""
        new_threats = []

        for ip, hit in self.ip_hits.items():
            nodes = hit["nodes"]

            if len(nodes) >= MIN_NODES_FOR_CORRELATION:
                # This IP has hit multiple nodes - potential coordinated attack

                # Calculate aggregate severity
                severity_score = sum(
                    SEVERITY_WEIGHTS.get(s, 25) for s in hit["severities"]
                ) / max(len(hit["severities"]), 1)

                if severity_score >= 75:
                    severity = "critical"
                elif severity_score >= 50:
                    severity = "high"
                elif severity_score >= 25:
                    severity = "medium"
                else:
                    severity = "low"

                # Determine recommended action
                if len(nodes) >= 5 or severity == "critical":
                    action = "block_globally"
                elif len(nodes) >= 3:
                    action = "rate_limit"
                else:
                    action = "monitor"

                threat = CorrelatedThreat(
                    threat_id=f"CT-{ip.replace('.', '-')}-{datetime.utcnow().strftime('%Y%m%d')}",
                    source_ip=ip,
                    nodes_affected=list(nodes),
                    first_seen=hit["first_seen"],
                    last_seen=hit["last_seen"],
                    total_hits=hit["hits"],
                    scenarios=list(hit["scenarios"]),
                    severity=severity,
                    recommended_action=action
                )
                new_threats.append(threat)

        # Update correlated threats (merge with existing)
        existing_ips = {t.source_ip for t in self.correlated_threats}
        for threat in new_threats:
            if threat.source_ip in existing_ips:
                # Update existing
                for i, t in enumerate(self.correlated_threats):
                    if t.source_ip == threat.source_ip:
                        self.correlated_threats[i] = threat
                        break
            else:
                self.correlated_threats.append(threat)

        # Cleanup old threats (older than 24h)
        cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        self.correlated_threats = [
            t for t in self.correlated_threats
            if t.last_seen > cutoff
        ]

        self._save_data()

    def get_correlated_threats(
        self,
        severity: Optional[str] = None,
        min_nodes: int = 2
    ) -> List[Dict[str, Any]]:
        """Get list of correlated threats."""
        threats = self.correlated_threats

        if severity:
            threats = [t for t in threats if t.severity == severity]

        threats = [t for t in threats if len(t.nodes_affected) >= min_nodes]

        # Sort by severity and node count
        threats.sort(
            key=lambda t: (
                SEVERITY_WEIGHTS.get(t.severity, 0),
                len(t.nodes_affected)
            ),
            reverse=True
        )

        return [asdict(t) for t in threats]

    def get_threat_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get threat details for a specific IP."""
        for t in self.correlated_threats:
            if t.source_ip == ip:
                return asdict(t)
        return None

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of correlated threats."""
        by_severity = defaultdict(int)
        by_action = defaultdict(int)
        total_affected_nodes = set()

        for t in self.correlated_threats:
            by_severity[t.severity] += 1
            by_action[t.recommended_action] += 1
            total_affected_nodes.update(t.nodes_affected)

        return {
            "total_threats": len(self.correlated_threats),
            "by_severity": dict(by_severity),
            "by_action": dict(by_action),
            "nodes_under_attack": len(total_affected_nodes),
            "top_threats": [
                asdict(t) for t in self.correlated_threats[:5]
            ],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def cleanup_old_data(self, hours: int = 24):
        """Cleanup IP hits older than specified hours."""
        cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

        old_ips = [
            ip for ip, hit in self.ip_hits.items()
            if hit["last_seen"] < cutoff
        ]

        for ip in old_ips:
            del self.ip_hits[ip]

        return len(old_ips)


# Global instance
correlator = AlertCorrelator()
