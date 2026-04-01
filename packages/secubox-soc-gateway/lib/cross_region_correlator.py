"""
SecuBox-Deb :: SOC Gateway Cross-Region Correlator
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Correlates threats across multiple regional SOCs for central SOC.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from collections import defaultdict
from dataclasses import dataclass, asdict

logger = logging.getLogger("secubox.soc-gateway.cross-region")


@dataclass
class CrossRegionThreat:
    """Cross-region correlated threat."""
    threat_id: str
    source_ip: str
    severity: str
    regions_affected: List[str]
    nodes_affected: List[str]
    first_seen: str
    last_seen: str
    total_hits: int
    attack_types: List[str]
    details: Dict[str, Any]


class CrossRegionCorrelator:
    """Correlates threats across regional SOCs."""

    def __init__(self):
        # IP → region → hits mapping
        self.ip_regions: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(
            lambda: defaultdict(lambda: {"count": 0, "last_seen": None, "nodes": set()})
        )

        # Cross-region threats
        self.threats: Dict[str, CrossRegionThreat] = {}

        # Regional summaries
        self.regional_summaries: Dict[str, Dict[str, Any]] = {}

        # Thresholds
        self.min_regions = 2  # Minimum regions for cross-region correlation
        self.window_hours = 24  # Correlation window

    def ingest_regional_data(
        self,
        region_id: str,
        region_name: str,
        data: Dict[str, Any]
    ):
        """Ingest aggregated data from a regional SOC."""
        now = datetime.utcnow()

        # Store regional summary
        self.regional_summaries[region_id] = {
            "region_name": region_name,
            "nodes_online": data.get("nodes_online", 0),
            "nodes_total": data.get("nodes_total", 0),
            "alerts_count": data.get("alerts_count", 0),
            "critical_alerts": data.get("critical_alerts", 0),
            "last_update": now.isoformat() + "Z",
            "correlated_threats": data.get("correlated_threats", [])
        }

        # Process correlated threats from regional SOC
        regional_threats = data.get("correlated_threats", [])
        for threat in regional_threats:
            self._process_regional_threat(region_id, region_name, threat)

    def _process_regional_threat(
        self,
        region_id: str,
        region_name: str,
        threat: Dict[str, Any]
    ):
        """Process a correlated threat from a regional SOC."""
        source_ip = threat.get("source_ip")
        if not source_ip:
            return

        now = datetime.utcnow()
        nodes = threat.get("nodes_affected", [])
        severity = threat.get("severity", "medium")

        # Update IP→region mapping
        region_data = self.ip_regions[source_ip][region_id]
        region_data["count"] += 1
        region_data["last_seen"] = now.isoformat() + "Z"
        region_data["nodes"].update(nodes)
        region_data["region_name"] = region_name
        region_data["severity"] = severity
        region_data["attack_types"] = threat.get("attack_types", [])

        # Check for cross-region correlation
        self._check_cross_region_correlation(source_ip)

    def _check_cross_region_correlation(self, source_ip: str):
        """Check if an IP is attacking multiple regions."""
        regions_data = self.ip_regions.get(source_ip, {})

        # Filter recent activity (within window)
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=self.window_hours)

        active_regions = {}
        for region_id, data in regions_data.items():
            if data.get("last_seen"):
                last_seen = datetime.fromisoformat(data["last_seen"].rstrip("Z"))
                if last_seen > cutoff:
                    active_regions[region_id] = data

        # Check if attacking multiple regions
        if len(active_regions) >= self.min_regions:
            self._create_cross_region_threat(source_ip, active_regions)

    def _create_cross_region_threat(
        self,
        source_ip: str,
        regions_data: Dict[str, Dict[str, Any]]
    ):
        """Create or update a cross-region threat."""
        threat_id = f"xr:{source_ip}"
        now = datetime.utcnow()

        regions_affected = list(regions_data.keys())
        region_names = [d.get("region_name", r) for r, d in regions_data.items()]

        # Collect all affected nodes
        all_nodes = []
        total_hits = 0
        attack_types = set()
        severities = []

        for region_id, data in regions_data.items():
            all_nodes.extend(list(data.get("nodes", set())))
            total_hits += data.get("count", 0)
            attack_types.update(data.get("attack_types", []))
            severities.append(data.get("severity", "medium"))

        # Determine overall severity (highest across regions)
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_severity = max(severities, key=lambda s: severity_order.get(s, 0))

        # Escalate severity for cross-region attacks
        if len(regions_affected) >= 3:
            max_severity = "critical"
        elif len(regions_affected) >= 2 and max_severity in ["medium", "low"]:
            max_severity = "high"

        # Update or create threat
        if threat_id in self.threats:
            threat = self.threats[threat_id]
            threat.regions_affected = regions_affected
            threat.nodes_affected = list(set(all_nodes))
            threat.last_seen = now.isoformat() + "Z"
            threat.total_hits = total_hits
            threat.severity = max_severity
            threat.attack_types = list(attack_types)
        else:
            threat = CrossRegionThreat(
                threat_id=threat_id,
                source_ip=source_ip,
                severity=max_severity,
                regions_affected=regions_affected,
                nodes_affected=list(set(all_nodes)),
                first_seen=now.isoformat() + "Z",
                last_seen=now.isoformat() + "Z",
                total_hits=total_hits,
                attack_types=list(attack_types),
                details={
                    "region_names": region_names,
                    "per_region_hits": {r: d.get("count", 0) for r, d in regions_data.items()}
                }
            )
            self.threats[threat_id] = threat
            logger.warning(
                f"Cross-region threat detected: {source_ip} attacking {len(regions_affected)} regions"
            )

    def get_cross_region_threats(
        self,
        severity: Optional[str] = None,
        min_regions: int = 2
    ) -> List[Dict[str, Any]]:
        """Get cross-region correlated threats."""
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=self.window_hours)

        threats = []
        for threat in self.threats.values():
            # Filter by recency
            last_seen = datetime.fromisoformat(threat.last_seen.rstrip("Z"))
            if last_seen < cutoff:
                continue

            # Filter by severity
            if severity and threat.severity != severity:
                continue

            # Filter by region count
            if len(threat.regions_affected) < min_regions:
                continue

            threats.append(asdict(threat))

        # Sort by severity and recency
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        threats.sort(
            key=lambda t: (
                -severity_order.get(t.get("severity", "medium"), 0),
                t.get("last_seen", "")
            ),
            reverse=True
        )

        return threats

    def get_global_summary(self) -> Dict[str, Any]:
        """Get global cross-region summary."""
        now = datetime.utcnow()

        total_nodes_online = 0
        total_nodes = 0
        total_alerts = 0
        total_critical = 0
        regions_online = 0

        for region_id, summary in self.regional_summaries.items():
            total_nodes_online += summary.get("nodes_online", 0)
            total_nodes += summary.get("nodes_total", 0)
            total_alerts += summary.get("alerts_count", 0)
            total_critical += summary.get("critical_alerts", 0)

            # Check if region is recent
            last_update = summary.get("last_update")
            if last_update:
                lu = datetime.fromisoformat(last_update.rstrip("Z"))
                if (now - lu).total_seconds() < 300:  # 5 minutes
                    regions_online += 1

        cross_region_threats = self.get_cross_region_threats()

        return {
            "total_regions": len(self.regional_summaries),
            "regions_online": regions_online,
            "total_nodes": total_nodes,
            "total_nodes_online": total_nodes_online,
            "total_alerts": total_alerts,
            "total_critical": total_critical,
            "cross_region_threats": len(cross_region_threats),
            "active_attackers": len([t for t in cross_region_threats if t.get("severity") == "critical"]),
            "timestamp": now.isoformat() + "Z"
        }

    def get_regional_breakdown(self) -> List[Dict[str, Any]]:
        """Get breakdown by region."""
        breakdown = []
        now = datetime.utcnow()

        for region_id, summary in self.regional_summaries.items():
            status = "offline"
            last_update = summary.get("last_update")
            if last_update:
                lu = datetime.fromisoformat(last_update.rstrip("Z"))
                if (now - lu).total_seconds() < 300:
                    status = "online"
                elif (now - lu).total_seconds() < 600:
                    status = "degraded"

            breakdown.append({
                "region_id": region_id,
                "region_name": summary.get("region_name", region_id),
                "status": status,
                "nodes_online": summary.get("nodes_online", 0),
                "nodes_total": summary.get("nodes_total", 0),
                "alerts_count": summary.get("alerts_count", 0),
                "critical_alerts": summary.get("critical_alerts", 0),
                "last_update": last_update
            })

        return breakdown

    def cleanup_stale(self, hours: int = 48):
        """Cleanup stale threats older than given hours."""
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=hours)

        stale_threats = []
        for threat_id, threat in self.threats.items():
            last_seen = datetime.fromisoformat(threat.last_seen.rstrip("Z"))
            if last_seen < cutoff:
                stale_threats.append(threat_id)

        for threat_id in stale_threats:
            del self.threats[threat_id]

        # Cleanup IP regions
        stale_ips = []
        for ip, regions in self.ip_regions.items():
            all_stale = True
            for region_id, data in list(regions.items()):
                if data.get("last_seen"):
                    ls = datetime.fromisoformat(data["last_seen"].rstrip("Z"))
                    if ls < cutoff:
                        del regions[region_id]
                    else:
                        all_stale = False
            if all_stale:
                stale_ips.append(ip)

        for ip in stale_ips:
            del self.ip_regions[ip]

        return len(stale_threats)


# Global instance
cross_region_correlator = CrossRegionCorrelator()
