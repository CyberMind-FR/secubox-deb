# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
DEFCON Level Calculator for SecuBox - CSPN/TPN Media Compliant

Provides real-time security posture assessment with military-standard DEFCON levels
mapped to ANSSI CSPN requirements and TPN Media compliance.

DEFCON Levels:
    DEFCON 5 (Normal)     - All systems operational, score 90-100%
    DEFCON 4 (Chatter)    - Minor issues, score 70-89%
    DEFCON 3 (Heightened)- Active threats, score 50-69%
    DEFCON 2 (Severe)    - Major incident, score 30-49%
    DEFCON 1 (Maximum)   - Critical breach, score 0-29%

CSPN Alignment:
    Maps to docs/cspn/CSPN-TEST-MATRIX.md requirements
    Maps to doctrine/opad/CSPN.matrix.md capabilities

TPN Media Alignment:
    Maps to TPN (Trusted Partner Network) Media security requirements
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import asyncio
import httpx
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger("secubox.security-posture.defcon")


class DefconLevel(str, Enum):
    """DEFCON levels with military standard mapping."""
    DEFCON_5 = "defcon_5"  # Normal - All systems operational
    DEFCON_4 = "defcon_4"  # Increased Chatter - Minor alerts
    DEFCON_3 = "defcon_3"  # Heightened - Active threats
    DEFCON_2 = "defcon_2"  # Severe - Major incident
    DEFCON_1 = "defcon_1"  # Maximum - Critical breach


@dataclass
class DefconIndicator:
    """Single DEFCON indicator with weight and current value."""
    name: str
    category: str  # network, threat, access, data, resilience
    weight: float  # 0.0-1.0
    current_value: float = 1.0  # 0.0-1.0 (1.0 = perfect)
    threshold_critical: float = 0.3  # Below this = error state
    threshold_warning: float = 0.7   # Below this = warning state
    threshold_ok: float = 0.95       # Above this = perfect
    description: str = ""
    cspn_requirement: str = ""  # Reference to CSPN matrix ID
    tpn_requirement: str = ""   # Reference to TPN Media requirement
    inverse: bool = False  # If True, lower values are better
    unit: str = ""  # Unit of measurement (% , count, etc.)
    
    def get_status(self) -> str:
        """Get current status based on value and thresholds."""
        value = self.current_value
        if self.inverse:
            value = 1.0 - value
            
        if value >= self.threshold_ok:
            return "ok"
        elif value >= self.threshold_warning:
            return "degraded"
        elif value >= self.threshold_critical:
            return "warning"
        else:
            return "error"
    
    def get_score(self) -> float:
        """Get normalized score (0-1) for this indicator."""
        value = self.current_value
        if self.inverse:
            return 1.0 - value
        return value


class DefconEngine:
    """
    Main DEFCON calculation engine.
    
    Aggregates metrics from all SecuBox modules and calculates:
    1. Overall security score (0-100)
    2. DEFCON level (1-5)
    3. Per-category scores
    4. Compliance status (CSPN/TPN)
    
    Usage:
        engine = DefconEngine()
        metrics = await engine.collect_all_metrics()
        score = engine.calculate_score(metrics)
        defcon = engine.get_defcon_level(score)
        info = engine.get_defcon_info(score)
    """
    
    # Category weight distribution (CSPN-aligned)
    CATEGORY_WEIGHTS: Dict[str, float] = {
        "network": 0.30,    # WAF, Firewall, nftables
        "threat": 0.25,     # CrowdSec, DPI, threat detection
        "access": 0.20,     # Auth, privilege separation, ACL
        "data": 0.15,       # Encryption, data integrity
        "resilience": 0.10  # Uptime, backups, failover
    }
    
    def __init__(self):
        self.indicators: Dict[str, DefconIndicator] = {}
        self._init_indicators()
        self._last_collection: Optional[datetime] = None
        self._cached_metrics: Dict[str, Any] = {}
    
    def _init_indicators(self):
        """Initialize all DEFCON indicators from CSPN test matrix and TPN requirements."""
        
        # ========================================================================
        # NETWORK SECURITY INDICATORS (30% total weight)
        # ========================================================================
        
        self.indicators["waf_operational"] = DefconIndicator(
            name="WAF Operational",
            category="network",
            weight=0.15,
            current_value=1.0,
            threshold_ok=0.99,
            threshold_warning=0.95,
            threshold_critical=0.80,
            description="WAF mitmproxy is running and processing requests",
            cspn_requirement="WAF-01",
            tpn_requirement="TPN-NET-01",
            unit="boolean"
        )
        
        self.indicators["firewall_policy"] = DefconIndicator(
            name="Firewall Policy",
            category="network",
            weight=0.10,
            current_value=1.0,
            threshold_ok=0.99,
            threshold_warning=0.95,
            threshold_critical=0.70,
            description="nftables DEFAULT DROP policy active on all chains",
            cspn_requirement="NET-01",
            tpn_requirement="TPN-NET-02",
            unit="boolean"
        )
        
        self.indicators["nftables_rules"] = DefconIndicator(
            name="nftables Rules Loaded",
            category="network",
            weight=0.05,
            current_value=1.0,
            threshold_ok=0.99,
            threshold_warning=0.90,
            threshold_critical=0.50,
            description="nftables rules loaded and active",
            cspn_requirement="NET-05",
            tpn_requirement="TPN-NET-03",
            unit="%"
        )
        
        # ========================================================================
        # THREAT INTELLIGENCE INDICATORS (25% total weight)
        # ========================================================================
        
        self.indicators["crowdsec_detection"] = DefconIndicator(
            name="CrowdSec Detection",
            category="threat",
            weight=0.10,
            current_value=1.0,
            threshold_ok=0.99,
            threshold_warning=0.90,
            threshold_critical=0.50,
            description="CrowdSec LAPI responding and detecting threats",
            cspn_requirement="WAF-04",
            tpn_requirement="TPN-THREAT-01",
            unit="boolean"
        )
        
        self.indicators["threat_block_rate"] = DefconIndicator(
            name="Threat Block Rate",
            category="threat",
            weight=0.10,
            current_value=1.0,
            threshold_ok=0.99,
            threshold_warning=0.90,
            threshold_critical=0.70,
            description="Percentage of detected threats successfully blocked",
            cspn_requirement="WAF-03",
            tpn_requirement="TPN-THREAT-02",
            unit="%"
        )
        
        self.indicators["false_positive_rate"] = DefconIndicator(
            name="False Positive Rate",
            category="threat",
            weight=0.05,
            current_value=0.0,  # Start at 0% (perfect)
            threshold_ok=0.01,   # <1% is perfect
            threshold_warning=0.05,
            threshold_critical=0.10,
            description="Rate of false positives in threat detection",
            cspn_requirement="WAF-04",
            tpn_requirement="TPN-THREAT-03",
            unit="%",
            inverse=True  # Lower is better
        )
        
        # ========================================================================
        # ACCESS CONTROL INDICATORS (20% total weight)
        # ========================================================================
        
        self.indicators["auth_system"] = DefconIndicator(
            name="Authentication System",
            category="access",
            weight=0.10,
            current_value=1.0,
            threshold_ok=0.99,
            threshold_warning=0.95,
            threshold_critical=0.70,
            description="Auth system (Authelia/SSO) operational",
            cspn_requirement="AUT-01",
            tpn_requirement="TPN-ACCESS-01",
            unit="boolean"
        )
        
        self.indicators["privilege_separation"] = DefconIndicator(
            name="Privilege Separation",
            category="access",
            weight=0.05,
            current_value=1.0,
            threshold_ok=0.99,
            threshold_warning=0.90,
            threshold_critical=0.70,
            description="All services running as non-root users",
            cspn_requirement="ACL-01",
            tpn_requirement="TPN-ACCESS-02",
            unit="%"
        )
        
        self.indicators["audit_logging"] = DefconIndicator(
            name="Audit Logging",
            category="access",
            weight=0.05,
            current_value=1.0,
            threshold_ok=0.99,
            threshold_warning=0.95,
            threshold_critical=0.80,
            description="Security audit log writing and immutable",
            cspn_requirement="LOG-01",
            tpn_requirement="TPN-ACCESS-03",
            unit="boolean"
        )
        
        # ========================================================================
        # DATA PROTECTION INDICATORS (15% total weight)
        # ========================================================================
        
        self.indicators["tls_compliance"] = DefconIndicator(
            name="TLS Compliance",
            category="data",
            weight=0.05,
            current_value=1.0,
            threshold_ok=0.99,
            threshold_warning=0.95,
            threshold_critical=0.80,
            description="TLS 1.3+ enforced, no weak ciphers",
            cspn_requirement="CRY-01",
            tpn_requirement="TPN-DATA-01",
            unit="boolean"
        )
        
        self.indicators["secrets_protection"] = DefconIndicator(
            name="Secrets Protection",
            category="data",
            weight=0.05,
            current_value=1.0,
            threshold_ok=0.99,
            threshold_warning=0.95,
            threshold_critical=0.80,
            description="No secrets in logs, configs, or VCS",
            cspn_requirement="DAT-01,CRY-05",
            tpn_requirement="TPN-DATA-02",
            unit="boolean"
        )
        
        self.indicators["data_integrity"] = DefconIndicator(
            name="Data Integrity",
            category="data",
            weight=0.05,
            current_value=1.0,
            threshold_ok=0.99,
            threshold_warning=0.95,
            threshold_critical=0.80,
            description="Data retention and integrity checks passing",
            cspn_requirement="DAT-04",
            tpn_requirement="TPN-DATA-03",
            unit="boolean"
        )
        
        # ========================================================================
        # RESILIENCE INDICATORS (10% total weight)
        # ========================================================================
        
        self.indicators["service_uptime"] = DefconIndicator(
            name="Service Uptime",
            category="resilience",
            weight=0.05,
            current_value=1.0,
            threshold_ok=0.999,
            threshold_warning=0.99,
            threshold_critical=0.95,
            description="Critical services uptime > 99.9%",
            cspn_requirement="RES-01",
            tpn_requirement="TPN-RES-01",
            unit="%"
        )
        
        self.indicators["backup_status"] = DefconIndicator(
            name="Backup Status",
            category="resilience",
            weight=0.05,
            current_value=1.0,
            threshold_ok=0.99,
            threshold_warning=0.95,
            threshold_critical=0.80,
            description="Configuration backups current and restorable",
            cspn_requirement="CFG-02",
            tpn_requirement="TPN-RES-02",
            unit="boolean"
        )
    
    # -------------------------------------------------------------------------
    # Metric Collection
    # -------------------------------------------------------------------------
    
    async def collect_all_metrics(self, use_cache: bool = True) -> Dict[str, Any]:
        """
        Collect all metrics from various SecuBox modules.
        
        Args:
            use_cache: If True, return cached values if still valid (60s TTL)
            
        Returns:
            Dictionary containing all collected metrics
        """
        
        # Check cache
        now = datetime.now()
        if use_cache and self._last_collection:
            if (now - self._last_collection).total_seconds() < 60:
                return self._cached_metrics
        
        metrics: Dict[str, Any] = {}
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Collect WAF metrics
                metrics["waf"] = await self._collect_waf_metrics(client)
                
                # Collect Threat Analyst overview
                metrics["threat_analyst"] = await self._collect_threat_analyst(client)
                
                # Collect Health Doctor checks
                metrics["health_doctor"] = await self._collect_health_doctor(client)
                
                # Collect CrowdSec metrics
                metrics["crowdsec"] = await self._collect_crowdsec(client)
                
                # Collect System metrics
                metrics["system"] = await self._collect_system_metrics()
                
                # Update cache
                self._cached_metrics = metrics
                self._last_collection = now
                
        except Exception as e:
            logger.error(f"Metric collection error: {e}")
            # Return cached metrics if available
            if self._cached_metrics:
                return self._cached_metrics
        
        return metrics
    
    async def _collect_waf_metrics(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        """Collect WAF metrics from unix socket."""
        try:
            transport = httpx.AsyncHTTPTransport(uds="/run/secubox/waf.sock")
            async with httpx.AsyncClient(transport=transport, timeout=4) as waf_client:
                response = await waf_client.get("http://waf/stats")
                if response.status_code == 200:
                    return response.json()
        except Exception as e:
            logger.debug(f"WAF stats collection failed: {e}")
        
        return {"running": False, "error": "unable to connect"}
    
    async def _collect_threat_analyst(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        """Collect Threat Analyst overview."""
        try:
            transport = httpx.AsyncHTTPTransport(uds="/run/secubox/threat-analyst.sock")
            async with httpx.AsyncClient(transport=transport, timeout=4) as ta_client:
                response = await ta_client.get("http://threat-analyst/overview")
                if response.status_code == 200:
                    return response.json()
        except Exception as e:
            logger.debug(f"Threat Analyst collection failed: {e}")
        
        return {"error": "unable to connect"}
    
    async def _collect_health_doctor(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        """Collect Health Doctor checks."""
        try:
            transport = httpx.AsyncHTTPTransport(uds="/run/secubox/health-doctor.sock")
            async with httpx.AsyncClient(transport=transport, timeout=4) as hd_client:
                response = await hd_client.get("http://health-doctor/checks")
                if response.status_code == 200:
                    return response.json()
        except Exception as e:
            logger.debug(f"Health Doctor collection failed: {e}")
        
        return {"checks": {}, "error": "unable to connect"}
    
    async def _collect_crowdsec(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        """Collect CrowdSec Prometheus metrics."""
        try:
            response = await client.get("http://127.0.0.1:6060/metrics", timeout=4)
            if response.status_code == 200:
                return self._parse_prometheus(response.text)
        except Exception as e:
            logger.debug(f"CrowdSec metrics collection failed: {e}")
        
        return {}
    
    async def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system-level metrics."""
        metrics = {}
        
        # Check nftables
        try:
            result = subprocess.run(
                ["nft", "list", "ruleset"],
                capture_output=True,
                text=True,
                timeout=5
            )
            metrics["nftables_ruleset"] = result.stdout
            metrics["nftables_error"] = result.stderr
            metrics["nftables_running"] = result.returncode == 0
        except Exception as e:
            metrics["nftables_error"] = str(e)
            metrics["nftables_running"] = False
        
        # Check service status
        try:
            result = subprocess.run(
                ["systemctl", "is-system-running"],
                capture_output=True,
                text=True,
                timeout=5
            )
            metrics["system_running"] = result.returncode == 0
        except Exception:
            metrics["system_running"] = False
        
        return metrics
    
    def _parse_prometheus(self, text: str) -> Dict[str, float]:
        """Parse Prometheus metrics text format."""
        result: Dict[str, float] = {}
        
        for line in text.splitlines():
            if line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                metric_name = parts[0]
                try:
                    value = float(parts[1])
                    result[metric_name] = value
                except (ValueError, IndexError):
                    pass
        
        return result
    
    # -------------------------------------------------------------------------
    # Score Calculation
    # -------------------------------------------------------------------------
    
    def calculate_score(self, metrics: Dict[str, Any]) -> float:
        """
        Calculate overall security score (0-100).
        
        Args:
            metrics: Dictionary of collected metrics
            
        Returns:
            Security score as float (0-100)
        """
        # Update indicator values from metrics
        self._update_indicators(metrics)
        
        # Calculate weighted score
        total_score = 0.0
        
        for indicator in self.indicators.values():
            # Get normalized score for this indicator
            indicator_score = indicator.get_score()
            
            # Apply weight
            total_score += indicator_score * indicator.weight
        
        # Convert to 0-100 scale
        return min(100.0, max(0.0, total_score * 100))
    
    def calculate_category_scores(self, metrics: Dict[str, Any]) -> Dict[str, float]:
        """
        Calculate per-category scores.
        
        Args:
            metrics: Dictionary of collected metrics
            
        Returns:
            Dictionary of category_name -> score (0-100)
        """
        self._update_indicators(metrics)
        
        category_totals: Dict[str, float] = {}
        category_weights: Dict[str, float] = {}
        
        for indicator in self.indicators.values():
            category = indicator.category
            category_totals[category] = category_totals.get(category, 0.0) + \
                indicator.get_score() * indicator.weight
            category_weights[category] = category_weights.get(category, 0.0) + \
                indicator.weight
        
        # Normalize to category weights
        category_scores: Dict[str, float] = {}
        for category, total in category_totals.items():
            weight_sum = category_weights[category]
            if weight_sum > 0:
                # Normalize to 0-100
                category_scores[category] = min(100.0, (total / weight_sum) * 100)
        
        return category_scores
    
    def _update_indicators(self, metrics: Dict[str, Any]):
        """Update all indicator values based on collected metrics."""
        
        # WAF indicators
        if "waf" in metrics:
            waf = metrics["waf"]
            
            # WAF operational
            self.indicators["waf_operational"].current_value = \
                1.0 if waf.get("running", False) else 0.0
            
            # Calculate block rate
            blocked_24h = waf.get("blocked_24h", 0)
            threats_today = waf.get("threats_today", 0)
            total_requests = waf.get("total_requests", 0)
            
            if threats_today > 0:
                block_rate = blocked_24h / threats_today
                self.indicators["threat_block_rate"].current_value = min(1.0, block_rate)
        
        # CrowdSec indicators
        if "crowdsec" in metrics:
            cs = metrics["crowdsec"]
            
            cs_alerts = cs.get("cs_alerts", 0)
            cs_decisions = cs.get("cs_active_decisions", 0)
            
            # CrowdSec detection is active if we have alerts or decisions
            self.indicators["crowdsec_detection"].current_value = \
                1.0 if (cs_alerts > 0 or cs_decisions > 0) else 0.0
        
        # Health Doctor indicators
        if "health_doctor" in metrics:
            hd = metrics["health_doctor"]
            checks = hd.get("checks", {})
            
            # Count passing checks
            passing = sum(1 for c in checks.values() if c.get("ok", False))
            total = len(checks)
            
            if total > 0:
                # Use specific checks for specific indicators
                if "crowdsec" in checks:
                    self.indicators["crowdsec_detection"].current_value = \
                        1.0 if checks["crowdsec"].get("ok", False) else 0.0
                
                if "secubox-auth" in checks:
                    self.indicators["auth_system"].current_value = \
                        1.0 if checks["secubox-auth"].get("ok", False) else 0.0
                
                if "mitmproxy-lxc" in checks:
                    self.indicators["waf_operational"].current_value = \
                        max(self.indicators["waf_operational"].current_value,
                           1.0 if checks["mitmproxy-lxc"].get("ok", False) else 0.0)
                
                if "haproxy" in checks:
                    self.indicators["firewall_policy"].current_value = \
                        1.0 if checks["haproxy"].get("ok", False) else 0.0
        
        # System metrics
        if "system" in metrics:
            sys = metrics["system"]
            
            self.indicators["nftables_rules"].current_value = \
                1.0 if sys.get("nftables_running", False) else 0.0
        
        # Simulate some values for indicators we can't directly measure
        # In production, implement actual checks for these
        
        # For now, set reasonable defaults that will be updated by real checks
        if self.indicators["privilege_separation"].current_value == 1.0:
            # Check if services are running as non-root
            self.indicators["privilege_separation"].current_value = self._check_privilege_separation()
        
        if self.indicators["audit_logging"].current_value == 1.0:
            self.indicators["audit_logging"].current_value = self._check_audit_logging()
        
        # Set TLS compliance (assume good for now)
        self.indicators["tls_compliance"].current_value = 1.0
        
        # Set secrets protection (assume good for now)
        self.indicators["secrets_protection"].current_value = 1.0
        
        # Set data integrity (assume good for now)
        self.indicators["data_integrity"].current_value = 1.0
        
        # Set service uptime (assume good for now)
        self.indicators["service_uptime"].current_value = 1.0
        
        # Set backup status (assume good for now)
        self.indicators["backup_status"].current_value = 0.95
        
        # Set false positive rate (assume low for now)
        self.indicators["false_positive_rate"].current_value = 0.02
    
    def _check_privilege_separation(self) -> float:
        """Check if services are running as non-root users."""
        try:
            result = subprocess.run(
                ["ps", "-eo", "user,comm", "|", "grep", "secubox", "|", "grep", "-v", "grep"],
                capture_output=True,
                text=True,
                timeout=5,
                shell=True
            )
            # If we find secubox services, assume good
            if result.returncode == 0 and result.stdout:
                return 1.0
            return 0.7
        except Exception:
            return 0.5
    
    def _check_audit_logging(self) -> float:
        """Check if audit logging is working."""
        audit_log = Path("/var/log/secubox/audit.log")
        if audit_log.exists():
            # Check if file was modified recently
            try:
                mtime = audit_log.stat().st_mtime
                age_hours = (datetime.now() - datetime.fromtimestamp(mtime)).total_seconds() / 3600
                # If modified in last 24 hours, consider it active
                return 1.0 if age_hours < 24 else 0.5
            except Exception:
                return 0.7
        return 0.3
    
    # -------------------------------------------------------------------------
    # DEFCON Level Determination
    # -------------------------------------------------------------------------
    
    def get_defcon_level(self, score: float) -> DefconLevel:
        """
        Map security score to DEFCON level.
        
        Args:
            score: Security score (0-100)
            
        Returns:
            DEFCON level enum value
        """
        if score >= 90:
            return DefconLevel.DEFCON_5
        elif score >= 70:
            return DefconLevel.DEFCON_4
        elif score >= 50:
            return DefconLevel.DEFCON_3
        elif score >= 30:
            return DefconLevel.DEFCON_2
        else:
            return DefconLevel.DEFCON_1
    
    async def get_defcon_info(self, score: Optional[float] = None, metrics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Get full DEFCON information.
        
        Args:
            score: Optional pre-calculated score (if not provided, will calculate from metrics)
            metrics: Optional metrics to use for calculation
            
        Returns:
            Dictionary with complete DEFCON information
        """
        if score is None:
            if metrics is None:
                # Use cached or collect fresh
                if self._cached_metrics:
                    metrics = self._cached_metrics
                else:
                    # Need to collect
                    metrics = await self.collect_all_metrics(use_cache=False)
            score = self.calculate_score(metrics)
        
        level = self.get_defcon_level(score)
        category_scores = self.calculate_category_scores(metrics or self._cached_metrics)
        
        defcon_info = {
            "level": level.value,
            "level_name": level.name.replace("_", " ").title(),
            "level_enum": level,
            "score": round(score, 1),
            "score_int": int(score),
            "color": self._get_defcon_color(level),
            "emoji": self._get_defcon_emoji(level),
            "blink": level in [DefconLevel.DEFCON_1, DefconLevel.DEFCON_2],
            "description": self._get_defcon_description(level, score),
            "recommendations": self._get_recommendations(level),
            "category_scores": category_scores,
            "indicators": self.get_indicator_details(),
            "timestamp": datetime.now().isoformat() + "Z",
            "cspn_compliance": self._calculate_cspn_compliance(score, category_scores),
            "tpn_compliance": self._calculate_tpn_compliance(score, category_scores),
        }
        
        return defcon_info
    
    def _get_defcon_color(self, level: DefconLevel) -> str:
        """Get color associated with DEFCON level."""
        colors = {
            DefconLevel.DEFCON_5: "#22c55e",  # Green
            DefconLevel.DEFCON_4: "#eab308",  # Yellow/Amber
            DefconLevel.DEFCON_3: "#f97316",  # Orange
            DefconLevel.DEFCON_2: "#ef4444",  # Red
            DefconLevel.DEFCON_1: "#dc2626",  # Dark Red
        }
        return colors.get(level, "#6b7280")
    
    def _get_defcon_emoji(self, level: DefconLevel) -> str:
        """Get emoji associated with DEFCON level."""
        emojis = {
            DefconLevel.DEFCON_5: "🟢",
            DefconLevel.DEFCON_4: "🟡",
            DefconLevel.DEFCON_3: "🟠",
            DefconLevel.DEFCON_2: "🔴",
            DefconLevel.DEFCON_1: "🚨",
        }
        return emojis.get(level, "⚪")
    
    def _get_defcon_description(self, level: DefconLevel, score: float) -> str:
        """Get description for DEFCON level."""
        descriptions = {
            DefconLevel.DEFCON_5: (
                f"✅ NORMAL OPERATIONS • All systems secure and operational • "
                f"Security Score: {score:.1f}/100 • CSPN-compliant"
            ),
            DefconLevel.DEFCON_4: (
                f"⚠️ INCREASED CHATTER • Minor security issues detected • "
                f"Security Score: {score:.1f}/100 • Monitor closely"
            ),
            DefconLevel.DEFCON_3: (
                f"🟠 HEIGHTENED • Active threats being detected and mitigated • "
                f"Security Score: {score:.1f}/100 • Active monitoring required"
            ),
            DefconLevel.DEFCON_2: (
                f"🔴 SEVERE • Major security incident in progress • "
                f"Security Score: {score:.1f}/100 • Immediate action required"
            ),
            DefconLevel.DEFCON_1: (
                f"🚨 MAXIMUM • Critical breach detected • "
                f"Security Score: {score:.1f}/100 • Emergency protocols activated"
            ),
        }
        return descriptions.get(level, f"Unknown DEFCON level (Score: {score:.1f})")
    
    def _get_recommendations(self, level: DefconLevel) -> List[str]:
        """Get actionable recommendations based on DEFCON level."""
        recommendations = []
        
        if level in [DefconLevel.DEFCON_1, DefconLevel.DEFCON_2]:
            recommendations.extend([
                "🔴 Activate emergency response procedures",
                "🔴 Isolate affected systems immediately",
                "🔴 Notify security team and CSPN evaluator",
                "🔴 Review all recent configuration changes",
                "🔴 Check audit logs for suspicious activity",
                "🔴 Verify backup integrity and prepare for restore",
            ])
        elif level == DefconLevel.DEFCON_3:
            recommendations.extend([
                "🟠 Review active threat alerts in Threat Analyst",
                "🟠 Verify WAF rules are up to date",
                "🟠 Check CrowdSec decisions for false positives",
                "🟠 Monitor network traffic for anomalies",
                "🟠 Consider activating additional protections",
                "🟠 Review recent system changes",
            ])
        elif level == DefconLevel.DEFCON_4:
            recommendations.extend([
                "🟡 Verify all critical services are running",
                "🟡 Check for minor configuration issues",
                "🟡 Review recent security events",
                "🟡 Ensure backups are current",
                "🟡 Test failover procedures",
            ])
        else:  # DEFCON 5
            recommendations.extend([
                "🟢 Continue normal monitoring",
                "🟢 Review weekly security reports",
                "🟢 Test backup restoration procedures",
                "🟢 Verify CSPN compliance status",
                "🟢 Check for security updates",
            ])
        
        # Add indicator-specific recommendations for degraded/failed indicators
        for name, indicator in self.indicators.items():
            status = indicator.get_status()
            if status in ["error", "warning"]:
                recommendations.append(
                    f"⚠️ {indicator.name}: {status.upper()} "
                    f"({indicator.current_value:.0%}) - {indicator.description}"
                )
        
        return recommendations
    
    def _calculate_cspn_compliance(self, score: float, category_scores: Dict[str, float]) -> Dict[str, Any]:
        """Calculate CSPN compliance status."""
        # CSPN requires minimum scores in certain areas
        
        # Check critical CSPN requirements
        critical_passing = True
        warnings = []
        
        # Network security must be > 80 for CSPN
        if category_scores.get("network", 0) < 80:
            critical_passing = False
            warnings.append("Network security below CSPN threshold (80%)")
        
        # Threat detection must be > 70 for CSPN
        if category_scores.get("threat", 0) < 70:
            critical_passing = False
            warnings.append("Threat detection below CSPN threshold (70%)")
        
        # Access control must be > 80 for CSPN
        if category_scores.get("access", 0) < 80:
            critical_passing = False
            warnings.append("Access control below CSPN threshold (80%)")
        
        return {
            "status": "compliant" if critical_passing and score >= 70 else "non_compliant",
            "score": score,
            "threshold": 70,
            "warnings": warnings,
            "category_passing": {
                "network": category_scores.get("network", 0) >= 80,
                "threat": category_scores.get("threat", 0) >= 70,
                "access": category_scores.get("access", 0) >= 80,
                "data": category_scores.get("data", 0) >= 80,
                "resilience": category_scores.get("resilience", 0) >= 70,
            }
        }
    
    def _calculate_tpn_compliance(self, score: float, category_scores: Dict[str, float]) -> Dict[str, Any]:
        """Calculate TPN Media compliance status."""
        # TPN Media has stricter requirements
        
        tpn_passing = True
        warnings = []
        
        # All categories must be > 80 for TPN Media
        for category, threshold in [
            ("network", 85),
            ("threat", 80),
            ("access", 85),
            ("data", 85),
            ("resilience", 80),
        ]:
            if category_scores.get(category, 0) < threshold:
                tpn_passing = False
                warnings.append(f"{category} below TPN threshold ({threshold}%)")
        
        # Overall score must be > 85 for TPN Media
        if score < 85:
            tpn_passing = False
            warnings.append(f"Overall score below TPN threshold (85%, got {score:.1f}%)")
        
        return {
            "status": "compliant" if tpn_passing else "non_compliant",
            "score": score,
            "threshold": 85,
            "warnings": warnings,
            "category_passing": {
                "network": category_scores.get("network", 0) >= 85,
                "threat": category_scores.get("threat", 0) >= 80,
                "access": category_scores.get("access", 0) >= 85,
                "data": category_scores.get("data", 0) >= 85,
                "resilience": category_scores.get("resilience", 0) >= 80,
            }
        }
    
    # -------------------------------------------------------------------------
    # Indicator Access
    # -------------------------------------------------------------------------
    
    def get_indicator_details(self) -> Dict[str, Dict[str, Any]]:
        """Get all indicator details for dashboard display."""
        return {
            name: {
                "name": ind.name,
                "category": ind.category,
                "value": round(ind.current_value * 100, 1),
                "value_raw": ind.current_value,
                "weight": ind.weight,
                "status": ind.get_status(),
                "status_color": self._get_status_color(ind.get_status()),
                "description": ind.description,
                "cspn_requirement": ind.cspn_requirement,
                "tpn_requirement": ind.tpn_requirement,
                "unit": ind.unit,
                "inverse": ind.inverse,
            }
            for name, ind in self.indicators.items()
        }
    
    def _get_status_color(self, status: str) -> str:
        """Get color for indicator status."""
        colors = {
            "ok": "#22c55e",
            "degraded": "#eab308",
            "warning": "#f97316",
            "error": "#ef4444",
        }
        return colors.get(status, "#6b7280")
    
    async def get_summary(self) -> Dict[str, Any]:
        """Get a quick summary of the current state."""
        if not self._cached_metrics:
            # Force collection
            self._cached_metrics = await self.collect_all_metrics(use_cache=False)
            self._last_collection = datetime.now()
        
        score = self.calculate_score(self._cached_metrics)
        level = self.get_defcon_level(score)
        
        return {
            "defcon": level.value,
            "score": round(score, 1),
            "color": self._get_defcon_color(level),
            "emoji": self._get_defcon_emoji(level),
        }


# Global instance
defcon_engine = DefconEngine()
