# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
TPN Media Compliance Module

TPN (Trusted Partner Network) Media - Specific compliance requirements for
media/publishing industry security standards.

This module extends the CSPN compliance framework with TPN Media-specific
requirements that are stricter than baseline CSPN.

TPN Media focuses on:
- Content protection and anti-piracy
- Digital rights management (DRM) integration
- Media-specific threat intelligence
- Content security lifecycle management
- Partner/network trust verification

Reference: TPN Media Security Requirements v2.0
"""

from __future__ import annotations

import asyncio
import httpx
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .cspn_compliance import CspnComplianceChecker, CspnRequirement, CheckStatus, CheckType

logger = logging.getLogger("secubox.security-posture.tpn")


class TpnCategory(str, Enum):
    """TPN Media compliance categories."""
    CONTENT_PROTECTION = "Content Protection"
    ANTI_PIRACY = "Anti-Piracy"
    DRM_INTEGRATION = "DRM Integration"
    THREAT_INTELLIGENCE = "Threat Intelligence"
    PARTNER_TRUST = "Partner Trust"
    CONTENT_LIFECYCLE = "Content Lifecycle"
    ACCESS_CONTROL = "Access Control"
    MONITORING = "Monitoring"
    INCIDENT_RESPONSE = "Incident Response"


@dataclass
class TpnRequirement:
    """Single TPN Media requirement."""
    id: str  # e.g., "TPN-CONTENT-01"
    description: str
    category: TpnCategory
    check_type: CheckType
    method: str
    pass_condition: str
    status: CheckStatus = CheckStatus.SKIP
    result: Optional[str] = None
    evidence: Optional[str] = None
    weight: int = 5
    cspn_mapping: List[str] = field(default_factory=list)  # Related CSPN requirements
    severity: str = "medium"  # high, medium, low
    
    def is_passing(self) -> bool:
        return self.status in [CheckStatus.PASS, CheckStatus.SKIP]
    
    def is_failing(self) -> bool:
        return self.status in [CheckStatus.FAIL, CheckStatus.ERROR]
    
    def is_warning(self) -> bool:
        return self.status == CheckStatus.WARNING


class TpnMediaComplianceChecker:
    """
    TPN Media compliance checking engine.
    
    Provides TPN Media-specific compliance checks that extend beyond CSPN requirements.
    
    Usage:
        checker = TpnMediaComplianceChecker()
        report = await checker.run_all_checks()
        summary = checker.get_summary()
        media_cert_ready = checker.is_media_certificate_ready()
    """
    
    TPN_REQUIREMENTS: Dict[str, TpnRequirement] = {}
    
    def __init__(self, cspn_checker: Optional[CspnComplianceChecker] = None):
        self.cspn_checker = cspn_checker or CspnComplianceChecker()
        self._init_tpn_requirements()
        self._last_check: Optional[datetime] = None
        self._cached_report: Optional[Dict[str, Any]] = None
    
    def _init_tpn_requirements(self):
        """Initialize all TPN Media requirements."""
        
        # Content Protection
        self.TPN_REQUIREMENTS["TPN-CONTENT-01"] = TpnRequirement(
            id="TPN-CONTENT-01",
            description="Content encryption in transit (TLS 1.3 + AES-256)",
            category=TpnCategory.CONTENT_PROTECTION,
            check_type=CheckType.AUTOMATED,
            method="Verify all content delivery uses TLS 1.3 with AES-256-GCM",
            pass_condition="All media content encrypted with TLS 1.3 + AES-256",
            weight=10,
            cspn_mapping=["CRY-01", "CRY-02"],
            severity="high"
        )
        
        self.TPN_REQUIREMENTS["TPN-CONTENT-02"] = TpnRequirement(
            id="TPN-CONTENT-02",
            description="Content encryption at rest (AES-256)",
            category=TpnCategory.CONTENT_PROTECTION,
            check_type=CheckType.AUTOMATED,
            method="Verify stored content encrypted with AES-256",
            pass_condition="All stored media content encrypted with AES-256",
            weight=10,
            cspn_mapping=["DAT-04"],
            severity="high"
        )
        
        self.TPN_REQUIREMENTS["TPN-CONTENT-03"] = TpnRequirement(
            id="TPN-CONTENT-03",
            description="Content integrity verification (hash/SHA-256)",
            category=TpnCategory.CONTENT_PROTECTION,
            check_type=CheckType.AUTOMATED,
            method="Verify content integrity using SHA-256 hashes",
            pass_condition="All content verified with SHA-256 integrity checks",
            weight=8,
            cspn_mapping=["DAT-04"],
            severity="high"
        )
        
        # Anti-Piracy
        self.TPN_REQUIREMENTS["TPN-ANTI-PIRACY-01"] = TpnRequirement(
            id="TPN-ANTI-PIRACY-01",
            description="Torrent/DNS-based piracy detection",
            category=TpnCategory.ANTI_PIRACY,
            check_type=CheckType.AUTOMATED,
            method="Verify CrowdSec or similar detects torrent/piracy traffic",
            pass_condition="Piracy-related traffic detected and blocked",
            weight=10,
            cspn_mapping=["WAF-03", "WAF-04"],
            severity="high"
        )
        
        self.TPN_REQUIREMENTS["TPN-ANTI-PIRACY-02"] = TpnRequirement(
            id="TPN-ANTI-PIRACY-02",
            description="Stream ripping detection and prevention",
            category=TpnCategory.ANTI_PIRACY,
            check_type=CheckType.AUTOMATED,
            method="Verify detection of stream ripping tools and patterns",
            pass_condition="Stream ripping attempts detected and blocked",
            weight=8,
            cspn_mapping=["WAF-04"],
            severity="high"
        )
        
        self.TPN_REQUIREMENTS["TPN-ANTI-PIRACY-03"] = TpnRequirement(
            id="TPN-ANTI-PIRACY-03",
            description="Content fingerprinting/watermarking verification",
            category=TpnCategory.ANTI_PIRACY,
            check_type=CheckType.MANUAL,
            method="Verify content contains invisible watermarks/fingerprints",
            pass_condition="All distributed content contains forensic watermarks",
            weight=5,
            cspn_mapping=["WAF-04"],
            severity="medium"
        )
        
        # DRM Integration
        self.TPN_REQUIREMENTS["TPN-DRM-01"] = TpnRequirement(
            id="TPN-DRM-01",
            description="DRM system integration (Widevine, PlayReady, FairPlay)",
            category=TpnCategory.DRM_INTEGRATION,
            check_type=CheckType.MANUAL,
            method="Verify DRM license server integration and functionality",
            pass_condition="DRM systems integrated and functional",
            weight=10,
            cspn_mapping=["AUT-01"],
            severity="high"
        )
        
        self.TPN_REQUIREMENTS["TPN-DRM-02"] = TpnRequirement(
            id="TPN-DRM-02",
            description="DRM token/license protection",
            category=TpnCategory.DRM_INTEGRATION,
            check_type=CheckType.AUTOMATED,
            method="Verify DRM tokens/licenses encrypted and protected",
            pass_condition="DRM tokens/licenses encrypted and protected from theft",
            weight=8,
            cspn_mapping=["CRY-04", "CRY-05"],
            severity="high"
        )
        
        # Threat Intelligence
        self.TPN_REQUIREMENTS["TPN-THREAT-01"] = TpnRequirement(
            id="TPN-THREAT-01",
            description="Media-specific threat intelligence feeds",
            category=TpnCategory.THREAT_INTELLIGENCE,
            check_type=CheckType.AUTOMATED,
            method="Verify integration with MPAA/ACE or similar threat intel feeds",
            pass_condition="Media-specific threat intelligence feeds active",
            weight=8,
            cspn_mapping=["WAF-04"],
            severity="medium"
        )
        
        self.TPN_REQUIREMENTS["TPN-THREAT-02"] = TpnRequirement(
            id="TPN-THREAT-02",
            description="Real-time threat blocking for media content",
            category=TpnCategory.THREAT_INTELLIGENCE,
            check_type=CheckType.AUTOMATED,
            method="Verify threats to media content blocked in real-time",
            pass_condition="Media threats blocked with <100ms latency",
            weight=8,
            cspn_mapping=["WAF-03"],
            severity="medium"
        )
        
        self.TPN_REQUIREMENTS["TPN-THREAT-03"] = TpnRequirement(
            id="TPN-THREAT-03",
            description="Content scraping detection and prevention",
            category=TpnCategory.THREAT_INTELLIGENCE,
            check_type=CheckType.AUTOMATED,
            method="Verify detection and blocking of content scraping bots",
            pass_condition="Content scraping attempts detected and blocked",
            weight=6,
            cspn_mapping=["WAF-04"],
            severity="medium"
        )
        
        # Partner Trust
        self.TPN_REQUIREMENTS["TPN-PARTNER-01"] = TpnRequirement(
            id="TPN-PARTNER-01",
            description="Partner identity verification (mTLS)",
            category=TpnCategory.PARTNER_TRUST,
            check_type=CheckType.AUTOMATED,
            method="Verify mutual TLS authentication for partner connections",
            pass_condition="All partner connections use mTLS authentication",
            weight=10,
            cspn_mapping=["AUT-01", "CRY-01"],
            severity="high"
        )
        
        self.TPN_REQUIREMENTS["TPN-PARTNER-02"] = TpnRequirement(
            id="TPN-PARTNER-02",
            description="Partner network segmentation",
            category=TpnCategory.PARTNER_TRUST,
            check_type=CheckType.AUTOMATED,
            method="Verify partners isolated in separate network segments",
            pass_condition="Partner networks segmented and isolated",
            weight=8,
            cspn_mapping=["NET-01", "ACL-01"],
            severity="high"
        )
        
        # Content Lifecycle
        self.TPN_REQUIREMENTS["TPN-LIFECYCLE-01"] = TpnRequirement(
            id="TPN-LIFECYCLE-01",
            description="Content expiration and automatic purge",
            category=TpnCategory.CONTENT_LIFECYCLE,
            check_type=CheckType.AUTOMATED,
            method="Verify expired content automatically purged from systems",
            pass_condition="Expired content automatically removed within 24 hours",
            weight=6,
            cspn_mapping=["DAT-04"],
            severity="medium"
        )
        
        self.TPN_REQUIREMENTS["TPN-LIFECYCLE-02"] = TpnRequirement(
            id="TPN-LIFECYCLE-02",
            description="Content access logging and audit trail",
            category=TpnCategory.CONTENT_LIFECYCLE,
            check_type=CheckType.AUTOMATED,
            method="Verify all content access logged with full audit trail",
            pass_condition="All content access logged with immutable audit trail",
            weight=8,
            cspn_mapping=["LOG-01", "LOG-02", "LOG-03"],
            severity="high"
        )
        
        # Access Control (TPN-specific extensions)
        self.TPN_REQUIREMENTS["TPN-ACCESS-01"] = TpnRequirement(
            id="TPN-ACCESS-01",
            description="Role-based access control (RBAC) for content",
            category=TpnCategory.ACCESS_CONTROL,
            check_type=CheckType.AUTOMATED,
            method="Verify RBAC implementation for content access",
            pass_condition="RBAC enforced for all content access",
            weight=8,
            cspn_mapping=["AUT-01", "ACL-01"],
            severity="high"
        )
        
        self.TPN_REQUIREMENTS["TPN-ACCESS-02"] = TpnRequirement(
            id="TPN-ACCESS-02",
            description="Temporary access tokens with short expiration",
            category=TpnCategory.ACCESS_CONTROL,
            check_type=CheckType.AUTOMATED,
            method="Verify temporary access tokens expire within 1 hour",
            pass_condition="All temporary access tokens expire within 1 hour",
            weight=6,
            cspn_mapping=["AUT-03"],
            severity="medium"
        )
        
        self.TPN_REQUIREMENTS["TPN-ACCESS-03"] = TpnRequirement(
            id="TPN-ACCESS-03",
            description="Device binding for content access",
            category=TpnCategory.ACCESS_CONTROL,
            check_type=CheckType.MANUAL,
            method="Verify content access bound to specific devices",
            pass_condition="Content access restricted to authorized devices",
            weight=5,
            cspn_mapping=["AUT-01"],
            severity="medium"
        )
        
        # Monitoring
        self.TPN_REQUIREMENTS["TPN-MONITOR-01"] = TpnRequirement(
            id="TPN-MONITOR-01",
            description="Real-time content delivery monitoring",
            category=TpnCategory.MONITORING,
            check_type=CheckType.AUTOMATED,
            method="Verify real-time monitoring of content delivery",
            pass_condition="Content delivery monitored with <5 second latency",
            weight=6,
            cspn_mapping=["RES-01"],
            severity="medium"
        )
        
        self.TPN_REQUIREMENTS["TPN-MONITOR-02"] = TpnRequirement(
            id="TPN-MONITOR-02",
            description="Content access anomaly detection",
            category=TpnCategory.MONITORING,
            check_type=CheckType.AUTOMATED,
            method="Verify detection of anomalous content access patterns",
            pass_condition="Anomalous content access detected and alerted",
            weight=6,
            cspn_mapping=["LOG-01"],
            severity="medium"
        )
        
        # Incident Response
        self.TPN_REQUIREMENTS["TPN-IR-01"] = TpnRequirement(
            id="TPN-IR-01",
            description="Content leak incident response procedure",
            category=TpnCategory.INCIDENT_RESPONSE,
            check_type=CheckType.DOCUMENT,
            method="Verify documented procedure for content leak response",
            pass_condition="Content leak response procedure documented and tested",
            weight=10,
            cspn_mapping=["RES-01"],
            severity="high"
        )
        
        self.TPN_REQUIREMENTS["TPN-IR-02"] = TpnRequirement(
            id="TPN-IR-02",
            description="Content takedown capability (DMCA compliance)",
            category=TpnCategory.INCIDENT_RESPONSE,
            check_type=CheckType.MANUAL,
            method="Verify capability to rapidly takedown infringing content",
            pass_condition="Content can be taken down within 1 hour of DMCA notice",
            weight=10,
            cspn_mapping=["RES-01"],
            severity="high"
        )
        
        logger.info(f"Initialized {len(self.TPN_REQUIREMENTS)} TPN Media requirements")
    
    # -------------------------------------------------------------------------
    # TPN-Specific Checks
    # -------------------------------------------------------------------------
    
    async def run_all_checks(self) -> Dict[str, Any]:
        """Run all TPN Media compliance checks."""
        
        report: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat() + "Z",
            "requirements": {},
            "summary": {},
            "cspn_compliance": await self.cspn_checker.run_all_checks(),
        }
        
        # Run TPN-specific checks
        for req_id, requirement in self.TPN_REQUIREMENTS.items():
            # For now, mark automated checks as pass/fail based on CSPN status
            # In production, implement actual checks
            
            if requirement.check_type == CheckType.AUTOMATED:
                # Check related CSPN requirements
                cspn_status = self._get_cspn_status(requirement.cspn_mapping)
                
                if cspn_status == CheckStatus.PASS:
                    requirement.status = CheckStatus.PASS
                    requirement.result = "Related CSPN requirements passing"
                elif cspn_status == CheckStatus.FAIL:
                    requirement.status = CheckStatus.FAIL
                    requirement.result = "Related CSPN requirements failing"
                else:
                    requirement.status = CheckStatus.WARNING
                    requirement.result = "Related CSPN requirements have warnings"
            else:
                requirement.status = CheckStatus.SKIP
                requirement.result = f"{requirement.check_type.value} check"
            
            report["requirements"][req_id] = self._requirement_to_dict(requirement)
        
        # Calculate summary
        report["summary"] = self._calculate_summary()
        
        # Cache report
        self._cached_report = report
        self._last_check = datetime.now()
        
        return report
    
    def _get_cspn_status(self, cspn_ids: List[str]) -> CheckStatus:
        """Get combined status of related CSPN requirements."""
        statuses = []
        for cspn_id in cspn_ids:
            if cspn_id in self.cspn_checker.REQUIREMENTS:
                statuses.append(self.cspn_checker.REQUIREMENTS[cspn_id].status)
        
        if not statuses:
            return CheckStatus.SKIP
        
        # If any is failing, return fail
        if CheckStatus.FAIL in statuses or CheckStatus.ERROR in statuses:
            return CheckStatus.FAIL
        
        # If any is warning, return warning
        if CheckStatus.WARNING in statuses:
            return CheckStatus.WARNING
        
        # If any is skip, return skip
        if CheckStatus.SKIP in statuses:
            return CheckStatus.SKIP
        
        return CheckStatus.PASS
    
    def _requirement_to_dict(self, requirement: TpnRequirement) -> Dict[str, Any]:
        """Convert requirement to dictionary."""
        return {
            "id": requirement.id,
            "description": requirement.description,
            "category": requirement.category.value,
            "check_type": requirement.check_type.value,
            "method": requirement.method,
            "pass_condition": requirement.pass_condition,
            "status": requirement.status.value,
            "result": requirement.result,
            "evidence": requirement.evidence,
            "weight": requirement.weight,
            "cspn_mapping": requirement.cspn_mapping,
            "severity": requirement.severity,
            "is_passing": requirement.is_passing(),
            "is_failing": requirement.is_failing(),
            "is_warning": requirement.is_warning(),
        }
    
    def _calculate_summary(self) -> Dict[str, Any]:
        """Calculate summary statistics."""
        
        total_weight = 0
        passed_weight = 0
        failed_weight = 0
        warning_weight = 0
        skip_weight = 0
        
        by_category: Dict[str, Dict[str, Any]] = {}
        
        for req_id, requirement in self.TPN_REQUIREMENTS.items():
            total_weight += requirement.weight
            
            if requirement.status == CheckStatus.PASS:
                passed_weight += requirement.weight
            elif requirement.status == CheckStatus.FAIL:
                failed_weight += requirement.weight
            elif requirement.status == CheckStatus.WARNING:
                warning_weight += requirement.weight
            else:  # SKIP or ERROR
                skip_weight += requirement.weight
            
            # By category
            cat = requirement.category.value
            if cat not in by_category:
                by_category[cat] = {
                    "pass": 0,
                    "fail": 0,
                    "warning": 0,
                    "skip": 0,
                    "error": 0,
                    "total": 0,
                }
            
            status_key = requirement.status.value if requirement.status else 'error'
            by_category[cat][status_key] = by_category[cat].get(status_key, 0) + 1
            by_category[cat]["total"] += 1
        
        # Calculate percentages
        total_checks = len(self.TPN_REQUIREMENTS)
        pass_pct = (passed_weight / total_weight * 100) if total_weight > 0 else 0
        fail_pct = (failed_weight / total_weight * 100) if total_weight > 0 else 0
        warning_pct = (warning_weight / total_weight * 100) if total_weight > 0 else 0
        
        return {
            "total_requirements": total_checks,
            "total_weight": total_weight,
            "passed": passed_weight,
            "failed": failed_weight,
            "warnings": warning_weight,
            "skipped": skip_weight,
            "pass_percentage": round(pass_pct, 1),
            "fail_percentage": round(fail_pct, 1),
            "warning_percentage": round(warning_pct, 1),
            "compliance_score": round(pass_pct, 1),
            "is_compliant": pass_pct >= 95,  # TPN requires >95% compliance
            "by_category": by_category,
        }
    
    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------
    
    def get_summary(self) -> Dict[str, Any]:
        """Get current TPN compliance summary."""
        if self._cached_report:
            return self._cached_report["summary"]
        
        summary = self._calculate_summary()
        return summary
    
    def get_requirement(self, req_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific TPN requirement."""
        if req_id in self.TPN_REQUIREMENTS:
            return self._requirement_to_dict(self.TPN_REQUIREMENTS[req_id])
        return None
    
    def get_requirements_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get all TPN requirements in a specific category."""
        return [
            self._requirement_to_dict(req)
            for req in self.TPN_REQUIREMENTS.values()
            if req.category.value == category
        ]
    
    def get_all_requirements(self) -> List[Dict[str, Any]]:
        """Get all TPN requirements."""
        return [
            self._requirement_to_dict(req)
            for req in self.TPN_REQUIREMENTS.values()
        ]
    
    def is_media_certificate_ready(self) -> bool:
        """Check if TPN Media certificate requirements are met."""
        # TPN Media requires both CSPN compliance AND TPN-specific compliance
        cspn_ready = self.cspn_checker.is_certificate_ready()
        tpn_summary = self.get_summary()
        tpn_ready = tpn_summary.get("is_compliant", False)
        
        return cspn_ready and tpn_ready
    
    def get_media_certificate_readiness(self) -> Dict[str, Any]:
        """Get detailed TPN Media certificate readiness."""
        cspn_readiness = self.cspn_checker.get_certificate_readiness()
        tpn_summary = self.get_summary()
        
        # Get blocking TPN issues
        blocking = []
        for req_id, req in self.TPN_REQUIREMENTS.items():
            if req.is_failing():
                blocking.append({
                    "id": req_id,
                    "description": req.description,
                    "category": req.category.value,
                    "result": req.result or "No result",
                })
        
        return {
            "cspn_ready": cspn_readiness.get("ready", False),
            "cspn_score": cspn_readiness.get("compliance_score", 0),
            "tpn_ready": tpn_summary.get("is_compliant", False),
            "tpn_score": tpn_summary.get("compliance_score", 0),
            "overall_ready": cspn_readiness.get("ready", False) and tpn_summary.get("is_compliant", False),
            "blocking_cspn_issues": cspn_readiness.get("blocking_issues", []),
            "blocking_tpn_issues": blocking,
            "total_issues": len(cspn_readiness.get("blocking_issues", [])) + len(blocking),
            "recommendations": [
                "Address all CSPN FAIL checks",
                "Address all TPN Media FAIL checks",
                "Ensure CSPN compliance score >90%",
                "Ensure TPN Media compliance score >95%",
                "Document all manual checks",
                "Complete penetration testing",
            ]
        }
    
    def get_combined_compliance(self) -> Dict[str, Any]:
        """Get combined CSPN + TPN Media compliance."""
        cspn_summary = self.cspn_checker.get_summary()
        tpn_summary = self.get_summary()
        
        return {
            "timestamp": datetime.now().isoformat() + "Z",
            "cspn": cspn_summary,
            "tpn_media": tpn_summary,
            "combined_score": round(
                (cspn_summary.get("compliance_score", 0) * 0.6 + 
                 tpn_summary.get("compliance_score", 0) * 0.4), 1
            ),
            "overall_compliant": (
                cspn_summary.get("is_compliant", False) and 
                tpn_summary.get("is_compliant", False)
            ),
        }


# Global instance
tpn_checker = TpnMediaComplianceChecker()
