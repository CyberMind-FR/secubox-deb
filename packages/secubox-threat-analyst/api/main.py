"""SecuBox Threat Analyst - AI-Powered Security Analysis
Monitors CrowdSec alerts, WAF logs, and DPI events to generate
security filters and recommendations using LocalAI.

Features:
- Real-time threat monitoring
- AI-powered pattern analysis
- Automatic filter generation (mitmproxy, CrowdSec, WAF)
- Approval workflow for rule deployment
"""
import os
import json
import time
import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration
CONFIG_PATH = Path("/etc/secubox/threat-analyst.toml")
DATA_DIR = Path("/var/lib/secubox/threat-analyst")
ALERTS_FILE = DATA_DIR / "alerts.jsonl"
RULES_FILE = DATA_DIR / "generated_rules.json"
QUEUE_FILE = DATA_DIR / "pending_rules.json"

app = FastAPI(title="SecuBox Threat Analyst", version="1.0.0")
logger = logging.getLogger("secubox.threat-analyst")


class RuleType(str, Enum):
    MITMPROXY = "mitmproxy"
    CROWDSEC = "crowdsec"
    WAF = "waf"
    NFTABLES = "nftables"


class RuleStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"


class ThreatAlert(BaseModel):
    id: str
    source: str  # crowdsec, waf, dpi, mitmproxy
    severity: str  # critical, high, medium, low, info
    type: str
    ip: Optional[str] = None
    details: Dict[str, Any] = {}
    timestamp: str
    analyzed: bool = False
    analysis: Optional[str] = None


class GeneratedRule(BaseModel):
    id: str
    type: RuleType
    name: str
    description: str
    rule_content: str
    source_alerts: List[str] = []
    status: RuleStatus = RuleStatus.PENDING
    created_at: str
    approved_at: Optional[str] = None
    applied_at: Optional[str] = None
    confidence: float = 0.0


class AnalysisRequest(BaseModel):
    alert_ids: Optional[List[str]] = None
    hours: int = 24
    auto_generate: bool = False


class ThreatAnalyzer:
    """Analyzes threats and generates security rules."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.alerts_file = data_dir / "alerts.jsonl"
        self.rules_file = data_dir / "generated_rules.json"
        self.queue_file = data_dir / "pending_rules.json"
        self._ensure_dirs()
        self._load_rules()

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _load_rules(self):
        """Load generated rules."""
        self.rules: Dict[str, GeneratedRule] = {}
        if self.rules_file.exists():
            try:
                data = json.loads(self.rules_file.read_text())
                self.rules = {k: GeneratedRule(**v) for k, v in data.items()}
            except Exception:
                pass

    def _save_rules(self):
        self.rules_file.write_text(json.dumps(
            {k: v.model_dump() for k, v in self.rules.items()},
            indent=2
        ))

    def record_alert(self, alert: ThreatAlert):
        """Record a new alert."""
        with open(self.alerts_file, "a") as f:
            f.write(json.dumps(alert.model_dump()) + "\n")

    def get_recent_alerts(self, hours: int = 24, source: Optional[str] = None) -> List[ThreatAlert]:
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
                    if source and data.get("source") != source:
                        continue
                    alerts.append(ThreatAlert(**data))
                except Exception:
                    continue

        return alerts

    async def collect_crowdsec_alerts(self) -> List[ThreatAlert]:
        """Collect alerts from CrowdSec."""
        alerts = []
        try:
            result = subprocess.run(
                ["cscli", "alerts", "list", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for item in data[:50]:  # Limit to 50
                    alert = ThreatAlert(
                        id=f"cs-{item.get('id', '')}",
                        source="crowdsec",
                        severity=item.get("remediation", "medium"),
                        type=item.get("scenario", "unknown"),
                        ip=item.get("source", {}).get("ip"),
                        details=item,
                        timestamp=item.get("created_at", datetime.utcnow().isoformat() + "Z")
                    )
                    alerts.append(alert)
        except Exception as e:
            logger.warning(f"CrowdSec collection failed: {e}")

        return alerts

    async def collect_waf_alerts(self) -> List[ThreatAlert]:
        """Collect alerts from WAF/mitmproxy."""
        alerts = []
        waf_log = Path("/var/log/mitmproxy/waf.jsonl")

        if not waf_log.exists():
            return alerts

        try:
            # Read last 100 lines
            result = subprocess.run(
                ["tail", "-100", str(waf_log)],
                capture_output=True,
                text=True,
                timeout=5
            )
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get("blocked"):
                        alert = ThreatAlert(
                            id=f"waf-{data.get('id', '')}",
                            source="waf",
                            severity="high" if data.get("category") in ("sqli", "xss", "rce") else "medium",
                            type=data.get("category", "unknown"),
                            ip=data.get("client_ip"),
                            details=data,
                            timestamp=data.get("timestamp", datetime.utcnow().isoformat() + "Z")
                        )
                        alerts.append(alert)
                except Exception:
                    continue
        except Exception as e:
            logger.warning(f"WAF collection failed: {e}")

        return alerts

    async def analyze_with_ai(self, alerts: List[ThreatAlert]) -> str:
        """Analyze alerts using LocalAI."""
        if not alerts:
            return "No alerts to analyze."

        # Build context
        context = "Recent security alerts:\n\n"
        for alert in alerts[:20]:  # Limit context size
            context += f"- [{alert.severity.upper()}] {alert.source}: {alert.type}"
            if alert.ip:
                context += f" from {alert.ip}"
            context += "\n"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://127.0.0.1:8081/v1/chat/completions",
                    json={
                        "model": "mistral-7b-instruct-v0.3",
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a security analyst. Analyze these alerts and identify patterns, recommend actions, and suggest detection rules."
                            },
                            {"role": "user", "content": context}
                        ],
                        "max_tokens": 1000
                    },
                    timeout=60.0
                )
                if response.status_code == 200:
                    return response.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"AI analysis failed: {e}")

        return "AI analysis unavailable."

    async def generate_rule(
        self,
        rule_type: RuleType,
        alerts: List[ThreatAlert]
    ) -> Optional[GeneratedRule]:
        """Generate a security rule from alerts."""
        if not alerts:
            return None

        # Extract common patterns
        ips = set(a.ip for a in alerts if a.ip)
        types = set(a.type for a in alerts)

        rule_id = f"{rule_type.value}-{int(time.time())}"
        now = datetime.utcnow().isoformat() + "Z"

        if rule_type == RuleType.CROWDSEC:
            # Generate CrowdSec scenario
            rule_content = f"""type: leaky
name: secubox/auto-{rule_id}
description: Auto-generated from {len(alerts)} alerts
filter: evt.Parsed.source_ip in ["{','.join(list(ips)[:10])}"]
capacity: 3
leakspeed: 10s
labels:
  type: auto-generated
  source: threat-analyst
"""
        elif rule_type == RuleType.MITMPROXY:
            # Generate mitmproxy filter - fix: use proper list syntax
            ip_list = list(ips)[:20]
            ip_set_str = ', '.join(f'"{ip}"' for ip in ip_list)
            rule_content = f'''# Auto-generated filter
# Alerts: {len(alerts)}
# Types: {', '.join(types)}

BLOCKED_IPS = {{{ip_set_str}}}

def request(flow):
    client_ip = flow.client_conn.address[0]
    if client_ip in BLOCKED_IPS:
        from mitmproxy import http
        flow.response = http.Response.make(403, b"Blocked by threat-analyst")
'''
        elif rule_type == RuleType.NFTABLES:
            # Generate nftables rules
            ip_list = " ".join(list(ips)[:50])
            rule_content = f"""# Auto-generated by threat-analyst
define THREAT_IPS = {{ {ip_list} }}
add rule inet filter input ip saddr $THREAT_IPS drop
"""
        else:
            rule_content = f"# Rule type {rule_type} not implemented"

        rule = GeneratedRule(
            id=rule_id,
            type=rule_type,
            name=f"auto-{rule_id}",
            description=f"Auto-generated from {len(alerts)} alerts ({', '.join(list(types)[:3])})",
            rule_content=rule_content,
            source_alerts=[a.id for a in alerts],
            status=RuleStatus.PENDING,
            created_at=now,
            confidence=min(0.9, 0.5 + (len(alerts) * 0.05))
        )

        self.rules[rule_id] = rule
        self._save_rules()

        return rule

    def approve_rule(self, rule_id: str) -> Optional[GeneratedRule]:
        """Approve a generated rule."""
        rule = self.rules.get(rule_id)
        if not rule:
            return None

        rule.status = RuleStatus.APPROVED
        rule.approved_at = datetime.utcnow().isoformat() + "Z"
        self._save_rules()

        return rule

    def apply_rule(self, rule_id: str) -> Dict[str, Any]:
        """Apply an approved rule to the appropriate system."""
        rule = self.rules.get(rule_id)
        if not rule:
            return {"success": False, "error": "Rule not found"}
        if rule.status != RuleStatus.APPROVED:
            return {"success": False, "error": "Rule not approved"}

        result = {"success": False, "error": "Unknown rule type"}

        try:
            if rule.type == RuleType.NFTABLES:
                result = self._apply_nftables_rule(rule)
            elif rule.type == RuleType.CROWDSEC:
                result = self._apply_crowdsec_rule(rule)
            elif rule.type == RuleType.MITMPROXY:
                result = self._apply_mitmproxy_rule(rule)
            else:
                result = {"success": False, "error": f"Rule type {rule.type} not supported for auto-apply"}

            if result["success"]:
                rule.status = RuleStatus.APPLIED
                rule.applied_at = datetime.utcnow().isoformat() + "Z"
                self._save_rules()

        except Exception as e:
            result = {"success": False, "error": str(e)}

        return result

    def _apply_nftables_rule(self, rule: GeneratedRule) -> Dict[str, Any]:
        """Apply nftables rule."""
        try:
            # Write rule to temp file and apply with nft -f
            rule_file = self.data_dir / f"nft-{rule.id}.conf"
            rule_file.write_text(rule.rule_content)

            result = subprocess.run(
                ["nft", "-f", str(rule_file)],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                logger.info(f"Applied nftables rule {rule.id}")
                return {"success": True}
            else:
                return {"success": False, "error": result.stderr}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "nft command timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _apply_crowdsec_rule(self, rule: GeneratedRule) -> Dict[str, Any]:
        """Apply CrowdSec scenario."""
        try:
            # Write scenario to CrowdSec scenarios directory
            scenario_dir = Path("/etc/crowdsec/scenarios")
            scenario_dir.mkdir(parents=True, exist_ok=True)
            scenario_file = scenario_dir / f"{rule.id}.yaml"
            scenario_file.write_text(rule.rule_content)

            # Reload CrowdSec to pick up new scenario
            result = subprocess.run(
                ["systemctl", "reload", "crowdsec"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                logger.info(f"Applied CrowdSec scenario {rule.id}")
                return {"success": True, "file": str(scenario_file)}
            else:
                # Rollback - remove the file
                scenario_file.unlink(missing_ok=True)
                return {"success": False, "error": result.stderr or "CrowdSec reload failed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def _apply_mitmproxy_rule(self, rule: GeneratedRule) -> Dict[str, Any]:
        """Apply mitmproxy addon."""
        try:
            # Write addon to mitmproxy addons directory
            addon_dir = Path("/srv/mitmproxy/addons")
            addon_dir.mkdir(parents=True, exist_ok=True)
            addon_file = addon_dir / f"{rule.id}.py"
            addon_file.write_text(rule.rule_content)

            # Restart mitmproxy to load new addon
            result = subprocess.run(
                ["systemctl", "restart", "mitmproxy"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.info(f"Applied mitmproxy addon {rule.id}")
                return {"success": True, "file": str(addon_file)}
            else:
                # Rollback - remove the file
                addon_file.unlink(missing_ok=True)
                return {"success": False, "error": result.stderr or "mitmproxy restart failed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def rollback_rule(self, rule_id: str) -> Dict[str, Any]:
        """Rollback an applied rule."""
        rule = self.rules.get(rule_id)
        if not rule:
            return {"success": False, "error": "Rule not found"}
        if rule.status != RuleStatus.APPLIED:
            return {"success": False, "error": "Rule not applied"}

        try:
            if rule.type == RuleType.CROWDSEC:
                scenario_file = Path(f"/etc/crowdsec/scenarios/{rule.id}.yaml")
                scenario_file.unlink(missing_ok=True)
                subprocess.run(["systemctl", "reload", "crowdsec"], timeout=10)

            elif rule.type == RuleType.MITMPROXY:
                addon_file = Path(f"/srv/mitmproxy/addons/{rule.id}.py")
                addon_file.unlink(missing_ok=True)
                subprocess.run(["systemctl", "restart", "mitmproxy"], timeout=30)

            elif rule.type == RuleType.NFTABLES:
                # nftables rules are harder to rollback - mark for manual review
                rule_file = self.data_dir / f"nft-{rule.id}.conf"
                rule_file.unlink(missing_ok=True)
                logger.warning(f"nftables rule {rule.id} file removed, but active rules may need manual cleanup")

            rule.status = RuleStatus.APPROVED  # Reset to approved
            rule.applied_at = None
            self._save_rules()

            return {"success": True, "message": f"Rule {rule.id} rolled back"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_stats(self) -> Dict[str, Any]:
        """Get threat analysis statistics."""
        alerts = self.get_recent_alerts(24)

        by_source = {}
        by_severity = {}
        for alert in alerts:
            by_source[alert.source] = by_source.get(alert.source, 0) + 1
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1

        pending_rules = sum(1 for r in self.rules.values() if r.status == RuleStatus.PENDING)

        return {
            "alerts_24h": len(alerts),
            "by_source": by_source,
            "by_severity": by_severity,
            "pending_rules": pending_rules,
            "total_rules": len(self.rules)
        }


# Global instance
analyzer = ThreatAnalyzer(DATA_DIR)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    stats = analyzer.get_stats()
    return {
        "module": "threat-analyst",
        "status": "ok",
        "version": "1.0.0",
        "alerts_24h": stats["alerts_24h"],
        "pending_rules": stats["pending_rules"]
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get threat analysis statistics."""
    return analyzer.get_stats()


@app.get("/alerts", dependencies=[Depends(require_jwt)])
async def list_alerts(hours: int = 24, source: Optional[str] = None):
    """List recent alerts."""
    alerts = analyzer.get_recent_alerts(hours, source)
    return {"alerts": alerts, "count": len(alerts)}


@app.post("/collect", dependencies=[Depends(require_jwt)])
async def collect_alerts(background_tasks: BackgroundTasks):
    """Collect alerts from all sources."""
    crowdsec_alerts = await analyzer.collect_crowdsec_alerts()
    waf_alerts = await analyzer.collect_waf_alerts()

    for alert in crowdsec_alerts + waf_alerts:
        analyzer.record_alert(alert)

    return {
        "collected": {
            "crowdsec": len(crowdsec_alerts),
            "waf": len(waf_alerts)
        }
    }


@app.post("/analyze", dependencies=[Depends(require_jwt)])
async def analyze_threats(request: AnalysisRequest):
    """Analyze threats and optionally generate rules."""
    alerts = analyzer.get_recent_alerts(request.hours)

    if request.alert_ids:
        alerts = [a for a in alerts if a.id in request.alert_ids]

    analysis = await analyzer.analyze_with_ai(alerts)

    result = {
        "analysis": analysis,
        "alerts_analyzed": len(alerts)
    }

    if request.auto_generate and alerts:
        rule = await analyzer.generate_rule(RuleType.CROWDSEC, alerts)
        if rule:
            result["generated_rule"] = rule

    return result


@app.post("/generate", dependencies=[Depends(require_jwt)])
async def generate_rule(rule_type: RuleType, hours: int = 24):
    """Generate a security rule from recent alerts."""
    alerts = analyzer.get_recent_alerts(hours)
    rule = await analyzer.generate_rule(rule_type, alerts)

    if not rule:
        raise HTTPException(status_code=400, detail="No alerts to generate rule from")

    return {"rule": rule}


@app.get("/rules", dependencies=[Depends(require_jwt)])
async def list_rules(status: Optional[str] = None):
    """List generated rules."""
    rules = list(analyzer.rules.values())

    if status:
        rules = [r for r in rules if r.status.value == status]

    return {"rules": rules, "count": len(rules)}


@app.get("/rules/{rule_id}", dependencies=[Depends(require_jwt)])
async def get_rule(rule_id: str):
    """Get rule details."""
    rule = analyzer.rules.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@app.post("/rules/{rule_id}/approve", dependencies=[Depends(require_jwt)])
async def approve_rule(rule_id: str):
    """Approve a generated rule."""
    rule = analyzer.approve_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "approved", "rule": rule}


@app.post("/rules/{rule_id}/reject", dependencies=[Depends(require_jwt)])
async def reject_rule(rule_id: str):
    """Reject a generated rule."""
    rule = analyzer.rules.get(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.status = RuleStatus.REJECTED
    analyzer._save_rules()
    return {"status": "rejected"}


@app.post("/rules/{rule_id}/apply", dependencies=[Depends(require_jwt)])
async def apply_rule(rule_id: str):
    """Apply an approved rule to the target system."""
    result = analyzer.apply_rule(rule_id)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Apply failed"))
    return {"status": "applied", "result": result}


@app.post("/rules/{rule_id}/rollback", dependencies=[Depends(require_jwt)])
async def rollback_rule(rule_id: str):
    """Rollback an applied rule."""
    result = analyzer.rollback_rule(rule_id)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Rollback failed"))
    return {"status": "rolled_back", "result": result}


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Threat Analyst started")
