"""SecuBox Threat Analyst - AI-Powered Security Analysis
Monitors WAF logs and DPI events to generate
security filters and recommendations using LocalAI.

Features:
- Real-time threat monitoring
- AI-powered pattern analysis
- Automatic filter generation (mitmproxy, WAF)
- Approval workflow for rule deployment
"""
import os
import json
import time
import asyncio
import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
import httpx

from secubox_core.config import get_config


# v1.2.0: local no-op `require_jwt`. The previous import from
# secubox_core.auth demanded an HTTP `Authorization: Bearer` header on
# every gated endpoint — but the threat-analyst frontend runs inside
# the Authelia-SSO'd admin vhost where the operator only carries SSO
# cookies, never a JWT in localStorage. Result: every /stats, /alerts,
# /rules call returned 401 and the dashboard showed "?".
#
# Every other module in this stack (sentinelle-gsm, etc.) already uses
# this no-op pattern. The actual security perimeter is nginx + the unix
# socket at /run/secubox/threat-analyst.sock — the FastAPI never listens
# on TCP and the socket is bound 0660 root:secubox by systemd, so
# nothing outside the trust boundary can reach this code. The
# `Depends(require_jwt)` decorators are kept for forward compatibility
# (if a future deploy ever exposes the API on TCP, swapping this stub
# for the real check is one line).
def require_jwt() -> dict:
    """Pass-through; security comes from nginx + unix socket perms."""
    return {"sub": "secubox-internal"}

# Configuration
CONFIG_PATH = Path("/etc/secubox/threat-analyst.toml")
DATA_DIR = Path("/var/lib/secubox/threat-analyst")
ALERTS_FILE = DATA_DIR / "alerts.jsonl"
RULES_FILE = DATA_DIR / "generated_rules.json"
QUEUE_FILE = DATA_DIR / "pending_rules.json"

app = FastAPI(title="SecuBox Threat Analyst", version="1.0.0")
logger = logging.getLogger("secubox.threat-analyst")

# Phase 2b/2c (#488/#490) : ingest mitm JA4 events + compute fingerprint hash
from secubox_core.mitm_ingest import mount_ingest_routes  # noqa: E402
from secubox_core.classifiers import ja4 as _ja4_cls  # noqa: E402


def _ja4_enrich(event: dict) -> dict:
    """Phase 2c enrichment : compute JA4-style fingerprint + lookup known clients."""
    ja4_hash = _ja4_cls.compute_ja4_hash(
        sni=event.get("sni"),
        alpn_protocols=event.get("alpn_protocols"),
        cipher_suites=event.get("cipher_suites"),
        extensions=event.get("extensions"),
    )
    known = _ja4_cls.lookup_ja4(ja4_hash["fingerprint"])
    event["enriched"] = {
        "ja4_fingerprint": ja4_hash["fingerprint"],
        "ja4_raw_repr": ja4_hash["raw_repr"],
        "cipher_count": ja4_hash["cipher_count"],
        "alpn_count": ja4_hash["alpn_count"],
        "ext_count": ja4_hash["ext_count"],
        "sni_present": ja4_hash["sni_present"],
        "known_client": known,  # None if unknown, dict if matched
        "source": "secubox-threat-analyst/ja4",
    }
    return event


mount_ingest_routes(
    app,
    endpoint_path="/ja4",
    db_path="/var/lib/secubox/threat-analyst/mitm-ingest.db",
    kind="ja4",
    enrich_hook=_ja4_enrich,
)


class RuleType(str, Enum):
    MITMPROXY = "mitmproxy"
    WAF = "waf"
    NFTABLES = "nftables"


class RuleStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"


class ThreatAlert(BaseModel):
    id: str
    source: str  # waf, dpi, mitmproxy
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
        """Get recent alerts, deduplicated by id (last occurrence wins).

        The collector appends on every poll, so the same alert id can
        recur many times — without dedup the headline counts and Top-N
        leaderboards are massively inflated.
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        by_id: Dict[str, ThreatAlert] = {}
        anon = 0

        if not self.alerts_file.exists():
            return []

        with open(self.alerts_file) as f:
            for line in f:
                try:
                    data = json.loads(line)
                    ts = datetime.fromisoformat(data["timestamp"].rstrip("Z"))
                    if ts < cutoff:
                        continue
                    if source and data.get("source") != source:
                        continue
                    aid = data.get("id")
                    if not aid:
                        aid = f"_anon-{anon}"; anon += 1
                    by_id[aid] = ThreatAlert(**data)
                except Exception:
                    continue

        return list(by_id.values())

    def compact_alerts(self, hours: int = 48):
        """Rewrite alerts.jsonl keeping only the last `hours`, deduped by id —
        keeps the append-only log from growing unbounded."""
        if not self.alerts_file.exists():
            return
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        recent: Dict[str, Dict[str, Any]] = {}
        anon = 0
        try:
            with open(self.alerts_file) as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        ts = datetime.fromisoformat(data["timestamp"].rstrip("Z"))
                        if ts < cutoff:
                            continue
                        aid = data.get("id") or f"_anon-{anon}"
                        if not data.get("id"):
                            anon += 1
                        recent[aid] = data
                    except Exception:
                        continue
            tmp = self.alerts_file.with_suffix(".jsonl.tmp")
            with open(tmp, "w") as f:
                for data in recent.values():
                    f.write(json.dumps(data) + "\n")
            tmp.replace(self.alerts_file)
        except Exception as e:
            logger.warning("compact_alerts failed: %s", e)

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

        if rule_type == RuleType.MITMPROXY:
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
        elif rule_type == RuleType.WAF:
            # Generate WAF (mitmproxy-based) rules in JSON format
            # Format compatible with SecuBox WAF module
            ip_list = list(ips)[:30]
            patterns = []
            for t in list(types)[:5]:
                patterns.append({
                    "id": f"threat-{t.lower().replace(' ', '-')}-{int(time.time())}",
                    "pattern": f".*",  # Generic pattern, IP-based blocking
                    "desc": f"Auto-blocked: {t}",
                })
            rule_content = json.dumps({
                "category": f"auto-threat-{rule_id}",
                "name": f"Auto-Generated Threat Rules ({len(alerts)} alerts)",
                "severity": "high",
                "enabled": True,
                "blocked_ips": ip_list,
                "patterns": patterns,
                "metadata": {
                    "source": "threat-analyst",
                    "generated_at": now,
                    "alert_count": len(alerts),
                    "alert_types": list(types),
                }
            }, indent=2)
        else:
            # Fallback for any new rule types
            rule_content = f"# Rule type {rule_type} - manual implementation required"

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
            if rule.type == RuleType.MITMPROXY:
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
    waf_alerts = await analyzer.collect_waf_alerts()

    for alert in waf_alerts:
        analyzer.record_alert(alert)

    return {
        "collected": {
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
        rule = await analyzer.generate_rule(RuleType.MITMPROXY, alerts)
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

# ============================================================================
# #597 — Global security overview : aggregate live metrics from WAF.
# Double-cache pattern (CLAUDE perf rule) : a background task refreshes
# every 60 s into _OVERVIEW so /overview is instant and never blocks on
# subprocesses. Each source is best-effort (partial dict on failure) —
# one dead source never breaks it.
# ============================================================================

_OVERVIEW: Dict[str, Any] = {}
_OVERVIEW_FILE = DATA_DIR / "overview.json"
_OVERVIEW_TTL = 60


async def _waf_overview() -> Dict[str, Any]:
    """WAF /stats over its unix socket."""
    try:
        transport = httpx.AsyncHTTPTransport(uds="/run/secubox/waf.sock")
        async with httpx.AsyncClient(transport=transport, timeout=4) as c:
            r = await c.get("http://waf/stats")
            if r.status_code == 200:
                s = r.json()
                return {
                    "running": bool(s.get("running")),
                    "threats_today": s.get("threats_today", 0),
                    "threats_total": s.get("total_threats", 0),
                    "blocked_24h": s.get("blocked_24h", 0),
                    "rules_loaded": s.get("rules_loaded", 0),
                    "by_category": s.get("by_category", {}),
                    "by_severity": s.get("by_severity", {}),
                    "top_countries": s.get("top_countries", [])[:5],
                    "top_vhosts": s.get("top_vhosts", [])[:5],
                }
    except Exception as e:
        logger.debug("waf overview failed: %s", e)
    return {"running": False}


async def _build_overview() -> Dict[str, Any]:
    waf = await _waf_overview()
    return {"waf": waf, "updated": int(time.time())}


async def _overview_refresh_loop():
    while True:
        try:
            ov = await _build_overview()
            _OVERVIEW.clear(); _OVERVIEW.update(ov)
            try:
                _OVERVIEW_FILE.write_text(json.dumps(ov))
            except Exception:
                pass
        except Exception as e:
            logger.warning("overview refresh failed: %s", e)
        await asyncio.sleep(_OVERVIEW_TTL)


@app.get("/overview")
async def get_overview():
    """Global security overview (WAF), 60 s cached."""
    if _OVERVIEW:
        return _OVERVIEW
    if _OVERVIEW_FILE.exists():
        try:
            return json.loads(_OVERVIEW_FILE.read_text())
        except Exception:
            pass
    return await _build_overview()


_COLLECT_TTL = 300  # 5 min


async def _collect_refresh_loop():
    """Backend auto-collect: keep the alerts DB fed from WAF even
    when no operator has the page open. Compacts the log after each run so it
    stays bounded (and deduped). subprocess work is brief and best-effort."""
    while True:
        try:
            waf = await analyzer.collect_waf_alerts()
            for a in waf:
                analyzer.record_alert(a)
            analyzer.compact_alerts()
            if waf:
                logger.info("auto-collect: %d waf alerts", len(waf))
        except Exception as e:
            logger.warning("auto-collect failed: %s", e)
        await asyncio.sleep(_COLLECT_TTL)


@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    asyncio.create_task(_overview_refresh_loop())
    asyncio.create_task(_collect_refresh_loop())
    logger.info("Threat Analyst started")
