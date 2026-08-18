# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
secubox-crowdsec — FastAPI application
Port de luci-app-crowdsec-dashboard vers Debian

RPCD source : luci.crowdsec-dashboard
Méthodes complètes : status, decisions, alerts, bouncers, metrics, machines,
           hub, collections, wizard, console, acquisition, settings, etc.

Three-fold architecture:
  - /components : what is this module made of
  - /status     : health and runtime state
  - /access     : how to connect

Enhanced features (v2.0.0):
  - Decision history and analytics
  - Alert aggregation and trends
  - Ban statistics with TTL
  - Webhook notifications for security events
  - Stats caching with TTL
  - Scheduled metrics collection
"""
import asyncio
import subprocess
import json
import time
import threading
import hashlib
import hmac
import httpx
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

from .routers import (
    status,
    decisions,
    alerts,
    bouncers,
    metrics,
    actions,
    hub,
    bouncer_mgmt,
    wizard,
    acquisition,
)

log = get_logger("crowdsec")

# Data paths
DATA_DIR = Path("/var/lib/secubox/crowdsec")
STATS_HISTORY_FILE = DATA_DIR / "stats_history.json"
DECISION_HISTORY_FILE = DATA_DIR / "decision_history.json"
ALERT_HISTORY_FILE = DATA_DIR / "alert_history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionStats(BaseModel):
    total_bans: int = 0
    active_bans: int = 0
    bans_today: int = 0
    bans_week: int = 0
    top_scenarios: List[Dict[str, Any]] = []
    top_countries: List[Dict[str, Any]] = []


class AlertTrend(BaseModel):
    timestamp: str
    count: int
    by_scenario: Dict[str, int] = {}


class WebhookConfig(BaseModel):
    id: str
    url: str
    events: List[str] = ["ban_added", "alert_critical", "bouncer_offline"]
    secret: Optional[str] = None
    enabled: bool = True
    created_at: str
    last_triggered: Optional[str] = None
    failure_count: int = 0


# ═══════════════════════════════════════════════════════════════════════
# Stats Cache
# ═══════════════════════════════════════════════════════════════════════

class StatsCache:
    """Thread-safe stats cache with TTL."""
    def __init__(self, ttl_seconds: int = 60):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps[key] < self.ttl:
                    return self._cache[key]
                del self._cache[key]
                del self._timestamps[key]
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


stats_cache = StatsCache(ttl_seconds=60)


# ═══════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════

def _load_json(path: Path, default=None) -> Any:
    if default is None:
        default = {}
    try:
        if path.exists():
            return json.loads(path.read_text())
    except (json.JSONDecodeError, IOError):
        pass
    return default


def _save_json(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


async def _trigger_webhooks(event: str, payload: dict):
    """Trigger webhooks for security events."""
    webhooks = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    for hook in webhooks.get("webhooks", []):
        if not hook.get("enabled", True):
            continue
        if event not in hook.get("events", []):
            continue

        try:
            data = {
                "event": event,
                "timestamp": datetime.now().isoformat(),
                "payload": payload,
                "source": "secubox-crowdsec"
            }

            headers = {"Content-Type": "application/json"}
            if hook.get("secret"):
                sig = hmac.new(
                    hook["secret"].encode(),
                    json.dumps(data).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers["X-SecuBox-Signature"] = f"sha256={sig}"

            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(hook["url"], json=data, headers=headers)

            hook["last_triggered"] = datetime.now().isoformat()
            hook["failure_count"] = 0
        except Exception:
            hook["failure_count"] = hook.get("failure_count", 0) + 1

    _save_json(WEBHOOKS_FILE, webhooks)


# ═══════════════════════════════════════════════════════════════════════
# Background Tasks
# ═══════════════════════════════════════════════════════════════════════

_metrics_collector_task: Optional[asyncio.Task] = None


async def _periodic_metrics_collector():
    """Collect CrowdSec metrics periodically."""
    while True:
        try:
            await asyncio.sleep(60)  # Collect every minute

            # Get current decisions count
            result = await _run_ctl("decisions", "list", "-o", "json")
            if isinstance(result, list):
                active_bans = len(result)
            elif isinstance(result, dict) and "output" in result:
                try:
                    decisions_data = json.loads(result["output"])
                    active_bans = len(decisions_data) if isinstance(decisions_data, list) else 0
                except:
                    active_bans = 0
            else:
                active_bans = 0

            # Get alerts count
            alerts_result = await _run_ctl("alerts", "list", "-o", "json")
            alert_count = 0
            if isinstance(alerts_result, list):
                alert_count = len(alerts_result)

            # Record snapshot
            history = _load_json(STATS_HISTORY_FILE, {"records": []})
            history["records"].append({
                "timestamp": datetime.now().isoformat(),
                "active_bans": active_bans,
                "alert_count": alert_count
            })

            # Keep last 1440 records (24h at 1-min intervals)
            history["records"] = history["records"][-1440:]
            _save_json(STATS_HISTORY_FILE, history)

        except asyncio.CancelledError:
            break
        except Exception:
            pass


app = FastAPI(
    title="secubox-crowdsec",
    version="2.0.0",
    root_path="/api/v1/crowdsec",
)


@app.on_event("startup")
async def startup_event():
    """Start background tasks."""
    global _metrics_collector_task
    _metrics_collector_task = asyncio.create_task(_periodic_metrics_collector())
    # Start status cache refresh (double-buffer pattern)
    await status.start_cache_refresh()


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks."""
    global _metrics_collector_task
    if _metrics_collector_task:
        _metrics_collector_task.cancel()
    # Stop status cache refresh
    await status.stop_cache_refresh()

app.include_router(auth_router,           prefix="/auth")
app.include_router(status.router,         tags=["status"])
app.include_router(decisions.router,      tags=["decisions"])
app.include_router(alerts.router,         tags=["alerts"])
app.include_router(bouncers.router,       tags=["bouncers"])
app.include_router(metrics.router,        tags=["metrics"])
app.include_router(actions.router,        tags=["actions"])
app.include_router(hub.router,            tags=["hub"])
app.include_router(bouncer_mgmt.router,   tags=["bouncer-mgmt"])
app.include_router(wizard.router,         tags=["wizard"])
app.include_router(acquisition.router,    tags=["acquisition"])


# === Helper: run crowdsecctl ===
async def _run_ctl(*args, timeout: int = 30) -> dict:
    """Run crowdsecctl and return JSON output."""
    cmd = ["/usr/sbin/crowdsecctl"] + list(args)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode().strip()
        if proc.returncode == 0 and output:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                return {"output": output, "success": True}
        return {"success": proc.returncode == 0, "output": output, "error": stderr.decode().strip()}
    except asyncio.TimeoutError:
        return {"success": False, "error": "Command timeout"}
    except Exception as e:
        log.error("crowdsecctl error: %s", e)
        return {"success": False, "error": str(e)}


# === Three-Fold Architecture Endpoints ===

@app.get("/components")
async def components():
    """List system components (public, three-fold: what)."""
    return {
        "components": [
            {
                "name": "CrowdSec Engine",
                "type": "service",
                "description": "Security automation engine with behavior detection",
                "package": "crowdsec",
                "service": "crowdsec.service",
            },
            {
                "name": "CrowdSec LAPI",
                "type": "api",
                "description": "Local API for decision management and bouncer communication",
                "port": 8080,
                "protocol": "http",
            },
            {
                "name": "Firewall Bouncer",
                "type": "service",
                "description": "nftables bouncer for IP blocking",
                "package": "crowdsec-firewall-bouncer-nftables",
                "service": "crowdsec-firewall-bouncer.service",
            },
            {
                "name": "Hub Collections",
                "type": "content",
                "description": "Scenarios, parsers, and postoverflows from CrowdSec Hub",
                "path": "/etc/crowdsec/hub",
            },
            {
                "name": "crowdsecctl",
                "type": "cli",
                "description": "SecuBox CrowdSec control interface",
                "path": "/usr/sbin/crowdsecctl",
            },
        ]
    }


@app.get("/access")
def access():
    """Show connection endpoints (public, three-fold: how)."""
    import socket
    hostname = socket.getfqdn()

    return {
        "endpoints": [
            {
                "name": "CrowdSec Dashboard",
                "url": f"https://{hostname}/crowdsec/",
                "description": "SecuBox CrowdSec management interface",
            },
            {
                "name": "LAPI (Local)",
                "url": "http://127.0.0.1:8080",
                "description": "Local API for bouncers and decisions",
                "internal": True,
            },
            {
                "name": "Prometheus Metrics",
                "url": "http://127.0.0.1:6060/metrics",
                "description": "CrowdSec metrics endpoint",
                "internal": True,
            },
        ],
        "cli": {
            "tool": "cscli",
            "examples": [
                "cscli decisions list",
                "cscli alerts list",
                "cscli bouncers list",
                "cscli hub list",
            ],
        },
        "documentation": "https://docs.crowdsec.net/",
    }


# === Migration Endpoint ===

class MigrateRequest(BaseModel):
    source: str = "192.168.255.1"
    dry_run: bool = False


@app.post("/migrate")
async def migrate(req: MigrateRequest, background_tasks: BackgroundTasks, user=Depends(require_jwt)):
    """Migrate CrowdSec configuration from OpenWrt."""
    log.info("Migration requested from %s (dry_run=%s)", req.source, req.dry_run)

    args = ["migrate", req.source]
    if req.dry_run:
        args.append("--dry-run")

    # Run migration in background for long-running operation
    result = await _run_ctl(*args, timeout=120)
    return result


# === nftables Statistics ===

@app.get("/nftables")
async def nftables_stats(user=Depends(require_jwt)):
    """Get nftables CrowdSec statistics."""
    return await _run_ctl("nftables")


# === Service Control ===

@app.post("/service/start")
async def service_start(user=Depends(require_jwt)):
    """Start CrowdSec services."""
    log.info("Starting CrowdSec services")
    return await _run_ctl("start")


@app.post("/service/stop")
async def service_stop(user=Depends(require_jwt)):
    """Stop CrowdSec services."""
    log.info("Stopping CrowdSec services")
    return await _run_ctl("stop")


@app.post("/service/restart")
async def service_restart(user=Depends(require_jwt)):
    """Restart CrowdSec services."""
    log.info("Restarting CrowdSec services")
    return await _run_ctl("restart")


# === Console Management ===

class ConsoleEnrollRequest(BaseModel):
    enrollment_key: str


@app.get("/console/status")
async def console_status(user=Depends(require_jwt)):
    """Check CrowdSec Console connection status."""
    return await _run_ctl("console", "status")


@app.post("/console/enroll")
async def console_enroll(req: ConsoleEnrollRequest, user=Depends(require_jwt)):
    """Enroll to CrowdSec Console."""
    log.info("Enrolling to CrowdSec Console")
    return await _run_ctl("console", "enroll", req.enrollment_key)


@app.post("/capi/enroll")
def capi_enroll(user=Depends(require_jwt)):
    """Auto-enroll to CAPI (Central API) for community blocklists."""
    log.info("Auto-enrolling to CAPI")
    try:
        # CAPI enrollment happens automatically on first run
        # We just need to register the machine if not done
        result = subprocess.run(
            ["sudo", "cscli", "capi", "register"],
            capture_output=True, text=True, timeout=30
        )
        output = (result.stdout + result.stderr).lower()
        # Already enrolled scenarios
        if "already registered" in output or "already enrolled" in output:
            return {"success": True, "message": "Already enrolled to CAPI", "already_enrolled": True}
        if "forbidden" in output or "403" in output:
            return {"success": True, "message": "Already enrolled to CAPI", "already_enrolled": True}
        if result.returncode == 0:
            return {"success": True, "message": "CAPI registered"}
        return {"success": False, "error": result.stderr or result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}


# === Debug ===

@app.get("/debug")
async def debug_info(user=Depends(require_jwt)):
    """Collect debug information."""
    return await _run_ctl("debug")


# === Health Check ===

@app.get("/health")
async def health():
    """Layer 1: Basic health check (public)."""
    checks = {}

    # Check CrowdSec engine
    try:
        result = subprocess.run(["pgrep", "-x", "crowdsec"], capture_output=True, timeout=2)
        checks["engine_running"] = result.returncode == 0
    except Exception as e:
        log.warning("Engine check failed: %s", e)
        checks["engine_running"] = False

    # Check LAPI (Local API) - use direct HTTP check instead of cscli
    try:
        import urllib.request
        req = urllib.request.Request("http://127.0.0.1:8080/health", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            checks["lapi_ok"] = resp.status == 200
    except Exception as e:
        # Fallback: check if cscli lapi status succeeds (needs sudo)
        try:
            result = subprocess.run(
                ["sudo", "cscli", "lapi", "status"],
                capture_output=True, text=True, timeout=5
            )
            # Check if "successfully" appears in output
            checks["lapi_ok"] = result.returncode == 0 and "successfully" in result.stdout.lower()
        except Exception:
            checks["lapi_ok"] = False

    # Check bouncers registered (needs sudo for database access)
    try:
        result = subprocess.run(
            ["sudo", "cscli", "bouncers", "list", "-o", "json"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            try:
                bouncers = json.loads(result.stdout)
                checks["bouncers_count"] = len(bouncers) if isinstance(bouncers, list) else 0
                checks["bouncers_ok"] = checks["bouncers_count"] > 0
            except json.JSONDecodeError:
                checks["bouncers_ok"] = False
                checks["bouncers_count"] = 0
        else:
            checks["bouncers_ok"] = False
            checks["bouncers_count"] = 0
    except Exception as e:
        log.warning("Bouncers check failed: %s", e)
        checks["bouncers_ok"] = False
        checks["bouncers_count"] = 0

    # Check nftables tables exist (bouncer creates them)
    try:
        result = subprocess.run(
            ["sudo", "nft", "list", "tables"],
            capture_output=True, text=True, timeout=3
        )
        nft_output = result.stdout if result.returncode == 0 else ""
        # The SecuBox firewall-bouncer uses a CUSTOM table name (inet
        # secubox_blacklist), not the upstream default `ip crowdsec` / `ip6
        # crowdsec6` — so the legacy probe always missed it and reported the
        # firewall "not OK" even though it was active. Detect both the custom and
        # the default names, and base nftables_ok on the GENERAL SecuBox firewall
        # being loaded (inet filter / secubox_blacklist), not on the IPv6 anchor.
        checks["nftables_crowdsec"] = ("ip crowdsec" in nft_output) or ("secubox_blacklist" in nft_output)
        checks["nftables_crowdsec6"] = ("ip6 crowdsec6" in nft_output) or ("crowdsec6" in nft_output)
        checks["nftables_ok"] = ("inet filter" in nft_output) or ("secubox_blacklist" in nft_output)
    except Exception as e:
        log.warning("nftables check failed: %s", e)
        checks["nftables_ok"] = False
        checks["nftables_crowdsec"] = False
        checks["nftables_crowdsec6"] = False

    # Determine overall status
    if checks.get("engine_running") and checks.get("lapi_ok") and checks.get("bouncers_ok") and checks.get("nftables_ok"):
        status = "ok"
    elif checks.get("engine_running") and checks.get("lapi_ok") and checks.get("bouncers_ok"):
        status = "degraded"  # Bouncer running but nftables not synced - needs restart
    elif checks.get("engine_running") and checks.get("lapi_ok"):
        status = "degraded"  # Engine + LAPI ok but no bouncers
    elif checks.get("engine_running"):
        status = "degraded"  # Engine running but LAPI issues
    else:
        status = "error"

    return {
        "status": status,
        "healthy": status == "ok",
        "module": "crowdsec",
        "version": "2.0.0",
        "dev_stage": "production",
        "enabled": "enabled",
        "checks": checks
    }


@app.get("/doctor")
def doctor():
    """Layer 2: Diagnostic détaillé + can_repair."""
    issues = []

    # 1. Check engine
    try:
        result = subprocess.run(["pgrep", "crowdsec"], capture_output=True, timeout=2)
        if result.returncode != 0:
            issues.append({"type": "engine_not_running", "repairable": True})
    except Exception:
        issues.append({"type": "engine_check_failed", "repairable": True})

    # 2. Check LAPI
    try:
        result = subprocess.run(
            ["cscli", "lapi", "status"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            issues.append({"type": "lapi_error", "repairable": True, "details": result.stderr[:200]})
    except Exception as e:
        issues.append({"type": "lapi_check_failed", "repairable": True, "details": str(e)})

    # 3. Check CAPI (Central API) enrollment
    try:
        result = subprocess.run(
            ["cscli", "capi", "status"],
            capture_output=True, text=True, timeout=10
        )
        if "not enrolled" in result.stdout.lower() or result.returncode != 0:
            issues.append({"type": "capi_not_enrolled", "repairable": False, "details": "Manual enrollment required"})
    except Exception:
        issues.append({"type": "capi_check_failed", "repairable": False})

    # 4. Check bouncers
    try:
        result = subprocess.run(
            ["cscli", "bouncers", "list", "-o", "json"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            bouncers = json.loads(result.stdout) if result.stdout.strip() else []
            if len(bouncers) == 0:
                issues.append({"type": "no_bouncers", "repairable": True})
            # Check for stale bouncers
            for b in bouncers:
                last_pull = b.get("last_pull")
                if last_pull:
                    # If no pull in 1 hour, bouncer might be dead
                    pass  # TODO: Parse and check timestamp
    except Exception:
        pass

    # 5. Check nftables tables (bouncer must create them)
    try:
        result = subprocess.run(
            ["sudo", "nft", "list", "tables"],
            capture_output=True, text=True, timeout=3
        )
        nft_output = result.stdout if result.returncode == 0 else ""
        if "ip crowdsec" not in nft_output:
            issues.append({
                "type": "nftables_missing",
                "repairable": True,
                "details": "CrowdSec nftables table not found - bouncer needs restart"
            })
    except Exception:
        issues.append({"type": "nftables_check_failed", "repairable": True})

    # 6. Check hub updates (renumbered from 5)
    try:
        result = subprocess.run(
            ["cscli", "hub", "list", "-o", "json"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            hub_data = json.loads(result.stdout) if result.stdout.strip() else {}
            # Check for outdated collections
            for item_type in ["parsers", "scenarios", "collections"]:
                items = hub_data.get(item_type, [])
                for item in items:
                    if item.get("status") == "upgrade_available":
                        issues.append({
                            "type": "hub_update_available",
                            "repairable": True,
                            "item": item.get("name"),
                            "item_type": item_type
                        })
                        break  # One is enough to flag
    except Exception:
        pass

    # 6. Check acquisition config
    acq_file = Path("/etc/crowdsec/acquis.yaml")
    if not acq_file.exists():
        issues.append({"type": "acquis_missing", "repairable": False})

    can_repair = all(i.get("repairable", False) for i in issues) if issues else True

    return {
        "healthy": len(issues) == 0,
        "issues": issues,
        "can_repair": can_repair,
        "repair_endpoint": "/repair"
    }


@app.post("/repair", dependencies=[Depends(require_jwt)])
async def repair():
    """Layer 3: Auto-repair CrowdSec."""
    repairs = []

    # 1. Restart engine if not running
    try:
        result = subprocess.run(["pgrep", "-x", "crowdsec"], capture_output=True, timeout=2)
        if result.returncode != 0:
            subprocess.run(["systemctl", "restart", "crowdsec"], timeout=30)
            repairs.append({"action": "restart_engine", "status": "ok"})
    except Exception as e:
        repairs.append({"action": "restart_engine", "status": "error", "message": str(e)})

    # 2. Check and restart firewall bouncer if nftables tables missing
    try:
        result = subprocess.run(["sudo", "nft", "list", "tables"], capture_output=True, text=True, timeout=3)
        nft_output = result.stdout if result.returncode == 0 else ""
        if "ip crowdsec" not in nft_output:
            # Tables missing - restart bouncer to create them
            subprocess.run(["sudo", "systemctl", "restart", "crowdsec-firewall-bouncer"], timeout=30)
            await asyncio.sleep(3)  # Wait for bouncer to sync
            repairs.append({"action": "restart_firewall_bouncer", "status": "ok", "reason": "nftables tables missing"})
    except Exception as e:
        repairs.append({"action": "restart_firewall_bouncer", "status": "error", "message": str(e)})

    # 3. Update hub
    try:
        result = subprocess.run(
            ["cscli", "hub", "update"],
            capture_output=True, text=True, timeout=60
        )
        repairs.append({
            "action": "hub_update",
            "status": "ok" if result.returncode == 0 else "warning",
            "message": result.stdout[:200] if result.returncode != 0 else None
        })
    except subprocess.TimeoutExpired:
        repairs.append({"action": "hub_update", "status": "timeout"})
    except Exception as e:
        repairs.append({"action": "hub_update", "status": "error", "message": str(e)})

    # 4. Upgrade hub items if available
    try:
        result = subprocess.run(
            ["cscli", "hub", "upgrade"],
            capture_output=True, text=True, timeout=120
        )
        repairs.append({
            "action": "hub_upgrade",
            "status": "ok" if result.returncode == 0 else "warning"
        })
    except subprocess.TimeoutExpired:
        repairs.append({"action": "hub_upgrade", "status": "timeout"})
    except Exception as e:
        repairs.append({"action": "hub_upgrade", "status": "error", "message": str(e)})

    # 5. Reload configuration
    try:
        result = subprocess.run(
            ["cscli", "config", "reload"],
            capture_output=True, text=True, timeout=10
        )
        repairs.append({
            "action": "config_reload",
            "status": "ok" if result.returncode == 0 else "error"
        })
    except Exception as e:
        repairs.append({"action": "config_reload", "status": "error", "message": str(e)})

    # 6. Register HAProxy bouncer if missing
    try:
        result = subprocess.run(
            ["cscli", "bouncers", "list", "-o", "json"],
            capture_output=True, text=True, timeout=5
        )
        bouncers = json.loads(result.stdout) if result.stdout.strip() else []
        bouncer_names = [b.get("name", "") for b in bouncers]

        if "haproxy-bouncer" not in bouncer_names:
            # Add HAProxy bouncer
            result = subprocess.run(
                ["cscli", "bouncers", "add", "haproxy-bouncer", "-o", "raw"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                repairs.append({"action": "add_haproxy_bouncer", "status": "ok", "key": result.stdout.strip()[:20] + "..."})
            else:
                repairs.append({"action": "add_haproxy_bouncer", "status": "warning", "message": "May already exist"})
    except Exception as e:
        repairs.append({"action": "check_bouncers", "status": "error", "message": str(e)})

    # 7. Verify health after repairs
    await asyncio.sleep(2)
    health_result = await health()
    repairs.append({
        "action": "verify_health",
        "status": "ok" if health_result.get("healthy") else "warning",
        "final_status": health_result.get("status")
    })

    # Log repairs
    log.info("CrowdSec repair completed: %s", repairs)

    success = all(r.get("status") in ("ok", "warning") for r in repairs)

    return {
        "success": success,
        "repairs": repairs
    }


@app.post("/hub/update")
async def hub_update(user=Depends(require_jwt)):
    """Update CrowdSec hub."""
    return await _run_ctl("hub", "update")


@app.post("/service/reload")
async def service_reload(user=Depends(require_jwt)):
    """Reload CrowdSec service."""
    return await _run_ctl("config", "reload")


@app.post("/service/restart")
async def service_restart(user=Depends(require_jwt)):
    """Restart CrowdSec service."""
    result = await _run_ctl("systemctl", "restart", "crowdsec")
    return result





# ═══════════════════════════════════════════════════════════════════════
# DECISION ANALYTICS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/analytics/decisions")
async def get_decision_analytics(user=Depends(require_jwt)):
    """Get decision analytics and statistics."""
    cached = stats_cache.get("decision_analytics")
    if cached:
        return cached

    result = await _run_ctl("decisions", "list", "-o", "json")

    decisions = []
    if isinstance(result, list):
        decisions = result
    elif isinstance(result, dict) and result.get("output"):
        try:
            decisions = json.loads(result["output"])
        except:
            decisions = []

    # Calculate stats
    now = datetime.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)

    total_bans = len(decisions)
    active_bans = sum(1 for d in decisions if d.get("type") == "ban")
    bans_today = 0
    bans_week = 0
    scenario_counts = {}
    country_counts = {}

    for d in decisions:
        # Count by time
        created = d.get("created_at", "")
        if created:
            try:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                if created_dt.replace(tzinfo=None) >= today_start:
                    bans_today += 1
                if created_dt.replace(tzinfo=None) >= week_start:
                    bans_week += 1
            except:
                pass

        # Count by scenario
        scenario = d.get("scenario", "unknown")
        scenario_counts[scenario] = scenario_counts.get(scenario, 0) + 1

        # Count by origin/country (if available)
        origin = d.get("origin", "unknown")
        country_counts[origin] = country_counts.get(origin, 0) + 1

    analytics = {
        "total_bans": total_bans,
        "active_bans": active_bans,
        "bans_today": bans_today,
        "bans_week": bans_week,
        "top_scenarios": sorted(
            [{"scenario": k, "count": v} for k, v in scenario_counts.items()],
            key=lambda x: x["count"], reverse=True
        )[:10],
        "top_origins": sorted(
            [{"origin": k, "count": v} for k, v in country_counts.items()],
            key=lambda x: x["count"], reverse=True
        )[:10],
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("decision_analytics", analytics)
    return analytics


@app.get("/analytics/trends")
async def get_alert_trends(
    hours: int = Query(default=24, le=168),
    user=Depends(require_jwt)
):
    """Get alert trends over time."""
    history = _load_json(STATS_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    # Filter by time
    cutoff = datetime.now() - timedelta(hours=hours)
    cutoff_str = cutoff.isoformat()
    records = [r for r in records if r.get("timestamp", "") >= cutoff_str]

    return {
        "records": records,
        "period_hours": hours,
        "count": len(records)
    }


@app.get("/analytics/threat-level")
async def get_threat_level(user=Depends(require_jwt)):
    """Calculate current threat level based on recent activity."""
    result = await _run_ctl("alerts", "list", "-o", "json", "--since", "1h")

    alerts = []
    if isinstance(result, list):
        alerts = result
    elif isinstance(result, dict) and result.get("output"):
        try:
            alerts = json.loads(result["output"])
        except:
            alerts = []

    alert_count = len(alerts)

    # Determine threat level
    if alert_count >= 50:
        level = ThreatLevel.CRITICAL
    elif alert_count >= 20:
        level = ThreatLevel.HIGH
    elif alert_count >= 5:
        level = ThreatLevel.MEDIUM
    else:
        level = ThreatLevel.LOW

    return {
        "level": level.value,
        "alerts_last_hour": alert_count,
        "assessed_at": datetime.now().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════
# IP REPUTATION
# ═══════════════════════════════════════════════════════════════════════

@app.get("/reputation/{ip}")
async def check_ip_reputation(ip: str, user=Depends(require_jwt)):
    """Check if an IP has been banned or has alerts."""
    # Check decisions for this IP
    decisions_result = await _run_ctl("decisions", "list", "-i", ip, "-o", "json")

    decisions = []
    if isinstance(decisions_result, list):
        decisions = decisions_result
    elif isinstance(decisions_result, dict) and decisions_result.get("output"):
        try:
            decisions = json.loads(decisions_result["output"])
        except:
            decisions = []

    # Check alerts for this IP
    alerts_result = await _run_ctl("alerts", "list", "-i", ip, "-o", "json")

    alerts = []
    if isinstance(alerts_result, list):
        alerts = alerts_result
    elif isinstance(alerts_result, dict) and alerts_result.get("output"):
        try:
            alerts = json.loads(alerts_result["output"])
        except:
            alerts = []

    is_banned = len(decisions) > 0
    has_alerts = len(alerts) > 0

    return {
        "ip": ip,
        "banned": is_banned,
        "has_alerts": has_alerts,
        "active_decisions": len(decisions),
        "total_alerts": len(alerts),
        "decisions": decisions[:10],  # Limit to 10
        "recent_alerts": alerts[:10],  # Limit to 10
        "checked_at": datetime.now().isoformat()
    }


@app.post("/whitelist/{ip}")
async def whitelist_ip(ip: str, duration: str = Query(default="24h"), user=Depends(require_jwt)):
    """Add IP to whitelist (remove any active bans)."""
    log.info("Whitelisting IP: %s for %s", ip, duration)

    # Delete any existing decisions for this IP
    result = await _run_ctl("decisions", "delete", "-i", ip)

    # Record in history
    history = _load_json(DECISION_HISTORY_FILE, {"records": []})
    history["records"].append({
        "action": "whitelist",
        "ip": ip,
        "duration": duration,
        "timestamp": datetime.now().isoformat(),
        "user": user.get("sub", "unknown")
    })
    history["records"] = history["records"][-1000:]
    _save_json(DECISION_HISTORY_FILE, history)

    return {"success": True, "ip": ip, "action": "whitelisted"}


# ═══════════════════════════════════════════════════════════════════════
# WEBHOOKS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    """List configured webhooks."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})
    return {
        "webhooks": data.get("webhooks", []),
        "available_events": [
            "ban_added", "ban_removed", "alert_critical",
            "bouncer_offline", "bouncer_online", "engine_restart"
        ]
    }


class WebhookCreate(BaseModel):
    url: str
    events: List[str] = ["ban_added", "alert_critical"]
    secret: Optional[str] = None
    enabled: bool = True


@app.post("/webhooks")
async def add_webhook(config: WebhookCreate, user=Depends(require_jwt)):
    """Add a webhook."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    webhook_id = hashlib.sha256(f"{config.url}{time.time()}".encode()).hexdigest()[:12]

    webhook = {
        "id": webhook_id,
        "url": config.url,
        "events": config.events,
        "secret": config.secret,
        "enabled": config.enabled,
        "created_at": datetime.now().isoformat(),
        "last_triggered": None,
        "failure_count": 0
    }

    data["webhooks"].append(webhook)
    _save_json(WEBHOOKS_FILE, data)

    return {"status": "success", "webhook": webhook}


@app.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Delete a webhook."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    original_len = len(data["webhooks"])
    data["webhooks"] = [w for w in data["webhooks"] if w.get("id") != webhook_id]

    if len(data["webhooks"]) == original_len:
        raise HTTPException(status_code=404, detail="Webhook not found")

    _save_json(WEBHOOKS_FILE, data)
    return {"status": "success"}


@app.post("/webhooks/{webhook_id}/test")
async def test_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Test a webhook with a sample payload."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    webhook = next((w for w in data["webhooks"] if w.get("id") == webhook_id), None)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    test_payload = {
        "event": "test",
        "timestamp": datetime.now().isoformat(),
        "payload": {"message": "This is a test webhook from SecuBox CrowdSec"}
    }

    try:
        headers = {"Content-Type": "application/json"}
        if webhook.get("secret"):
            sig = hmac.new(
                webhook["secret"].encode(),
                json.dumps(test_payload).encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-SecuBox-Signature"] = f"sha256={sig}"

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook["url"], json=test_payload, headers=headers)
            return {
                "status": "success",
                "response_code": resp.status_code,
                "response_body": resp.text[:500]
            }
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════

@app.get("/summary")
async def get_crowdsec_summary(user=Depends(require_jwt)):
    """Get comprehensive CrowdSec summary."""
    # Check if running
    try:
        result = subprocess.run(["pgrep", "crowdsec"], capture_output=True, timeout=2)
        engine_running = result.returncode == 0
    except Exception:
        engine_running = False

    # Check bouncer
    try:
        result = subprocess.run(["pgrep", "-f", "crowdsec-firewall"], capture_output=True, timeout=2)
        bouncer_running = result.returncode == 0
    except Exception:
        bouncer_running = False

    # Get decision analytics
    analytics = await get_decision_analytics(user)

    # Get threat level
    threat = await get_threat_level(user)

    return {
        "service": {
            "engine_running": engine_running,
            "bouncer_running": bouncer_running,
            "version": "2.0.0"
        },
        "security": {
            "threat_level": threat["level"],
            "alerts_last_hour": threat["alerts_last_hour"],
            "active_bans": analytics["active_bans"],
            "bans_today": analytics["bans_today"]
        },
        "analytics": {
            "total_bans": analytics["total_bans"],
            "top_scenario": analytics["top_scenarios"][0]["scenario"] if analytics["top_scenarios"] else None,
            "top_origin": analytics["top_origins"][0]["origin"] if analytics["top_origins"] else None
        },
        "timestamp": datetime.now().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════
# HISTORY
# ═══════════════════════════════════════════════════════════════════════

@app.get("/history/decisions")
async def get_decision_history(
    limit: int = Query(default=100, le=1000),
    user=Depends(require_jwt)
):
    """Get decision action history (whitelist, manual bans, etc.)."""
    history = _load_json(DECISION_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    records = sorted(records, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "records": records[:limit],
        "total": len(records)
    }


@app.get("/export/decisions")
async def export_decisions(format: str = Query(default="json", enum=["json", "csv"]), user=Depends(require_jwt)):
    """Export current decisions."""
    result = await _run_ctl("decisions", "list", "-o", "json")

    decisions = []
    if isinstance(result, list):
        decisions = result
    elif isinstance(result, dict) and result.get("output"):
        try:
            decisions = json.loads(result["output"])
        except:
            decisions = []

    if format == "csv":
        lines = ["ip,scenario,type,duration,created_at"]
        for d in decisions:
            lines.append(",".join([
                d.get("value", ""),
                d.get("scenario", ""),
                d.get("type", ""),
                d.get("duration", ""),
                d.get("created_at", "")
            ]))
        return {"format": "csv", "data": "\n".join(lines)}

    return {
        "format": "json",
        "exported_at": datetime.now().isoformat(),
        "decisions": decisions
    }


# ═══════════════════════════════════════════════════════════════════════
# SOC DASHBOARD STATS (public)
# ═══════════════════════════════════════════════════════════════════════

@app.get("/decisions_stats")
def decisions_stats():
    """Get decision statistics for SOC dashboard (public).

    Returns counts, bouncers, and categories for the dashboard cards.
    """
    cached = stats_cache.get("decisions_stats")
    if cached:
        return cached

    # Get active decisions
    active_decisions = 0
    categories = {}
    try:
        result = subprocess.run(
            ["sudo", "cscli", "decisions", "list", "-o", "json"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            for item in data or []:
                for d in item.get("decisions", []):
                    active_decisions += 1
                    # Extract category from scenario name (e.g., "crowdsecurity/ssh-bf" → "ssh")
                    scenario = d.get("scenario", "")
                    cat = scenario.split("/")[-1].split("-")[0] if "/" in scenario else scenario
                    categories[cat] = categories.get(cat, 0) + 1
    except Exception:
        pass

    # Get bouncer count
    bouncers = 0
    try:
        result = subprocess.run(
            ["sudo", "cscli", "bouncers", "list", "-o", "json"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            bouncers = len(data) if isinstance(data, list) else 0
    except Exception:
        pass

    # Categories list with emoji-friendly names
    categories_list = [
        {"name": cat, "count": cnt}
        for cat, cnt in sorted(categories.items(), key=lambda x: -x[1])[:8]
    ]

    stats = {
        "active_decisions": active_decisions,
        "bouncers": bouncers,
        "categories": categories_list,
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("decisions_stats", stats)
    return stats


# ═══════════════════════════════════════════════════════════════════════
# BAN/UNBAN API (for SOC autoban panel)
# ═══════════════════════════════════════════════════════════════════════

class BanRequest(BaseModel):
    ip: str
    duration: str = "24h"
    reason: str = "Manual ban from SOC"


@app.post("/ban")
def ban_ip(req: BanRequest, user=Depends(require_jwt)):
    """Ban an IP address (manual ban from SOC dashboard)."""
    log.info("Manual ban requested for %s by %s", req.ip, user.get("sub", "unknown"))

    try:
        result = subprocess.run([
            "sudo", "cscli", "decisions", "add",
            "--ip", req.ip,
            "--type", "ban",
            "--duration", req.duration,
            "--reason", req.reason
        ], capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            # Record in history
            history = _load_json(DECISION_HISTORY_FILE, {"records": []})
            history["records"].append({
                "action": "ban",
                "ip": req.ip,
                "duration": req.duration,
                "reason": req.reason,
                "timestamp": datetime.now().isoformat(),
                "user": user.get("sub", "unknown")
            })
            history["records"] = history["records"][-1000:]
            _save_json(DECISION_HISTORY_FILE, history)

            # Invalidate cache
            stats_cache.invalidate("decisions_stats")

            return {"success": True, "ip": req.ip, "duration": req.duration}
        else:
            return {"success": False, "error": result.stderr or result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}


class UnbanRequest(BaseModel):
    ip: str


@app.post("/unban")
def unban_ip(req: UnbanRequest, user=Depends(require_jwt)):
    """Remove ban for an IP address."""
    log.info("Unban requested for %s by %s", req.ip, user.get("sub", "unknown"))

    try:
        result = subprocess.run([
            "sudo", "cscli", "decisions", "delete",
            "--ip", req.ip
        ], capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            # Record in history
            history = _load_json(DECISION_HISTORY_FILE, {"records": []})
            history["records"].append({
                "action": "unban",
                "ip": req.ip,
                "timestamp": datetime.now().isoformat(),
                "user": user.get("sub", "unknown")
            })
            history["records"] = history["records"][-1000:]
            _save_json(DECISION_HISTORY_FILE, history)

            # Invalidate cache
            stats_cache.invalidate("decisions_stats")

            return {"success": True, "ip": req.ip}
        else:
            return {"success": False, "error": result.stderr or result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}
