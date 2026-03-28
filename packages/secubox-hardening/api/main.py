#!/usr/bin/env python3
"""
SecuBox Hardening API — Kernel and System Hardening

Enhanced features (v2.0.0):
- Security score calculation
- Benchmark history and trends
- Individual check results
- Compliance tracking (CIS benchmarks)
- Webhook notifications for security events
- Scheduled benchmarks
- Recommendations engine
"""
from fastapi import FastAPI, Depends, HTTPException, Query, BackgroundTasks
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from pathlib import Path
from datetime import datetime, timedelta
from enum import Enum
import subprocess
import json
import time
import threading
import asyncio
import hashlib
import hmac
import httpx

import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "admin"}

# Data paths
DATA_DIR = Path("/var/lib/secubox/hardening")
BENCHMARK_HISTORY_FILE = DATA_DIR / "benchmark_history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
SCHEDULE_FILE = DATA_DIR / "schedule.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════

class SecurityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    PASSED = "passed"


class CheckResult(BaseModel):
    id: str
    name: str
    description: str
    status: str  # pass, fail, warn, skip
    severity: SecurityLevel
    recommendation: Optional[str] = None
    category: str = "general"


class BenchmarkResult(BaseModel):
    timestamp: str
    score: int
    max_score: int
    percentage: float
    passed: int
    failed: int
    warnings: int
    skipped: int
    checks: List[CheckResult] = []


class ScheduleConfig(BaseModel):
    enabled: bool = False
    interval_hours: int = Field(ge=1, le=168, default=24)
    last_run: Optional[str] = None
    next_run: Optional[str] = None


class WebhookConfig(BaseModel):
    id: str
    url: str
    events: List[str] = ["score_decreased", "critical_found", "benchmark_complete"]
    secret: Optional[str] = None
    enabled: bool = True
    created_at: str


# ═══════════════════════════════════════════════════════════════════════
# Stats Cache
# ═══════════════════════════════════════════════════════════════════════

class StatsCache:
    """Thread-safe stats cache with TTL."""
    def __init__(self, ttl_seconds: int = 300):
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


stats_cache = StatsCache(ttl_seconds=300)


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
    """Trigger webhooks for events."""
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
                "source": "secubox-hardening"
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
        except Exception:
            pass

    _save_json(WEBHOOKS_FILE, webhooks)


# ═══════════════════════════════════════════════════════════════════════
# Background Tasks
# ═══════════════════════════════════════════════════════════════════════

_scheduled_benchmark_task: Optional[asyncio.Task] = None


async def _periodic_benchmark():
    """Run scheduled benchmarks."""
    while True:
        try:
            await asyncio.sleep(3600)  # Check every hour

            schedule = _load_json(SCHEDULE_FILE, {"enabled": False, "interval_hours": 24})

            if schedule.get("enabled", False):
                last_run = schedule.get("last_run")
                interval = schedule.get("interval_hours", 24)

                should_run = False
                if not last_run:
                    should_run = True
                else:
                    try:
                        last_dt = datetime.fromisoformat(last_run)
                        if datetime.now() - last_dt > timedelta(hours=interval):
                            should_run = True
                    except:
                        should_run = True

                if should_run:
                    # Run benchmark
                    result = run_ctl("benchmark", "--json", parse_json=True)
                    if isinstance(result, dict) and "score" in result:
                        # Save to history
                        history = _load_json(BENCHMARK_HISTORY_FILE, {"records": []})
                        history["records"].append({
                            "timestamp": datetime.now().isoformat(),
                            "score": result.get("score", 0),
                            "max_score": result.get("max_score", 100),
                            "passed": result.get("passed", 0),
                            "failed": result.get("failed", 0),
                            "scheduled": True
                        })
                        history["records"] = history["records"][-100:]
                        _save_json(BENCHMARK_HISTORY_FILE, history)

                        # Update schedule
                        schedule["last_run"] = datetime.now().isoformat()
                        schedule["next_run"] = (datetime.now() + timedelta(hours=interval)).isoformat()
                        _save_json(SCHEDULE_FILE, schedule)

                        # Trigger webhook
                        await _trigger_webhooks("benchmark_complete", {
                            "score": result.get("score", 0),
                            "percentage": result.get("percentage", 0)
                        })

        except asyncio.CancelledError:
            break
        except Exception:
            pass


app = FastAPI(
    title="SecuBox Hardening API",
    description="Kernel and system hardening management",
    version="2.0.0",
    docs_url="/docs",
    redoc_url=None
)

HARDENINGCTL = "/usr/sbin/hardeningctl"


@app.on_event("startup")
async def startup_event():
    """Start background tasks."""
    global _scheduled_benchmark_task
    _scheduled_benchmark_task = asyncio.create_task(_periodic_benchmark())


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks."""
    global _scheduled_benchmark_task
    if _scheduled_benchmark_task:
        _scheduled_benchmark_task.cancel()


def run_ctl(*args, parse_json=False):
    """Run hardeningctl command."""
    cmd = [HARDENINGCTL] + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if parse_json and result.returncode == 0:
            return json.loads(result.stdout)
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None
        }
    except json.JSONDecodeError:
        return {"success": False, "error": "Invalid JSON", "raw": result.stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/status")
async def get_status():
    """Get hardening status."""
    return run_ctl("status", "--json", parse_json=True)

@app.get("/components")
async def get_components():
    """Get hardening components."""
    return run_ctl("components", parse_json=True)

@app.get("/access")
async def get_access():
    """Get access information."""
    return run_ctl("access", parse_json=True)

@app.post("/benchmark")
async def run_benchmark(user: dict = Depends(require_jwt)):
    """Run security benchmark."""
    return run_ctl("benchmark")

@app.post("/apply")
async def apply_hardening(user: dict = Depends(require_jwt)):
    """Apply hardening settings."""
    return run_ctl("apply")

@app.post("/install")
async def install_hardening(user: dict = Depends(require_jwt)):
    """Install hardening configuration."""
    return run_ctl("install")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "secubox-hardening", "version": "2.0.0"}


# ═══════════════════════════════════════════════════════════════════════
# ENHANCED BENCHMARK
# ═══════════════════════════════════════════════════════════════════════

@app.get("/benchmark/score")
async def get_security_score(user: dict = Depends(require_jwt)):
    """Get current security score without running full benchmark."""
    cached = stats_cache.get("security_score")
    if cached:
        return cached

    result = run_ctl("status", "--json", parse_json=True)

    if isinstance(result, dict) and "score" in result:
        score_data = {
            "score": result.get("score", 0),
            "max_score": result.get("max_score", 100),
            "percentage": round((result.get("score", 0) / max(result.get("max_score", 100), 1)) * 100, 1),
            "grade": _calculate_grade(result.get("score", 0), result.get("max_score", 100)),
            "timestamp": datetime.now().isoformat()
        }
        stats_cache.set("security_score", score_data)
        return score_data

    return {"score": 0, "max_score": 100, "percentage": 0, "grade": "F"}


def _calculate_grade(score: int, max_score: int) -> str:
    """Calculate letter grade from score."""
    if max_score == 0:
        return "F"
    pct = (score / max_score) * 100
    if pct >= 90:
        return "A"
    elif pct >= 80:
        return "B"
    elif pct >= 70:
        return "C"
    elif pct >= 60:
        return "D"
    return "F"


@app.post("/benchmark/run")
async def run_full_benchmark(
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_jwt)
):
    """Run full security benchmark and save results."""
    result = run_ctl("benchmark", "--json", parse_json=True)

    if isinstance(result, dict) and "score" in result:
        # Save to history
        history = _load_json(BENCHMARK_HISTORY_FILE, {"records": []})

        # Check for score decrease
        if history["records"]:
            prev_score = history["records"][-1].get("score", 0)
            if result.get("score", 0) < prev_score:
                background_tasks.add_task(_trigger_webhooks, "score_decreased", {
                    "previous_score": prev_score,
                    "current_score": result.get("score", 0),
                    "difference": prev_score - result.get("score", 0)
                })

        # Check for critical findings
        if result.get("critical", 0) > 0:
            background_tasks.add_task(_trigger_webhooks, "critical_found", {
                "count": result.get("critical", 0),
                "score": result.get("score", 0)
            })

        history["records"].append({
            "timestamp": datetime.now().isoformat(),
            "score": result.get("score", 0),
            "max_score": result.get("max_score", 100),
            "percentage": round((result.get("score", 0) / max(result.get("max_score", 100), 1)) * 100, 1),
            "passed": result.get("passed", 0),
            "failed": result.get("failed", 0),
            "warnings": result.get("warnings", 0),
            "critical": result.get("critical", 0),
            "user": user.get("sub", "unknown")
        })

        # Keep last 100 records
        history["records"] = history["records"][-100:]
        _save_json(BENCHMARK_HISTORY_FILE, history)

        # Invalidate cache
        stats_cache.set("security_score", None)

        # Trigger webhook
        background_tasks.add_task(_trigger_webhooks, "benchmark_complete", {
            "score": result.get("score", 0),
            "percentage": round((result.get("score", 0) / max(result.get("max_score", 100), 1)) * 100, 1)
        })

        return result

    return {"success": False, "error": "Benchmark failed"}


@app.get("/benchmark/history")
async def get_benchmark_history(
    limit: int = Query(default=50, le=100),
    user: dict = Depends(require_jwt)
):
    """Get benchmark history."""
    history = _load_json(BENCHMARK_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    records = sorted(records, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "records": records[:limit],
        "total": len(records)
    }


@app.get("/benchmark/trend")
async def get_security_trend(
    days: int = Query(default=30, le=90),
    user: dict = Depends(require_jwt)
):
    """Get security score trend over time."""
    history = _load_json(BENCHMARK_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    # Filter by time
    cutoff = datetime.now() - timedelta(days=days)
    cutoff_str = cutoff.isoformat()
    records = [r for r in records if r.get("timestamp", "") >= cutoff_str]

    if not records:
        return {"trend": "unknown", "data": []}

    # Calculate trend
    if len(records) >= 2:
        first_score = records[0].get("percentage", 0)
        last_score = records[-1].get("percentage", 0)
        if last_score > first_score + 5:
            trend = "improving"
        elif last_score < first_score - 5:
            trend = "declining"
        else:
            trend = "stable"
    else:
        trend = "insufficient_data"

    return {
        "trend": trend,
        "period_days": days,
        "data": [{"timestamp": r["timestamp"], "score": r.get("percentage", 0)} for r in records]
    }


# ═══════════════════════════════════════════════════════════════════════
# RECOMMENDATIONS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/recommendations")
async def get_recommendations(user: dict = Depends(require_jwt)):
    """Get security recommendations based on current state."""
    result = run_ctl("benchmark", "--json", parse_json=True)

    recommendations = []

    if isinstance(result, dict):
        checks = result.get("checks", [])

        for check in checks:
            if check.get("status") in ["fail", "warn"]:
                severity = "critical" if check.get("severity") == "high" else (
                    "high" if check.get("severity") == "medium" else "medium"
                )
                recommendations.append({
                    "id": check.get("id", "unknown"),
                    "name": check.get("name", "Unknown check"),
                    "description": check.get("description", ""),
                    "severity": severity,
                    "recommendation": check.get("recommendation", "Review and fix this security issue"),
                    "category": check.get("category", "general")
                })

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    recommendations.sort(key=lambda x: severity_order.get(x["severity"], 4))

    return {
        "recommendations": recommendations[:20],
        "total": len(recommendations),
        "by_severity": {
            "critical": sum(1 for r in recommendations if r["severity"] == "critical"),
            "high": sum(1 for r in recommendations if r["severity"] == "high"),
            "medium": sum(1 for r in recommendations if r["severity"] == "medium")
        }
    }


# ═══════════════════════════════════════════════════════════════════════
# SCHEDULING
# ═══════════════════════════════════════════════════════════════════════

@app.get("/schedule")
async def get_schedule(user: dict = Depends(require_jwt)):
    """Get benchmark schedule configuration."""
    schedule = _load_json(SCHEDULE_FILE, {
        "enabled": False,
        "interval_hours": 24,
        "last_run": None,
        "next_run": None
    })
    return schedule


@app.post("/schedule")
async def set_schedule(config: ScheduleConfig, user: dict = Depends(require_jwt)):
    """Configure automatic benchmark schedule."""
    schedule = {
        "enabled": config.enabled,
        "interval_hours": config.interval_hours,
        "last_run": config.last_run,
        "next_run": (datetime.now() + timedelta(hours=config.interval_hours)).isoformat() if config.enabled else None
    }
    _save_json(SCHEDULE_FILE, schedule)

    return {"status": "success", "schedule": schedule}


# ═══════════════════════════════════════════════════════════════════════
# WEBHOOKS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/webhooks")
async def list_webhooks(user: dict = Depends(require_jwt)):
    """List configured webhooks."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})
    return {
        "webhooks": data.get("webhooks", []),
        "available_events": [
            "benchmark_complete", "score_decreased", "critical_found",
            "hardening_applied", "config_changed"
        ]
    }


class WebhookCreate(BaseModel):
    url: str
    events: List[str] = ["benchmark_complete", "score_decreased"]
    secret: Optional[str] = None
    enabled: bool = True


@app.post("/webhooks")
async def add_webhook(config: WebhookCreate, user: dict = Depends(require_jwt)):
    """Add a webhook."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    webhook_id = hashlib.sha256(f"{config.url}{time.time()}".encode()).hexdigest()[:12]

    webhook = {
        "id": webhook_id,
        "url": config.url,
        "events": config.events,
        "secret": config.secret,
        "enabled": config.enabled,
        "created_at": datetime.now().isoformat()
    }

    data["webhooks"].append(webhook)
    _save_json(WEBHOOKS_FILE, data)

    return {"status": "success", "webhook": webhook}


@app.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user: dict = Depends(require_jwt)):
    """Delete a webhook."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})

    original_len = len(data["webhooks"])
    data["webhooks"] = [w for w in data["webhooks"] if w.get("id") != webhook_id]

    if len(data["webhooks"]) == original_len:
        raise HTTPException(status_code=404, detail="Webhook not found")

    _save_json(WEBHOOKS_FILE, data)
    return {"status": "success"}


# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════

@app.get("/summary")
async def get_hardening_summary(user: dict = Depends(require_jwt)):
    """Get comprehensive hardening summary."""
    # Get current status
    status = run_ctl("status", "--json", parse_json=True)

    score = 0
    max_score = 100
    if isinstance(status, dict):
        score = status.get("score", 0)
        max_score = status.get("max_score", 100)

    percentage = round((score / max(max_score, 1)) * 100, 1)

    # Get history
    history = _load_json(BENCHMARK_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    # Calculate trend
    trend = "unknown"
    if len(records) >= 2:
        recent = records[-5:] if len(records) >= 5 else records
        first_pct = recent[0].get("percentage", 0)
        last_pct = recent[-1].get("percentage", 0)
        if last_pct > first_pct + 2:
            trend = "improving"
        elif last_pct < first_pct - 2:
            trend = "declining"
        else:
            trend = "stable"

    # Get schedule
    schedule = _load_json(SCHEDULE_FILE, {"enabled": False})

    return {
        "security": {
            "score": score,
            "max_score": max_score,
            "percentage": percentage,
            "grade": _calculate_grade(score, max_score),
            "trend": trend
        },
        "history": {
            "total_benchmarks": len(records),
            "last_benchmark": records[-1]["timestamp"] if records else None
        },
        "schedule": {
            "enabled": schedule.get("enabled", False),
            "interval_hours": schedule.get("interval_hours", 24),
            "next_run": schedule.get("next_run")
        },
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
