"""
SecuBox-Deb :: Metabolizer
CyberMind - https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

Log processor/analyzer module - parses journalctl logs, extracts patterns,
calculates statistics, and monitors log rotation.
"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger
from typing import Optional
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
import asyncio
import json
import subprocess
import re
from collections import defaultdict

app = FastAPI(title="secubox-metabolizer", version="1.0.0", root_path="/api/v1/metabolizer")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("metabolizer")

# Configuration
CACHE_FILE = Path("/var/cache/secubox/metabolizer/stats.json")
LOG_DIRS = ["/var/log", "/var/log/secubox"]
SECUBOX_SERVICES = [
    "secubox-hub", "secubox-crowdsec", "secubox-wireguard", "secubox-dpi",
    "secubox-nac", "secubox-qos", "secubox-system", "secubox-reporter",
    "secubox-metabolizer", "secubox-netdata", "secubox-vhost", "secubox-auth",
    "secubox-cdn", "secubox-netmodes", "secubox-mediaflow",
]

# Ensure directories exist
CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

# In-memory cache
_cache: dict = {}


class LogLevel(str, Enum):
    emerg = "emerg"
    alert = "alert"
    crit = "crit"
    err = "err"
    warning = "warning"
    notice = "notice"
    info = "info"
    debug = "debug"


class PatternType(str, Enum):
    error = "error"
    warning = "warning"
    auth_failure = "auth_failure"
    connection = "connection"
    service_state = "service_state"
    security = "security"


class LogEntry(BaseModel):
    timestamp: str
    service: str
    priority: int
    message: str
    unit: Optional[str] = None
    pid: Optional[int] = None


class PatternMatch(BaseModel):
    pattern_type: PatternType
    pattern: str
    count: int
    services: list[str]
    recent_match: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class ServiceLogStats(BaseModel):
    service: str
    total_lines: int
    error_count: int
    warning_count: int
    info_count: int
    lines_per_hour: float
    error_rate: float
    last_activity: Optional[str] = None


# Common error patterns to detect
ERROR_PATTERNS = [
    (PatternType.error, r"(?:error|fail(?:ed|ure)?|exception|fatal|critical)", "Error/Failure"),
    (PatternType.warning, r"(?:warn(?:ing)?|deprecated|timeout)", "Warning"),
    (PatternType.auth_failure, r"(?:auth(?:entication)?\s*fail|invalid\s*(?:password|credentials|token)|access\s*denied|permission\s*denied|unauthorized)", "Authentication Failure"),
    (PatternType.connection, r"(?:connection\s*(?:refused|reset|closed|timeout)|socket\s*error|network\s*(?:unreachable|down))", "Connection Issue"),
    (PatternType.service_state, r"(?:start(?:ed|ing)|stop(?:ped|ping)|restart(?:ed|ing)|reload(?:ed|ing))", "Service State Change"),
    (PatternType.security, r"(?:blocked|banned|intrusion|attack|vulnerability|exploit|malicious)", "Security Event"),
]


def _run_journalctl(args: list[str], timeout: int = 30) -> str:
    """Run journalctl with given arguments."""
    try:
        cmd = ["journalctl"] + args
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        log.warning(f"journalctl timed out with args: {args}")
        return ""
    except Exception as e:
        log.error(f"journalctl error: {e}")
        return ""


def _parse_journalctl_json(output: str) -> list[dict]:
    """Parse journalctl JSON output."""
    entries = []
    for line in output.strip().split("\n"):
        if not line:
            continue
        try:
            entry = json.loads(line)
            entries.append(entry)
        except json.JSONDecodeError:
            continue
    return entries


def _get_service_logs(service: str, since: str = "1h", lines: int = 500) -> list[dict]:
    """Get logs for a specific service."""
    output = _run_journalctl([
        "-u", service,
        "--since", f"-{since}",
        "-n", str(lines),
        "-o", "json",
        "--no-pager"
    ])
    return _parse_journalctl_json(output)


def _get_all_logs(since: str = "1h", lines: int = 1000, priority: Optional[int] = None) -> list[dict]:
    """Get all system logs."""
    args = [
        "--since", f"-{since}",
        "-n", str(lines),
        "-o", "json",
        "--no-pager"
    ]
    if priority is not None:
        args.extend(["-p", str(priority)])

    output = _run_journalctl(args)
    return _parse_journalctl_json(output)


def _analyze_patterns(entries: list[dict]) -> dict[str, PatternMatch]:
    """Analyze log entries for patterns."""
    patterns: dict[str, PatternMatch] = {}

    for entry in entries:
        message = entry.get("MESSAGE", "")
        if not message or not isinstance(message, str):
            continue

        service = entry.get("_SYSTEMD_UNIT", entry.get("SYSLOG_IDENTIFIER", "unknown"))
        timestamp = entry.get("__REALTIME_TIMESTAMP", "")

        # Convert timestamp from microseconds to ISO format
        if timestamp:
            try:
                ts_int = int(timestamp)
                dt = datetime.fromtimestamp(ts_int / 1_000_000)
                timestamp = dt.isoformat()
            except (ValueError, OSError):
                timestamp = ""

        for pattern_type, regex, description in ERROR_PATTERNS:
            if re.search(regex, message, re.IGNORECASE):
                key = f"{pattern_type.value}:{description}"

                if key not in patterns:
                    patterns[key] = PatternMatch(
                        pattern_type=pattern_type,
                        pattern=description,
                        count=0,
                        services=[],
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )

                patterns[key].count += 1
                if service and service not in patterns[key].services:
                    patterns[key].services.append(service)
                patterns[key].last_seen = timestamp
                patterns[key].recent_match = message[:200]

    return patterns


def _calculate_service_stats(service: str, entries: list[dict]) -> ServiceLogStats:
    """Calculate statistics for a service's logs."""
    total = len(entries)
    errors = 0
    warnings = 0
    infos = 0

    timestamps = []

    for entry in entries:
        priority = entry.get("PRIORITY", 6)
        if isinstance(priority, str):
            try:
                priority = int(priority)
            except ValueError:
                priority = 6

        if priority <= 3:  # err, crit, alert, emerg
            errors += 1
        elif priority == 4:  # warning
            warnings += 1
        elif priority >= 5:  # notice, info, debug
            infos += 1

        ts = entry.get("__REALTIME_TIMESTAMP", "")
        if ts:
            try:
                timestamps.append(int(ts))
            except ValueError:
                pass

    # Calculate lines per hour
    lines_per_hour = 0.0
    last_activity = None

    if timestamps:
        timestamps.sort()
        first_ts = timestamps[0]
        last_ts = timestamps[-1]

        # Convert to datetime
        try:
            last_dt = datetime.fromtimestamp(last_ts / 1_000_000)
            last_activity = last_dt.isoformat()

            duration_hours = (last_ts - first_ts) / (1_000_000 * 3600)
            if duration_hours > 0:
                lines_per_hour = total / duration_hours
        except (ValueError, OSError):
            pass

    error_rate = (errors / total * 100) if total > 0 else 0.0

    return ServiceLogStats(
        service=service,
        total_lines=total,
        error_count=errors,
        warning_count=warnings,
        info_count=infos,
        lines_per_hour=round(lines_per_hour, 2),
        error_rate=round(error_rate, 2),
        last_activity=last_activity,
    )


def _get_log_rotation_info() -> list[dict]:
    """Get information about log files and rotation."""
    rotation_info = []

    for log_dir in LOG_DIRS:
        log_path = Path(log_dir)
        if not log_path.exists():
            continue

        try:
            for log_file in log_path.iterdir():
                if not log_file.is_file():
                    continue

                stat = log_file.stat()
                rotation_info.append({
                    "path": str(log_file),
                    "name": log_file.name,
                    "size_bytes": stat.st_size,
                    "size_human": _format_bytes(stat.st_size),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "is_rotated": bool(re.search(r"\.\d+(?:\.gz)?$", log_file.name)),
                })
        except PermissionError:
            log.debug(f"Permission denied for {log_dir}")
            continue

    # Sort by modification time, newest first
    rotation_info.sort(key=lambda x: x["modified"], reverse=True)

    return rotation_info[:50]  # Limit to 50 files


def _format_bytes(b: int) -> str:
    """Format bytes to human-readable string."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024**2:
        return f"{b/1024:.1f} KB"
    elif b < 1024**3:
        return f"{b/1024**2:.1f} MB"
    else:
        return f"{b/1024**3:.2f} GB"


def _get_available_services() -> list[dict]:
    """Get list of available services with log activity."""
    services = []

    # Get list of systemd units
    output = _run_journalctl(["--list-boots", "-o", "json"], timeout=10)

    # Check SecuBox services
    for svc in SECUBOX_SERVICES:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True, text=True, timeout=5
            )
            status = result.stdout.strip()

            # Check if service has logs
            log_output = _run_journalctl(["-u", svc, "-n", "1", "-o", "json"], timeout=5)
            has_logs = bool(log_output.strip())

            services.append({
                "name": svc,
                "active": status == "active",
                "status": status,
                "has_logs": has_logs,
            })
        except Exception:
            services.append({
                "name": svc,
                "active": False,
                "status": "unknown",
                "has_logs": False,
            })

    # Get other services with recent activity
    other_output = _run_journalctl([
        "--since", "-1h",
        "-o", "json",
        "--no-pager",
        "-n", "100"
    ])
    entries = _parse_journalctl_json(other_output)

    other_services = set()
    for entry in entries:
        unit = entry.get("_SYSTEMD_UNIT", "")
        if unit and unit not in [s["name"] for s in services]:
            other_services.add(unit)

    for unit in sorted(other_services)[:20]:  # Limit to 20 other services
        services.append({
            "name": unit,
            "active": True,  # Has recent logs, so likely active
            "status": "active",
            "has_logs": True,
        })

    return services


# ═══════════════════════════════════════════════════════════════════
# API Endpoints
# ═══════════════════════════════════════════════════════════════════

@router.get("/health")
async def health():
    """Health check endpoint (public)."""
    return {"status": "ok", "module": "metabolizer", "version": "1.0.0"}


@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Get module status and overview."""
    # Get quick stats
    entries = _get_all_logs(since="1h", lines=500)

    error_count = sum(1 for e in entries if int(e.get("PRIORITY", 6)) <= 3)
    warning_count = sum(1 for e in entries if int(e.get("PRIORITY", 6)) == 4)

    # Count unique services
    services = set()
    for e in entries:
        unit = e.get("_SYSTEMD_UNIT", e.get("SYSLOG_IDENTIFIER", ""))
        if unit:
            services.add(unit)

    return {
        "module": "metabolizer",
        "version": "1.0.0",
        "status": "running",
        "last_hour": {
            "total_entries": len(entries),
            "error_count": error_count,
            "warning_count": warning_count,
            "active_services": len(services),
        },
        "cache_file": str(CACHE_FILE),
        "cache_exists": CACHE_FILE.exists(),
    }


@router.get("/stats")
async def get_stats(
    since: str = Query("1h", description="Time window (e.g., 1h, 6h, 24h, 7d)"),
    user=Depends(require_jwt)
):
    """Get overall log statistics."""
    entries = _get_all_logs(since=since, lines=2000)

    # Priority distribution
    priority_counts = defaultdict(int)
    hourly_counts = defaultdict(int)
    service_counts = defaultdict(int)

    for entry in entries:
        # Priority
        priority = entry.get("PRIORITY", 6)
        if isinstance(priority, str):
            try:
                priority = int(priority)
            except ValueError:
                priority = 6
        priority_counts[priority] += 1

        # Service
        unit = entry.get("_SYSTEMD_UNIT", entry.get("SYSLOG_IDENTIFIER", "other"))
        service_counts[unit] += 1

        # Hourly
        ts = entry.get("__REALTIME_TIMESTAMP", "")
        if ts:
            try:
                ts_int = int(ts)
                dt = datetime.fromtimestamp(ts_int / 1_000_000)
                hour_key = dt.strftime("%Y-%m-%d %H:00")
                hourly_counts[hour_key] += 1
            except (ValueError, OSError):
                pass

    # Calculate rates
    total = len(entries)
    error_count = sum(priority_counts.get(p, 0) for p in [0, 1, 2, 3])  # emerg, alert, crit, err
    warning_count = priority_counts.get(4, 0)

    # Top services by log volume
    top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Hourly trend (sorted)
    hourly_trend = [{"hour": k, "count": v} for k, v in sorted(hourly_counts.items())]

    return {
        "time_window": since,
        "total_entries": total,
        "error_count": error_count,
        "warning_count": warning_count,
        "info_count": total - error_count - warning_count,
        "error_rate_percent": round(error_count / total * 100, 2) if total > 0 else 0,
        "priority_distribution": {
            "emerg": priority_counts.get(0, 0),
            "alert": priority_counts.get(1, 0),
            "crit": priority_counts.get(2, 0),
            "err": priority_counts.get(3, 0),
            "warning": priority_counts.get(4, 0),
            "notice": priority_counts.get(5, 0),
            "info": priority_counts.get(6, 0),
            "debug": priority_counts.get(7, 0),
        },
        "top_services": [{"service": s, "count": c} for s, c in top_services],
        "hourly_trend": hourly_trend[-24:],  # Last 24 hours
    }


@router.get("/analyze")
async def analyze_logs(
    since: str = Query("1h", description="Time window"),
    priority: Optional[int] = Query(None, description="Filter by priority (0-7)"),
    service: Optional[str] = Query(None, description="Filter by service name"),
    user=Depends(require_jwt)
):
    """Analyze logs and extract patterns."""
    if service:
        entries = _get_service_logs(service, since=since, lines=1000)
    else:
        entries = _get_all_logs(since=since, lines=2000, priority=priority)

    # Analyze patterns
    patterns = _analyze_patterns(entries)

    # Sort by count
    sorted_patterns = sorted(patterns.values(), key=lambda p: p.count, reverse=True)

    # Get statistics
    stats = {
        "total_entries": len(entries),
        "patterns_found": len(patterns),
        "time_window": since,
    }

    if service:
        stats["service"] = service
    if priority is not None:
        stats["priority_filter"] = priority

    return {
        "stats": stats,
        "patterns": [p.model_dump() for p in sorted_patterns[:20]],  # Top 20 patterns
    }


@router.get("/services")
async def list_services(user=Depends(require_jwt)):
    """List available services with log information."""
    services = _get_available_services()

    # Group by status
    active_count = sum(1 for s in services if s["active"])

    return {
        "services": services,
        "total": len(services),
        "active_count": active_count,
    }


@router.get("/services/{service_name}/stats")
async def get_service_stats(
    service_name: str,
    since: str = Query("1h", description="Time window"),
    user=Depends(require_jwt)
):
    """Get detailed statistics for a specific service."""
    entries = _get_service_logs(service_name, since=since, lines=1000)

    if not entries:
        raise HTTPException(404, f"No logs found for service: {service_name}")

    stats = _calculate_service_stats(service_name, entries)
    patterns = _analyze_patterns(entries)

    # Get recent errors
    recent_errors = []
    for entry in entries:
        priority = int(entry.get("PRIORITY", 6))
        if priority <= 3:
            message = entry.get("MESSAGE", "")
            ts = entry.get("__REALTIME_TIMESTAMP", "")
            if ts:
                try:
                    ts_int = int(ts)
                    dt = datetime.fromtimestamp(ts_int / 1_000_000)
                    ts = dt.isoformat()
                except (ValueError, OSError):
                    ts = ""
            recent_errors.append({
                "timestamp": ts,
                "message": message[:300] if isinstance(message, str) else str(message)[:300],
            })

    return {
        "service": service_name,
        "time_window": since,
        "stats": stats.model_dump(),
        "patterns": [p.model_dump() for p in sorted(patterns.values(), key=lambda x: x.count, reverse=True)[:10]],
        "recent_errors": recent_errors[:10],
    }


@router.get("/services/{service_name}/logs")
async def get_service_logs(
    service_name: str,
    lines: int = Query(100, ge=1, le=1000),
    since: str = Query("1h", description="Time window"),
    priority: Optional[int] = Query(None, ge=0, le=7),
    user=Depends(require_jwt)
):
    """Get raw logs for a specific service."""
    args = [
        "-u", service_name,
        "--since", f"-{since}",
        "-n", str(lines),
        "-o", "json",
        "--no-pager"
    ]
    if priority is not None:
        args.extend(["-p", str(priority)])

    output = _run_journalctl(args)
    entries = _parse_journalctl_json(output)

    # Format entries for output
    logs = []
    for entry in entries:
        ts = entry.get("__REALTIME_TIMESTAMP", "")
        if ts:
            try:
                ts_int = int(ts)
                dt = datetime.fromtimestamp(ts_int / 1_000_000)
                ts = dt.isoformat()
            except (ValueError, OSError):
                ts = ""

        logs.append({
            "timestamp": ts,
            "priority": entry.get("PRIORITY", 6),
            "message": entry.get("MESSAGE", ""),
            "pid": entry.get("_PID"),
        })

    return {
        "service": service_name,
        "lines": len(logs),
        "logs": logs,
    }


@router.get("/patterns")
async def get_patterns(
    since: str = Query("24h", description="Time window"),
    pattern_type: Optional[PatternType] = Query(None, description="Filter by pattern type"),
    user=Depends(require_jwt)
):
    """Get detected patterns across all services."""
    entries = _get_all_logs(since=since, lines=5000)
    patterns = _analyze_patterns(entries)

    # Filter by type if specified
    if pattern_type:
        patterns = {k: v for k, v in patterns.items() if v.pattern_type == pattern_type}

    # Sort by count
    sorted_patterns = sorted(patterns.values(), key=lambda p: p.count, reverse=True)

    # Group by type
    by_type = defaultdict(list)
    for p in sorted_patterns:
        by_type[p.pattern_type.value].append(p.model_dump())

    return {
        "time_window": since,
        "total_patterns": len(patterns),
        "patterns_by_type": dict(by_type),
        "all_patterns": [p.model_dump() for p in sorted_patterns],
    }


@router.get("/errors")
async def get_errors(
    since: str = Query("6h", description="Time window"),
    limit: int = Query(50, ge=1, le=500),
    service: Optional[str] = Query(None, description="Filter by service"),
    user=Depends(require_jwt)
):
    """Get recent errors and critical log entries."""
    if service:
        entries = _get_service_logs(service, since=since, lines=limit * 2)
    else:
        entries = _get_all_logs(since=since, lines=limit * 4, priority=3)  # err and above

    errors = []
    for entry in entries:
        priority = entry.get("PRIORITY", 6)
        if isinstance(priority, str):
            try:
                priority = int(priority)
            except ValueError:
                priority = 6

        if priority > 3:
            continue

        ts = entry.get("__REALTIME_TIMESTAMP", "")
        if ts:
            try:
                ts_int = int(ts)
                dt = datetime.fromtimestamp(ts_int / 1_000_000)
                ts = dt.isoformat()
            except (ValueError, OSError):
                ts = ""

        priority_names = {0: "emerg", 1: "alert", 2: "crit", 3: "err"}

        errors.append({
            "timestamp": ts,
            "service": entry.get("_SYSTEMD_UNIT", entry.get("SYSLOG_IDENTIFIER", "unknown")),
            "priority": priority,
            "priority_name": priority_names.get(priority, "unknown"),
            "message": entry.get("MESSAGE", ""),
            "pid": entry.get("_PID"),
        })

    # Sort by timestamp, newest first
    errors.sort(key=lambda x: x["timestamp"], reverse=True)
    errors = errors[:limit]

    return {
        "time_window": since,
        "total_errors": len(errors),
        "errors": errors,
    }


@router.get("/rotation")
async def get_rotation_info(user=Depends(require_jwt)):
    """Get log rotation and file information."""
    rotation_info = _get_log_rotation_info()

    # Calculate totals
    total_size = sum(f["size_bytes"] for f in rotation_info)
    rotated_files = sum(1 for f in rotation_info if f["is_rotated"])

    return {
        "files": rotation_info,
        "total_files": len(rotation_info),
        "rotated_files": rotated_files,
        "total_size_bytes": total_size,
        "total_size_human": _format_bytes(total_size),
        "log_dirs": LOG_DIRS,
    }


# Background cache refresh task
async def refresh_cache():
    """Background task to update stats cache."""
    global _cache
    while True:
        try:
            entries = _get_all_logs(since="1h", lines=1000)
            error_count = sum(1 for e in entries if int(e.get("PRIORITY", 6)) <= 3)
            warning_count = sum(1 for e in entries if int(e.get("PRIORITY", 6)) == 4)

            _cache = {
                "total_entries": len(entries),
                "error_count": error_count,
                "warning_count": warning_count,
                "updated_at": datetime.now().isoformat(),
            }
            CACHE_FILE.write_text(json.dumps(_cache, indent=2))
        except Exception as e:
            log.error(f"Cache refresh failed: {e}")
        await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    """Startup tasks."""
    asyncio.create_task(refresh_cache())
    log.info("SecuBox Metabolizer started")


app.include_router(router)
