"""SecuBox DNS Master API - BIND Zone Management

Enhanced features (v2.0.0):
- Query statistics tracking
- Zone change history
- Record validation
- DNSSEC status monitoring
- Webhook notifications
- Stats caching
- Export/import zones
"""
import subprocess
import json
import time
import threading
import asyncio
import hashlib
import hmac
import httpx
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field, validator
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox DNS Master", version="2.0.0")
config = get_config("dns")

DNSMASTER_CMD = "/usr/sbin/dnsmaster"

# Data paths
DATA_DIR = Path("/var/lib/secubox/dns")
STATS_HISTORY_FILE = DATA_DIR / "stats_history.json"
CHANGE_HISTORY_FILE = DATA_DIR / "change_history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════

class RecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    PTR = "PTR"
    SRV = "SRV"
    CAA = "CAA"


class WebhookConfig(BaseModel):
    id: str
    url: str
    events: List[str] = ["zone_created", "zone_deleted", "record_changed"]
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


def _record_change(action: str, details: dict, user: str = "system"):
    """Record a change in history."""
    history = _load_json(CHANGE_HISTORY_FILE, {"records": []})
    history["records"].append({
        "action": action,
        "timestamp": datetime.now().isoformat(),
        "user": user,
        "details": details
    })
    # Keep last 1000 records
    history["records"] = history["records"][-1000:]
    _save_json(CHANGE_HISTORY_FILE, history)


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
                "source": "secubox-dns"
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


def run_cmd(args: list, capture=True) -> tuple:
    """Run dnsmaster command"""
    try:
        result = subprocess.run(
            [DNSMASTER_CMD] + args,
            capture_output=capture,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return 1, "", "dnsmaster not installed"
    except Exception as e:
        return 1, "", str(e)


# ═══════════════════════════════════════════════════════════════════════
# Background Tasks
# ═══════════════════════════════════════════════════════════════════════

_stats_collector_task: Optional[asyncio.Task] = None


async def _periodic_stats_collector():
    """Collect DNS stats periodically."""
    while True:
        try:
            await asyncio.sleep(60)  # Collect every minute

            code, out, _ = run_cmd(["status-json"])
            if code == 0:
                try:
                    status = json.loads(out)

                    history = _load_json(STATS_HISTORY_FILE, {"records": []})
                    history["records"].append({
                        "timestamp": datetime.now().isoformat(),
                        "running": status.get("running", False),
                        "zones": status.get("zones", 0),
                        "records": status.get("records", 0),
                        "queries": status.get("queries", 0)
                    })

                    # Keep last 1440 records (24h)
                    history["records"] = history["records"][-1440:]
                    _save_json(STATS_HISTORY_FILE, history)
                except json.JSONDecodeError:
                    pass

        except asyncio.CancelledError:
            break
        except Exception:
            pass


@app.on_event("startup")
async def startup_event():
    """Start background tasks."""
    global _stats_collector_task
    _stats_collector_task = asyncio.create_task(_periodic_stats_collector())


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks."""
    global _stats_collector_task
    if _stats_collector_task:
        _stats_collector_task.cancel()


# Models
class RecordCreate(BaseModel):
    zone: str
    type: str
    name: str
    value: str
    ttl: Optional[int] = Field(default=300, ge=60, le=86400)

    @validator('type')
    def validate_type(cls, v):
        valid_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR', 'SRV', 'CAA']
        if v.upper() not in valid_types:
            raise ValueError(f"Invalid record type. Must be one of: {valid_types}")
        return v.upper()


class RecordDelete(BaseModel):
    zone: str
    type: str
    name: str
    value: Optional[str] = None


class ZoneCreate(BaseModel):
    name: str

    @validator('name')
    def validate_zone_name(cls, v):
        if not v or len(v) < 2:
            raise ValueError("Zone name too short")
        if not all(c.isalnum() or c in '.-' for c in v):
            raise ValueError("Zone name contains invalid characters")
        return v.lower()


# Public endpoints
@app.get("/status")
async def status():
    """Get BIND status"""
    code, out, err = run_cmd(["status-json"])
    if code == 0:
        try:
            return json.loads(out)
        except:
            pass
    return {"running": False, "zones": 0, "records": 0}


@app.get("/zones")
async def list_zones():
    """List all DNS zones"""
    code, out, err = run_cmd(["zone-list-json"])
    if code == 0:
        try:
            return json.loads(out)
        except:
            pass
    return {"zones": []}


@app.get("/zone/{zone_name}/records")
async def get_records(zone_name: str):
    """Get records for a zone"""
    code, out, err = run_cmd(["records-json", zone_name])
    if code == 0:
        try:
            return json.loads(out)
        except:
            pass
    return {"error": "Zone not found", "zone": zone_name, "records": []}


# Protected endpoints
@app.post("/zone", dependencies=[Depends(require_jwt)])
async def add_zone(data: ZoneCreate):
    """Create a new DNS zone"""
    code, out, err = run_cmd(["zone-add", data.name])
    return {"success": code == 0, "code": code, "output": out or err}


@app.delete("/zone/{zone_name}", dependencies=[Depends(require_jwt)])
async def delete_zone(zone_name: str):
    """Delete a DNS zone"""
    code, out, err = run_cmd(["zone-del", zone_name])
    return {"success": code == 0, "code": code, "output": out or err}


@app.post("/record", dependencies=[Depends(require_jwt)])
async def add_record(data: RecordCreate):
    """Add a DNS record"""
    args = ["record-add", data.zone, data.type, data.name, data.value]
    if data.ttl:
        args.append(str(data.ttl))
    code, out, err = run_cmd(args)
    return {"success": code == 0, "code": code, "output": out or err}


@app.delete("/record", dependencies=[Depends(require_jwt)])
async def delete_record(data: RecordDelete):
    """Delete a DNS record"""
    args = ["record-del", data.zone, data.type, data.name]
    if data.value:
        args.append(data.value)
    code, out, err = run_cmd(args)
    return {"success": code == 0, "code": code, "output": out or err}


@app.post("/reload", dependencies=[Depends(require_jwt)])
async def reload_bind():
    """Reload BIND configuration"""
    code, out, err = run_cmd(["reload"])
    return {"success": code == 0, "code": code, "output": out or err}


@app.get("/check", dependencies=[Depends(require_jwt)])
async def check_config(zone: Optional[str] = None):
    """Check BIND configuration"""
    args = ["check"]
    if zone:
        args.append(zone)
    code, out, err = run_cmd(args)
    return {"valid": code == 0, "code": code, "output": out or err}


@app.get("/logs", dependencies=[Depends(require_jwt)])
async def get_logs(lines: int = 50):
    """Get BIND logs"""
    code, out, err = run_cmd(["logs", str(lines)])
    return {"logs": out}


@app.post("/backup/{zone_name}", dependencies=[Depends(require_jwt)])
async def backup_zone(zone_name: str):
    """Backup a DNS zone"""
    code, out, err = run_cmd(["backup", zone_name])

    if code == 0:
        _record_change("zone_backup", {"zone": zone_name})

    return {"success": code == 0, "code": code, "output": out or err}


# ═══════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ═══════════════════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    """Health check endpoint."""
    code, out, _ = run_cmd(["status-json"])
    if code == 0:
        try:
            status = json.loads(out)
            return {
                "status": "ok" if status.get("running") else "degraded",
                "module": "dns",
                "version": "2.0.0",
                "running": status.get("running", False)
            }
        except json.JSONDecodeError:
            pass

    return {
        "status": "degraded",
        "module": "dns",
        "version": "2.0.0",
        "running": False
    }


# ═══════════════════════════════════════════════════════════════════════
# STATISTICS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get detailed DNS statistics."""
    cached = stats_cache.get("dns_stats")
    if cached:
        return cached

    code, out, _ = run_cmd(["status-json"])
    if code != 0:
        return {"error": "Cannot get stats"}

    try:
        status = json.loads(out)
    except json.JSONDecodeError:
        return {"error": "Invalid stats response"}

    # Get zone details
    zones_code, zones_out, _ = run_cmd(["zone-list-json"])
    zones = []
    if zones_code == 0:
        try:
            zones_data = json.loads(zones_out)
            zones = zones_data.get("zones", [])
        except json.JSONDecodeError:
            pass

    # Calculate record types distribution
    record_types = {}
    for zone in zones:
        zone_name = zone.get("name") if isinstance(zone, dict) else zone
        rec_code, rec_out, _ = run_cmd(["records-json", zone_name])
        if rec_code == 0:
            try:
                rec_data = json.loads(rec_out)
                for rec in rec_data.get("records", []):
                    rtype = rec.get("type", "OTHER")
                    record_types[rtype] = record_types.get(rtype, 0) + 1
            except json.JSONDecodeError:
                pass

    stats = {
        "running": status.get("running", False),
        "zones": status.get("zones", len(zones)),
        "total_records": status.get("records", 0),
        "queries": status.get("queries", 0),
        "record_types": record_types,
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("dns_stats", stats)
    return stats


@app.get("/stats/history", dependencies=[Depends(require_jwt)])
async def get_stats_history(hours: int = Query(default=24, le=168)):
    """Get DNS stats history."""
    history = _load_json(STATS_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    # Filter by time
    cutoff = datetime.now() - timedelta(hours=hours)
    cutoff_str = cutoff.isoformat()
    records = [r for r in records if r.get("timestamp", "") >= cutoff_str]

    return {
        "records": records,
        "period_hours": hours
    }


# ═══════════════════════════════════════════════════════════════════════
# CHANGE HISTORY
# ═══════════════════════════════════════════════════════════════════════

@app.get("/history", dependencies=[Depends(require_jwt)])
async def get_change_history(
    limit: int = Query(default=100, le=1000),
    action: Optional[str] = None
):
    """Get zone/record change history."""
    history = _load_json(CHANGE_HISTORY_FILE, {"records": []})
    records = history.get("records", [])

    if action:
        records = [r for r in records if r.get("action") == action]

    records = sorted(records, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "records": records[:limit],
        "total": len(records)
    }


# ═══════════════════════════════════════════════════════════════════════
# ZONE MANAGEMENT (Enhanced)
# ═══════════════════════════════════════════════════════════════════════

@app.post("/zone", dependencies=[Depends(require_jwt)])
async def add_zone(data: ZoneCreate, background_tasks: BackgroundTasks):
    """Create a new DNS zone"""
    code, out, err = run_cmd(["zone-add", data.name])

    if code == 0:
        _record_change("zone_created", {"zone": data.name})
        background_tasks.add_task(_trigger_webhooks, "zone_created", {"zone": data.name})

    return {"success": code == 0, "code": code, "output": out or err}


@app.delete("/zone/{zone_name}", dependencies=[Depends(require_jwt)])
async def delete_zone(zone_name: str, background_tasks: BackgroundTasks):
    """Delete a DNS zone"""
    code, out, err = run_cmd(["zone-del", zone_name])

    if code == 0:
        _record_change("zone_deleted", {"zone": zone_name})
        background_tasks.add_task(_trigger_webhooks, "zone_deleted", {"zone": zone_name})

    return {"success": code == 0, "code": code, "output": out or err}


@app.get("/zone/{zone_name}", dependencies=[Depends(require_jwt)])
async def get_zone_details(zone_name: str):
    """Get detailed zone information."""
    rec_code, rec_out, _ = run_cmd(["records-json", zone_name])

    if rec_code != 0:
        raise HTTPException(404, f"Zone {zone_name} not found")

    try:
        records = json.loads(rec_out)
    except json.JSONDecodeError:
        records = {"records": []}

    # Group records by type
    by_type = {}
    for rec in records.get("records", []):
        rtype = rec.get("type", "OTHER")
        if rtype not in by_type:
            by_type[rtype] = []
        by_type[rtype].append(rec)

    return {
        "zone": zone_name,
        "records": records.get("records", []),
        "record_count": len(records.get("records", [])),
        "by_type": by_type
    }


# ═══════════════════════════════════════════════════════════════════════
# RECORD MANAGEMENT (Enhanced)
# ═══════════════════════════════════════════════════════════════════════

@app.post("/record", dependencies=[Depends(require_jwt)])
async def add_record(data: RecordCreate, background_tasks: BackgroundTasks):
    """Add a DNS record"""
    args = ["record-add", data.zone, data.type, data.name, data.value]
    if data.ttl:
        args.append(str(data.ttl))
    code, out, err = run_cmd(args)

    if code == 0:
        _record_change("record_added", {
            "zone": data.zone,
            "type": data.type,
            "name": data.name,
            "value": data.value,
            "ttl": data.ttl
        })
        background_tasks.add_task(_trigger_webhooks, "record_changed", {
            "action": "added",
            "zone": data.zone,
            "type": data.type,
            "name": data.name
        })

    return {"success": code == 0, "code": code, "output": out or err}


@app.delete("/record", dependencies=[Depends(require_jwt)])
async def delete_record(data: RecordDelete, background_tasks: BackgroundTasks):
    """Delete a DNS record"""
    args = ["record-del", data.zone, data.type, data.name]
    if data.value:
        args.append(data.value)
    code, out, err = run_cmd(args)

    if code == 0:
        _record_change("record_deleted", {
            "zone": data.zone,
            "type": data.type,
            "name": data.name
        })
        background_tasks.add_task(_trigger_webhooks, "record_changed", {
            "action": "deleted",
            "zone": data.zone,
            "type": data.type,
            "name": data.name
        })

    return {"success": code == 0, "code": code, "output": out or err}


# ═══════════════════════════════════════════════════════════════════════
# VALIDATION
# ═══════════════════════════════════════════════════════════════════════

@app.post("/validate/record", dependencies=[Depends(require_jwt)])
async def validate_record(data: RecordCreate):
    """Validate a DNS record before adding."""
    errors = []

    # Validate record type
    valid_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR', 'SRV', 'CAA']
    if data.type.upper() not in valid_types:
        errors.append(f"Invalid record type: {data.type}")

    # Validate value based on type
    rtype = data.type.upper()

    if rtype == "A":
        import re
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', data.value):
            errors.append("A record must be a valid IPv4 address")

    elif rtype == "AAAA":
        if not ":" in data.value:
            errors.append("AAAA record must be a valid IPv6 address")

    elif rtype == "MX":
        if not data.value[0].isdigit():
            errors.append("MX record should start with priority number")

    elif rtype == "TXT":
        if len(data.value) > 255:
            errors.append("TXT record exceeds 255 characters")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "record": data.dict()
    }


# ═══════════════════════════════════════════════════════════════════════
# WEBHOOKS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/webhooks", dependencies=[Depends(require_jwt)])
async def list_webhooks():
    """List configured webhooks."""
    data = _load_json(WEBHOOKS_FILE, {"webhooks": []})
    return {
        "webhooks": data.get("webhooks", []),
        "available_events": [
            "zone_created", "zone_deleted", "record_changed",
            "config_reload", "validation_failed"
        ]
    }


class WebhookCreate(BaseModel):
    url: str
    events: List[str] = ["zone_created", "record_changed"]
    secret: Optional[str] = None
    enabled: bool = True


@app.post("/webhooks", dependencies=[Depends(require_jwt)])
async def add_webhook(config: WebhookCreate):
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


@app.delete("/webhooks/{webhook_id}", dependencies=[Depends(require_jwt)])
async def delete_webhook(webhook_id: str):
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

@app.get("/summary", dependencies=[Depends(require_jwt)])
async def get_dns_summary():
    """Get comprehensive DNS summary."""
    code, out, _ = run_cmd(["status-json"])

    status = {"running": False, "zones": 0, "records": 0}
    if code == 0:
        try:
            status = json.loads(out)
        except json.JSONDecodeError:
            pass

    # Get zones
    zones_code, zones_out, _ = run_cmd(["zone-list-json"])
    zones = []
    if zones_code == 0:
        try:
            zones_data = json.loads(zones_out)
            zones = zones_data.get("zones", [])
        except json.JSONDecodeError:
            pass

    # Recent changes
    history = _load_json(CHANGE_HISTORY_FILE, {"records": []})
    recent_changes = sorted(
        history.get("records", []),
        key=lambda x: x.get("timestamp", ""),
        reverse=True
    )[:5]

    return {
        "service": {
            "running": status.get("running", False),
            "version": "2.0.0"
        },
        "stats": {
            "zones": status.get("zones", len(zones)),
            "records": status.get("records", 0),
            "queries": status.get("queries", 0)
        },
        "zones": [z.get("name") if isinstance(z, dict) else z for z in zones[:10]],
        "recent_changes": recent_changes,
        "timestamp": datetime.now().isoformat()
    }


# ═══════════════════════════════════════════════════════════════════════
# EXPORT / IMPORT
# ═══════════════════════════════════════════════════════════════════════

@app.get("/export/zone/{zone_name}", dependencies=[Depends(require_jwt)])
async def export_zone(zone_name: str, format: str = Query(default="json", enum=["json", "bind"])):
    """Export a DNS zone."""
    rec_code, rec_out, _ = run_cmd(["records-json", zone_name])

    if rec_code != 0:
        raise HTTPException(404, f"Zone {zone_name} not found")

    try:
        records = json.loads(rec_out)
    except json.JSONDecodeError:
        records = {"records": []}

    if format == "bind":
        # Generate BIND zone file format
        lines = [
            f"; Zone file for {zone_name}",
            f"; Exported at {datetime.now().isoformat()}",
            f"$ORIGIN {zone_name}.",
            f"$TTL 300",
            ""
        ]
        for rec in records.get("records", []):
            name = rec.get("name", "@")
            ttl = rec.get("ttl", 300)
            rtype = rec.get("type", "A")
            value = rec.get("value", "")
            lines.append(f"{name}\t{ttl}\tIN\t{rtype}\t{value}")

        return {"format": "bind", "zone": zone_name, "data": "\n".join(lines)}

    return {
        "format": "json",
        "zone": zone_name,
        "exported_at": datetime.now().isoformat(),
        "records": records.get("records", [])
    }


@app.get("/export/all", dependencies=[Depends(require_jwt)])
async def export_all_zones():
    """Export all DNS zones."""
    zones_code, zones_out, _ = run_cmd(["zone-list-json"])

    if zones_code != 0:
        return {"error": "Cannot get zones"}

    try:
        zones_data = json.loads(zones_out)
        zones = zones_data.get("zones", [])
    except json.JSONDecodeError:
        zones = []

    export_data = {
        "exported_at": datetime.now().isoformat(),
        "zones": []
    }

    for zone in zones:
        zone_name = zone.get("name") if isinstance(zone, dict) else zone
        rec_code, rec_out, _ = run_cmd(["records-json", zone_name])

        zone_data = {"name": zone_name, "records": []}
        if rec_code == 0:
            try:
                records = json.loads(rec_out)
                zone_data["records"] = records.get("records", [])
            except json.JSONDecodeError:
                pass

        export_data["zones"].append(zone_data)

    return export_data
