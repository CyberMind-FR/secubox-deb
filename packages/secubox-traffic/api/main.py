"""
SecuBox Traffic Shaper API - Production Ready
Advanced QoS traffic control with TC/CAKE

Features:
- Traffic class management
- Classification rules
- Preset configurations
- TC/CAKE integration
- Stats caching with TTL
- Event history tracking
- Webhook notifications
"""

from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime, timedelta
import subprocess
import threading
import hashlib
import hmac
import time
import json
import re
import asyncio

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox Traffic Shaper API", version="2.0.0")

# Configuration
DATA_DIR = Path("/var/lib/secubox/traffic")
CONFIG_FILE = Path("/etc/secubox/traffic-shaper.json")
HISTORY_FILE = DATA_DIR / "history.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"
STATS_FILE = DATA_DIR / "stats_history.json"

# Ensure directories
DATA_DIR.mkdir(parents=True, exist_ok=True)


class StatsCache:
    """Thread-safe stats cache with TTL."""
    def __init__(self, ttl_seconds: int = 15):
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

    def invalidate(self, key: str = None):
        with self._lock:
            if key:
                self._cache.pop(key, None)
                self._timestamps.pop(key, None)
            else:
                self._cache.clear()
                self._timestamps.clear()


# Global cache
stats_cache = StatsCache(ttl_seconds=15)

DEFAULT_CONFIG = {
    "enabled": False,
    "classes": [],
    "rules": []
}

PRESETS = {
    "gaming": {
        "name": "Gaming",
        "description": "Optimized for online gaming with low latency",
        "classes": [
            {"id": "gaming", "name": "Gaming", "priority": 1, "rate": "10mbit", "ceil": "50mbit", "interface": "wan", "enabled": True},
            {"id": "default", "name": "Default", "priority": 5, "rate": "5mbit", "ceil": "30mbit", "interface": "wan", "enabled": True}
        ],
        "rules": [
            {"id": "gaming_rule", "class": "gaming", "match_type": "dport", "match_value": "3074,3478-3479,27015-27030", "enabled": True}
        ]
    },
    "streaming": {
        "name": "Streaming",
        "description": "Prioritize video streaming services",
        "classes": [
            {"id": "streaming", "name": "Streaming", "priority": 2, "rate": "15mbit", "ceil": "80mbit", "interface": "wan", "enabled": True},
            {"id": "default", "name": "Default", "priority": 5, "rate": "5mbit", "ceil": "20mbit", "interface": "wan", "enabled": True}
        ],
        "rules": [
            {"id": "streaming_rule", "class": "streaming", "match_type": "dport", "match_value": "1935,8080,443", "enabled": True}
        ]
    },
    "work_from_home": {
        "name": "Work From Home",
        "description": "Optimize for VPN and video conferencing",
        "classes": [
            {"id": "video_conf", "name": "Video Conference", "priority": 1, "rate": "10mbit", "ceil": "30mbit", "interface": "wan", "enabled": True},
            {"id": "vpn", "name": "VPN", "priority": 2, "rate": "5mbit", "ceil": "50mbit", "interface": "wan", "enabled": True},
            {"id": "default", "name": "Default", "priority": 5, "rate": "3mbit", "ceil": "20mbit", "interface": "wan", "enabled": True}
        ],
        "rules": [
            {"id": "conf_rule", "class": "video_conf", "match_type": "dport", "match_value": "3478-3481,8801-8810", "enabled": True},
            {"id": "vpn_rule", "class": "vpn", "match_type": "dport", "match_value": "1194,1701,500,4500", "enabled": True}
        ]
    },
    "balanced": {
        "name": "Balanced",
        "description": "Fair distribution across all traffic types",
        "classes": [
            {"id": "high", "name": "High Priority", "priority": 2, "rate": "10mbit", "ceil": "50mbit", "interface": "wan", "enabled": True},
            {"id": "normal", "name": "Normal", "priority": 4, "rate": "5mbit", "ceil": "40mbit", "interface": "wan", "enabled": True},
            {"id": "bulk", "name": "Bulk", "priority": 6, "rate": "2mbit", "ceil": "30mbit", "interface": "wan", "enabled": True}
        ],
        "rules": []
    }
}


class TrafficClass(BaseModel):
    id: Optional[str] = None
    name: str
    priority: int = Field(default=5, ge=1, le=10)
    rate: str = "1mbit"
    ceil: str = "10mbit"
    interface: str = "wan"
    enabled: bool = True


class ClassUpdateRequest(BaseModel):
    id: str
    name: Optional[str] = None
    priority: Optional[int] = None
    rate: Optional[str] = None
    ceil: Optional[str] = None
    interface: Optional[str] = None
    enabled: Optional[bool] = None


class ClassDeleteRequest(BaseModel):
    id: str


class TrafficRule(BaseModel):
    id: Optional[str] = None
    class_id: str
    match_type: str  # dport, sport, ip, proto
    match_value: str
    enabled: bool = True


class RuleDeleteRequest(BaseModel):
    id: str


class PresetRequest(BaseModel):
    preset: str


class WebhookConfig(BaseModel):
    url: str
    secret: Optional[str] = None
    events: List[str] = ["all"]
    enabled: bool = True


def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def load_history() -> List[Dict]:
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except:
            pass
    return []


def save_history(history: List[Dict]):
    history = history[-500:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2, default=str))


def add_event(event_type: str, details: Dict = None):
    history = load_history()
    event = {
        "id": hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:12],
        "type": event_type,
        "details": details or {},
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    history.append(event)
    save_history(history)
    asyncio.create_task(trigger_webhooks(event))
    return event


def load_webhooks() -> List[Dict]:
    if WEBHOOKS_FILE.exists():
        try:
            return json.loads(WEBHOOKS_FILE.read_text())
        except:
            pass
    return []


def save_webhooks(webhooks: List[Dict]):
    WEBHOOKS_FILE.write_text(json.dumps(webhooks, indent=2))


async def trigger_webhooks(event: Dict):
    webhooks = load_webhooks()
    for wh in webhooks:
        if not wh.get("enabled", True):
            continue
        events = wh.get("events", ["all"])
        if "all" not in events and event["type"] not in events:
            continue

        try:
            payload = json.dumps(event)
            headers = {"Content-Type": "application/json"}
            if wh.get("secret"):
                sig = hmac.new(wh["secret"].encode(), payload.encode(), hashlib.sha256).hexdigest()
                headers["X-Webhook-Signature"] = f"sha256={sig}"

            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(wh["url"], content=payload, headers=headers)
        except:
            pass


def format_bytes(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(size) < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def get_qdisc_count() -> int:
    success, out, _ = run_cmd(["tc", "qdisc", "show"])
    if not success:
        return 0
    return out.count("cake") + out.count("htb")


def get_shaped_interfaces() -> list:
    success, out, _ = run_cmd(["tc", "qdisc", "show"])
    if not success:
        return []

    interfaces = set()
    for line in out.split('\n'):
        if 'dev' in line:
            match = re.search(r'dev\s+(\S+)', line)
            if match:
                interfaces.add(match.group(1))

    return list(interfaces)


def apply_tc_config(config: dict):
    for iface in get_shaped_interfaces():
        run_cmd(["tc", "qdisc", "del", "dev", iface, "root"])

    interfaces = set()
    for cls in config.get("classes", []):
        if cls.get("enabled", True):
            interfaces.add(cls.get("interface", "wan"))

    for iface in interfaces:
        success, _, _ = run_cmd([
            "tc", "qdisc", "add", "dev", iface, "root",
            "cake", "bandwidth", "100mbit", "diffserv4"
        ])

        if not success:
            run_cmd([
                "tc", "qdisc", "add", "dev", iface, "root",
                "handle", "1:", "htb", "default", "9999"
            ])


def get_tc_stats() -> list:
    stats = []
    success, out, _ = run_cmd(["tc", "-s", "class", "show"])

    if not success:
        return stats

    current_class = None
    current_stats = {}

    for line in out.split('\n'):
        if line.startswith('class'):
            if current_class and current_stats:
                stats.append(current_stats)

            match = re.search(r'class\s+\S+\s+(\S+)', line)
            if match:
                current_class = match.group(1)
                current_stats = {
                    "class": current_class,
                    "packets": 0,
                    "bytes": 0,
                    "drops": 0
                }

        elif 'Sent' in line and current_stats:
            match = re.search(r'Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt', line)
            if match:
                current_stats["bytes"] = int(match.group(1))
                current_stats["bytes_human"] = format_bytes(int(match.group(1)))
                current_stats["packets"] = int(match.group(2))

        elif 'dropped' in line and current_stats:
            match = re.search(r'dropped\s+(\d+)', line)
            if match:
                current_stats["drops"] = int(match.group(1))

    if current_class and current_stats:
        stats.append(current_stats)

    return stats


# ============================================================================
# Public Endpoints
# ============================================================================

@app.get("/status")
async def get_status():
    """Get traffic shaper status."""
    cached = stats_cache.get("status")
    if cached:
        return {**cached, "cached": True}

    config = load_config()
    qdisc_count = get_qdisc_count()

    status = {
        "active": qdisc_count > 0,
        "qdisc_count": qdisc_count,
        "class_count": len(config.get("classes", [])),
        "rule_count": len(config.get("rules", [])),
        "interfaces": get_shaped_interfaces()
    }

    stats_cache.set("status", status)
    return status


@app.get("/health")
async def health():
    return {"status": "healthy", "module": "traffic"}


@app.get("/summary")
async def get_summary():
    """Get comprehensive traffic shaper summary."""
    config = load_config()
    qdisc_count = get_qdisc_count()
    tc_stats = get_tc_stats()
    history = load_history()

    # Calculate totals
    total_bytes = sum(s.get("bytes", 0) for s in tc_stats)
    total_packets = sum(s.get("packets", 0) for s in tc_stats)
    total_drops = sum(s.get("drops", 0) for s in tc_stats)

    # Active classes
    enabled_classes = sum(1 for c in config.get("classes", []) if c.get("enabled", True))
    enabled_rules = sum(1 for r in config.get("rules", []) if r.get("enabled", True))

    # Recent events
    cutoff = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    recent_events = [e for e in history if e.get("timestamp", "") > cutoff]

    return {
        "active": qdisc_count > 0,
        "classes": {
            "total": len(config.get("classes", [])),
            "enabled": enabled_classes
        },
        "rules": {
            "total": len(config.get("rules", [])),
            "enabled": enabled_rules
        },
        "traffic": {
            "total_bytes": total_bytes,
            "total_bytes_human": format_bytes(total_bytes),
            "total_packets": total_packets,
            "total_drops": total_drops
        },
        "interfaces": get_shaped_interfaces(),
        "qdisc_count": qdisc_count,
        "events_24h": len(recent_events),
        "webhooks_configured": len(load_webhooks()),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


@app.get("/classes")
async def list_classes():
    config = load_config()
    return {"classes": config.get("classes", []), "total": len(config.get("classes", []))}


@app.get("/rules")
async def list_rules():
    config = load_config()
    return {"rules": config.get("rules", []), "total": len(config.get("rules", []))}


@app.get("/stats")
async def get_stats():
    stats = get_tc_stats()
    return {"stats": stats, "total": len(stats)}


@app.get("/presets")
async def list_presets():
    return {
        "presets": [
            {"id": k, "name": v["name"], "description": v["description"]}
            for k, v in PRESETS.items()
        ]
    }


@app.get("/history")
async def get_history(limit: int = Query(50, ge=1, le=500)):
    history = load_history()
    history = sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"events": history[:limit], "total": len(history)}


# ============================================================================
# Protected Endpoints
# ============================================================================

@app.post("/class/add", dependencies=[Depends(require_jwt)])
async def add_class(cls: TrafficClass):
    config = load_config()

    if "classes" not in config:
        config["classes"] = []

    if not cls.id:
        cls.id = f"class_{int(time.time())}"

    for existing in config["classes"]:
        if existing["id"] == cls.id:
            raise HTTPException(status_code=400, detail="Class ID already exists")

    config["classes"].append(cls.dict())
    save_config(config)
    apply_tc_config(config)
    stats_cache.invalidate()

    add_event("class_added", {"id": cls.id, "name": cls.name})
    return {"success": True, "message": "Class added successfully", "id": cls.id}


@app.post("/class/update", dependencies=[Depends(require_jwt)])
async def update_class(req: ClassUpdateRequest):
    config = load_config()

    found = False
    for cls in config.get("classes", []):
        if cls["id"] == req.id:
            if req.name is not None:
                cls["name"] = req.name
            if req.priority is not None:
                cls["priority"] = req.priority
            if req.rate is not None:
                cls["rate"] = req.rate
            if req.ceil is not None:
                cls["ceil"] = req.ceil
            if req.interface is not None:
                cls["interface"] = req.interface
            if req.enabled is not None:
                cls["enabled"] = req.enabled
            found = True
            break

    if not found:
        raise HTTPException(status_code=404, detail="Class not found")

    save_config(config)
    apply_tc_config(config)
    stats_cache.invalidate()

    add_event("class_updated", {"id": req.id})
    return {"success": True, "message": "Class updated successfully"}


@app.post("/class/delete", dependencies=[Depends(require_jwt)])
async def delete_class(req: ClassDeleteRequest):
    config = load_config()

    original_count = len(config.get("classes", []))
    config["classes"] = [c for c in config.get("classes", []) if c["id"] != req.id]

    if len(config["classes"]) == original_count:
        raise HTTPException(status_code=404, detail="Class not found")

    save_config(config)
    apply_tc_config(config)
    stats_cache.invalidate()

    add_event("class_deleted", {"id": req.id})
    return {"success": True, "message": "Class deleted successfully"}


@app.post("/rule/add", dependencies=[Depends(require_jwt)])
async def add_rule(rule: TrafficRule):
    config = load_config()

    if "rules" not in config:
        config["rules"] = []

    if not rule.id:
        rule.id = f"rule_{int(time.time())}"

    config["rules"].append({
        "id": rule.id,
        "class": rule.class_id,
        "match_type": rule.match_type,
        "match_value": rule.match_value,
        "enabled": rule.enabled
    })

    save_config(config)
    apply_tc_config(config)
    stats_cache.invalidate()

    add_event("rule_added", {"id": rule.id})
    return {"success": True, "message": "Rule added successfully", "id": rule.id}


@app.post("/rule/delete", dependencies=[Depends(require_jwt)])
async def delete_rule(req: RuleDeleteRequest):
    config = load_config()

    original_count = len(config.get("rules", []))
    config["rules"] = [r for r in config.get("rules", []) if r["id"] != req.id]

    if len(config["rules"]) == original_count:
        raise HTTPException(status_code=404, detail="Rule not found")

    save_config(config)
    apply_tc_config(config)
    stats_cache.invalidate()

    add_event("rule_deleted", {"id": req.id})
    return {"success": True, "message": "Rule deleted successfully"}


@app.post("/preset/apply", dependencies=[Depends(require_jwt)])
async def apply_preset(req: PresetRequest):
    if req.preset not in PRESETS:
        raise HTTPException(status_code=400, detail=f"Unknown preset: {req.preset}")

    preset = PRESETS[req.preset]

    config = {
        "enabled": True,
        "classes": preset["classes"],
        "rules": preset["rules"]
    }

    save_config(config)
    apply_tc_config(config)
    stats_cache.invalidate()

    add_event("preset_applied", {"preset": req.preset})
    return {"success": True, "message": f"Preset '{req.preset}' applied successfully"}


@app.post("/apply", dependencies=[Depends(require_jwt)])
async def apply_config():
    config = load_config()
    apply_tc_config(config)
    stats_cache.invalidate()

    add_event("config_applied", {})
    return {"success": True, "message": "Configuration applied"}


@app.post("/clear", dependencies=[Depends(require_jwt)])
async def clear_shaping():
    for iface in get_shaped_interfaces():
        run_cmd(["tc", "qdisc", "del", "dev", iface, "root"])
    stats_cache.invalidate()

    add_event("shaping_cleared", {})
    return {"success": True, "message": "Traffic shaping cleared"}


@app.get("/webhooks", dependencies=[Depends(require_jwt)])
async def list_webhooks():
    return {"webhooks": load_webhooks()}


@app.post("/webhooks", dependencies=[Depends(require_jwt)])
async def add_webhook(webhook: WebhookConfig):
    webhooks = load_webhooks()
    wh = {
        "id": hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:12],
        "url": webhook.url,
        "secret": webhook.secret,
        "events": webhook.events,
        "enabled": webhook.enabled,
        "created_at": datetime.utcnow().isoformat() + "Z"
    }
    webhooks.append(wh)
    save_webhooks(webhooks)
    return {"success": True, "webhook": wh}


@app.delete("/webhooks/{webhook_id}", dependencies=[Depends(require_jwt)])
async def delete_webhook(webhook_id: str):
    webhooks = load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    save_webhooks(webhooks)
    return {"success": True}


@app.get("/info")
async def get_info():
    return {
        "module": "secubox-traffic",
        "version": "2.0.0",
        "description": "Advanced QoS traffic control with TC/CAKE"
    }
