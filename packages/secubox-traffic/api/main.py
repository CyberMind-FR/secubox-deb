"""
SecuBox Traffic Shaper API
Advanced QoS traffic control with TC/CAKE
"""

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from pathlib import Path
import subprocess
import os
import json
import re

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/secubox/core')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "dev"}

app = FastAPI(title="SecuBox Traffic Shaper API", version="1.0.0")

# Configuration
CONFIG_FILE = Path("/etc/secubox/traffic-shaper.json")

DEFAULT_CONFIG = {
    "enabled": False,
    "classes": [],
    "rules": []
}

# Presets
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
    }
}


# Models
class TrafficClass(BaseModel):
    id: Optional[str] = None
    name: str
    priority: int = 5
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


# Helpers
def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def load_config() -> dict:
    """Load traffic shaper configuration"""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save traffic shaper configuration"""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def get_qdisc_count() -> int:
    """Count active qdiscs"""
    success, out, _ = run_cmd(["tc", "qdisc", "show"])
    if not success:
        return 0
    return out.count("cake") + out.count("htb")


def get_shaped_interfaces() -> list:
    """Get interfaces with shaping"""
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
    """Apply TC configuration"""
    # Clear existing qdiscs
    for iface in get_shaped_interfaces():
        run_cmd(["tc", "qdisc", "del", "dev", iface, "root"])

    # Get interfaces from classes
    interfaces = set()
    for cls in config.get("classes", []):
        if cls.get("enabled", True):
            interfaces.add(cls.get("interface", "wan"))

    # Setup CAKE qdisc on each interface
    for iface in interfaces:
        # Try CAKE first, fallback to HTB
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
    """Get TC class statistics"""
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
                current_stats["packets"] = int(match.group(2))

        elif 'dropped' in line and current_stats:
            match = re.search(r'dropped\s+(\d+)', line)
            if match:
                current_stats["drops"] = int(match.group(1))

    if current_class and current_stats:
        stats.append(current_stats)

    return stats


# Public endpoints
@app.get("/status")
async def get_status():
    """Get traffic shaper status"""
    config = load_config()
    qdisc_count = get_qdisc_count()

    return {
        "active": qdisc_count > 0,
        "qdisc_count": qdisc_count,
        "class_count": len(config.get("classes", [])),
        "rule_count": len(config.get("rules", [])),
        "interfaces": get_shaped_interfaces()
    }


@app.get("/classes")
async def list_classes():
    """List traffic classes"""
    config = load_config()
    return {"classes": config.get("classes", [])}


@app.get("/rules")
async def list_rules():
    """List classification rules"""
    config = load_config()
    return {"rules": config.get("rules", [])}


@app.get("/stats")
async def get_stats():
    """Get traffic statistics per class"""
    return {"stats": get_tc_stats()}


@app.get("/presets")
async def list_presets():
    """List available presets"""
    return {
        "presets": [
            {"id": k, "name": v["name"], "description": v["description"]}
            for k, v in PRESETS.items()
        ]
    }


# Protected endpoints
@app.post("/class/add")
async def add_class(cls: TrafficClass, user: dict = Depends(require_jwt)):
    """Add traffic class"""
    config = load_config()

    if "classes" not in config:
        config["classes"] = []

    # Generate ID if not provided
    if not cls.id:
        import time
        cls.id = f"class_{int(time.time())}"

    # Check for duplicate
    for existing in config["classes"]:
        if existing["id"] == cls.id:
            raise HTTPException(status_code=400, detail="Class ID already exists")

    config["classes"].append(cls.dict())
    save_config(config)
    apply_tc_config(config)

    return {"success": True, "message": "Class added successfully", "id": cls.id}


@app.post("/class/update")
async def update_class(req: ClassUpdateRequest, user: dict = Depends(require_jwt)):
    """Update traffic class"""
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

    return {"success": True, "message": "Class updated successfully"}


@app.post("/class/delete")
async def delete_class(req: ClassDeleteRequest, user: dict = Depends(require_jwt)):
    """Delete traffic class"""
    config = load_config()

    original_count = len(config.get("classes", []))
    config["classes"] = [c for c in config.get("classes", []) if c["id"] != req.id]

    if len(config["classes"]) == original_count:
        raise HTTPException(status_code=404, detail="Class not found")

    save_config(config)
    apply_tc_config(config)

    return {"success": True, "message": "Class deleted successfully"}


@app.post("/rule/add")
async def add_rule(rule: TrafficRule, user: dict = Depends(require_jwt)):
    """Add classification rule"""
    config = load_config()

    if "rules" not in config:
        config["rules"] = []

    # Generate ID if not provided
    if not rule.id:
        import time
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

    return {"success": True, "message": "Rule added successfully", "id": rule.id}


@app.post("/rule/delete")
async def delete_rule(req: RuleDeleteRequest, user: dict = Depends(require_jwt)):
    """Delete classification rule"""
    config = load_config()

    original_count = len(config.get("rules", []))
    config["rules"] = [r for r in config.get("rules", []) if r["id"] != req.id]

    if len(config["rules"]) == original_count:
        raise HTTPException(status_code=404, detail="Rule not found")

    save_config(config)
    apply_tc_config(config)

    return {"success": True, "message": "Rule deleted successfully"}


@app.post("/preset/apply")
async def apply_preset(req: PresetRequest, user: dict = Depends(require_jwt)):
    """Apply a preset configuration"""
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

    return {"success": True, "message": f"Preset '{req.preset}' applied successfully"}


@app.post("/apply")
async def apply_config(user: dict = Depends(require_jwt)):
    """Apply current configuration"""
    config = load_config()
    apply_tc_config(config)
    return {"success": True, "message": "Configuration applied"}


@app.post("/clear")
async def clear_shaping(user: dict = Depends(require_jwt)):
    """Clear all traffic shaping"""
    for iface in get_shaped_interfaces():
        run_cmd(["tc", "qdisc", "del", "dev", iface, "root"])

    return {"success": True, "message": "Traffic shaping cleared"}


@app.get("/info")
async def get_info():
    """Get module info"""
    return {
        "module": "secubox-traffic",
        "version": "1.0.0",
        "description": "Advanced QoS traffic control with TC/CAKE"
    }
