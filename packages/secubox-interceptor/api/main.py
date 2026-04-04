"""
SecuBox Interceptor API
Traffic interception and analysis module for HTTP/HTTPS inspection
"""

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime
import subprocess
import asyncio
import json
import uuid
import os

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/secubox/core')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "dev"}

app = FastAPI(title="SecuBox Interceptor API", version="1.0.0")

# Configuration
CONFIG_FILE = Path("/etc/secubox/interceptor.json")
DATA_DIR = Path("/var/lib/secubox/interceptor")
RECORDINGS_DIR = DATA_DIR / "recordings"
FLOWS_DIR = DATA_DIR / "flows"
RULES_FILE = DATA_DIR / "rules.json"
SESSIONS_FILE = Path("/tmp/secubox/interceptor-sessions.json")
STATS_CACHE = Path("/tmp/secubox/interceptor-stats.json")
LOGS_DIR = Path("/var/log/secubox")

DEFAULT_CONFIG = {
    "enabled": False,
    "listen_port": 8889,
    "ssl_inspection": True,
    "ca_cert": "/etc/secubox/interceptor/ca.crt",
    "ca_key": "/etc/secubox/interceptor/ca.key",
    "upstream_proxy": None,
    "recording_enabled": False,
    "max_flow_size": "10M",
    "session_timeout": 3600,
    "waf_integration": True,
    "content_filters": {
        "block_malware": True,
        "block_scripts": False,
        "block_trackers": False
    },
    "allowed_domains": [],
    "blocked_domains": []
}

DEFAULT_RULES = {
    "rules": [],
    "enabled": True
}


# Models
class ConfigRequest(BaseModel):
    enabled: Optional[bool] = None
    listen_port: Optional[int] = None
    ssl_inspection: Optional[bool] = None
    upstream_proxy: Optional[str] = None
    recording_enabled: Optional[bool] = None
    max_flow_size: Optional[str] = None
    session_timeout: Optional[int] = None
    waf_integration: Optional[bool] = None
    block_malware: Optional[bool] = None
    block_scripts: Optional[bool] = None
    block_trackers: Optional[bool] = None
    allowed_domains: Optional[List[str]] = None
    blocked_domains: Optional[List[str]] = None


class RuleRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    enabled: bool = True
    match_type: str = "all"  # all, request, response
    conditions: List[Dict[str, Any]] = []
    actions: List[Dict[str, Any]] = []


class ReplayRequest(BaseModel):
    modify_headers: Optional[Dict[str, str]] = None
    modify_body: Optional[str] = None


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
    """Load interceptor configuration"""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save interceptor configuration"""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def load_rules() -> dict:
    """Load interception rules"""
    if RULES_FILE.exists():
        try:
            return json.loads(RULES_FILE.read_text())
        except:
            pass
    return DEFAULT_RULES.copy()


def save_rules(rules: dict):
    """Save interception rules"""
    RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    RULES_FILE.write_text(json.dumps(rules, indent=2))


def load_sessions() -> List[dict]:
    """Load active sessions"""
    if SESSIONS_FILE.exists():
        try:
            return json.loads(SESSIONS_FILE.read_text())
        except:
            pass
    return []


def save_sessions(sessions: List[dict]):
    """Save sessions"""
    SESSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SESSIONS_FILE.write_text(json.dumps(sessions, indent=2))


def load_flows(limit: int = 100) -> List[dict]:
    """Load intercepted flows from directory"""
    flows = []
    if not FLOWS_DIR.exists():
        return flows

    flow_files = sorted(FLOWS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
    for f in flow_files[:limit]:
        try:
            flow = json.loads(f.read_text())
            flow["id"] = f.stem
            flows.append(flow)
        except:
            pass
    return flows


def get_flow(flow_id: str) -> Optional[dict]:
    """Get a specific flow by ID"""
    flow_file = FLOWS_DIR / f"{flow_id}.json"
    if flow_file.exists():
        try:
            flow = json.loads(flow_file.read_text())
            flow["id"] = flow_id
            return flow
        except:
            pass
    return None


def service_running() -> bool:
    """Check if interceptor service is running"""
    success, out, _ = run_cmd(["systemctl", "is-active", "secubox-interceptor"])
    return success and "active" in out


def get_stats() -> dict:
    """Get interceptor statistics"""
    if STATS_CACHE.exists():
        try:
            return json.loads(STATS_CACHE.read_text())
        except:
            pass

    # Calculate from flows
    flows = load_flows(1000)
    total_flows = len(flows)
    blocked = sum(1 for f in flows if f.get("blocked"))
    modified = sum(1 for f in flows if f.get("modified"))

    return {
        "total_flows": total_flows,
        "blocked_flows": blocked,
        "modified_flows": modified,
        "active_sessions": len(load_sessions()),
        "bytes_inspected": sum(f.get("size", 0) for f in flows),
        "timestamp": datetime.now().isoformat()
    }


# Public endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok", "module": "interceptor", "timestamp": datetime.now().isoformat()}


@app.get("/status")
async def get_status():
    """Get interceptor status"""
    config = load_config()
    running = service_running()
    stats = get_stats()

    return {
        "enabled": config.get("enabled", False),
        "running": running,
        "listen_port": config.get("listen_port", 8889),
        "ssl_inspection": config.get("ssl_inspection", True),
        "recording_enabled": config.get("recording_enabled", False),
        "waf_integration": config.get("waf_integration", True),
        "total_flows": stats.get("total_flows", 0),
        "blocked_flows": stats.get("blocked_flows", 0),
        "modified_flows": stats.get("modified_flows", 0),
        "active_sessions": stats.get("active_sessions", 0),
        "bytes_inspected": stats.get("bytes_inspected", 0),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/config")
async def get_config():
    """Get interceptor configuration"""
    return load_config()


@app.post("/config")
async def update_config(req: ConfigRequest, user: dict = Depends(require_jwt)):
    """Update interceptor configuration"""
    config = load_config()

    if req.enabled is not None:
        config["enabled"] = req.enabled
    if req.listen_port is not None:
        config["listen_port"] = req.listen_port
    if req.ssl_inspection is not None:
        config["ssl_inspection"] = req.ssl_inspection
    if req.upstream_proxy is not None:
        config["upstream_proxy"] = req.upstream_proxy
    if req.recording_enabled is not None:
        config["recording_enabled"] = req.recording_enabled
    if req.max_flow_size is not None:
        config["max_flow_size"] = req.max_flow_size
    if req.session_timeout is not None:
        config["session_timeout"] = req.session_timeout
    if req.waf_integration is not None:
        config["waf_integration"] = req.waf_integration

    # Content filters
    if "content_filters" not in config:
        config["content_filters"] = {}
    if req.block_malware is not None:
        config["content_filters"]["block_malware"] = req.block_malware
    if req.block_scripts is not None:
        config["content_filters"]["block_scripts"] = req.block_scripts
    if req.block_trackers is not None:
        config["content_filters"]["block_trackers"] = req.block_trackers

    # Domain lists
    if req.allowed_domains is not None:
        config["allowed_domains"] = req.allowed_domains
    if req.blocked_domains is not None:
        config["blocked_domains"] = req.blocked_domains

    save_config(config)
    return {"success": True, "message": "Configuration saved"}


@app.get("/sessions")
async def get_sessions():
    """Get active sessions"""
    sessions = load_sessions()
    return {
        "success": True,
        "count": len(sessions),
        "sessions": sessions,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/session/{session_id}")
async def get_session_detail(session_id: str):
    """Get session details"""
    sessions = load_sessions()
    for s in sessions:
        if s.get("id") == session_id:
            return {"success": True, "session": s}
    raise HTTPException(status_code=404, detail="Session not found")


@app.post("/session/{session_id}/close")
async def close_session(session_id: str, user: dict = Depends(require_jwt)):
    """Close an active session"""
    sessions = load_sessions()
    new_sessions = [s for s in sessions if s.get("id") != session_id]

    if len(new_sessions) == len(sessions):
        raise HTTPException(status_code=404, detail="Session not found")

    save_sessions(new_sessions)
    return {"success": True, "message": f"Session {session_id} closed"}


@app.get("/flows")
async def get_flows(limit: int = 100, offset: int = 0, filter_host: Optional[str] = None):
    """Get intercepted flows"""
    flows = load_flows(limit + offset)

    if filter_host:
        flows = [f for f in flows if filter_host.lower() in f.get("host", "").lower()]

    return {
        "success": True,
        "count": len(flows),
        "flows": flows[offset:offset+limit],
        "timestamp": datetime.now().isoformat()
    }


@app.get("/flow/{flow_id}")
async def get_flow_detail(flow_id: str):
    """Get flow details"""
    flow = get_flow(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return {"success": True, "flow": flow}


@app.post("/flow/{flow_id}/replay")
async def replay_flow(flow_id: str, req: Optional[ReplayRequest] = None, user: dict = Depends(require_jwt)):
    """Replay a flow"""
    flow = get_flow(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")

    # Create replay entry
    replay_id = str(uuid.uuid4())[:8]
    replay_data = {
        "id": replay_id,
        "original_flow_id": flow_id,
        "timestamp": datetime.now().isoformat(),
        "status": "queued",
        "modifications": {
            "headers": req.modify_headers if req else None,
            "body": req.modify_body if req else None
        }
    }

    # Save replay request
    replay_file = DATA_DIR / "replays" / f"{replay_id}.json"
    replay_file.parent.mkdir(parents=True, exist_ok=True)
    replay_file.write_text(json.dumps(replay_data, indent=2))

    return {
        "success": True,
        "replay_id": replay_id,
        "message": "Replay queued"
    }


@app.get("/rules")
async def get_rules():
    """Get interception rules"""
    rules = load_rules()
    return {
        "success": True,
        "enabled": rules.get("enabled", True),
        "count": len(rules.get("rules", [])),
        "rules": rules.get("rules", [])
    }


@app.post("/rule")
async def create_rule(req: RuleRequest, user: dict = Depends(require_jwt)):
    """Create a new interception rule"""
    rules = load_rules()

    rule_id = str(uuid.uuid4())[:8]
    new_rule = {
        "id": rule_id,
        "name": req.name,
        "description": req.description,
        "enabled": req.enabled,
        "match_type": req.match_type,
        "conditions": req.conditions,
        "actions": req.actions,
        "created": datetime.now().isoformat()
    }

    rules["rules"].append(new_rule)
    save_rules(rules)

    return {"success": True, "rule_id": rule_id, "message": "Rule created"}


@app.delete("/rule/{rule_id}")
async def delete_rule(rule_id: str, user: dict = Depends(require_jwt)):
    """Delete an interception rule"""
    rules = load_rules()
    original_count = len(rules.get("rules", []))
    rules["rules"] = [r for r in rules.get("rules", []) if r.get("id") != rule_id]

    if len(rules["rules"]) == original_count:
        raise HTTPException(status_code=404, detail="Rule not found")

    save_rules(rules)
    return {"success": True, "message": "Rule deleted"}


@app.put("/rule/{rule_id}")
async def update_rule(rule_id: str, req: RuleRequest, user: dict = Depends(require_jwt)):
    """Update an interception rule"""
    rules = load_rules()

    for i, rule in enumerate(rules.get("rules", [])):
        if rule.get("id") == rule_id:
            rules["rules"][i] = {
                "id": rule_id,
                "name": req.name,
                "description": req.description,
                "enabled": req.enabled,
                "match_type": req.match_type,
                "conditions": req.conditions,
                "actions": req.actions,
                "created": rule.get("created"),
                "updated": datetime.now().isoformat()
            }
            save_rules(rules)
            return {"success": True, "message": "Rule updated"}

    raise HTTPException(status_code=404, detail="Rule not found")


@app.get("/recordings")
async def get_recordings():
    """Get recorded sessions"""
    recordings = []
    if RECORDINGS_DIR.exists():
        for f in sorted(RECORDINGS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:50]:
            try:
                rec = json.loads(f.read_text())
                rec["id"] = f.stem
                recordings.append(rec)
            except:
                pass

    return {
        "success": True,
        "count": len(recordings),
        "recordings": recordings
    }


@app.post("/record/start")
async def start_recording(user: dict = Depends(require_jwt)):
    """Start traffic recording"""
    config = load_config()
    config["recording_enabled"] = True
    save_config(config)

    # Signal the interceptor to start recording
    run_cmd(["systemctl", "kill", "-s", "USR1", "secubox-interceptor"])

    return {"success": True, "message": "Recording started"}


@app.post("/record/stop")
async def stop_recording(user: dict = Depends(require_jwt)):
    """Stop traffic recording"""
    config = load_config()
    config["recording_enabled"] = False
    save_config(config)

    # Signal the interceptor to stop recording
    run_cmd(["systemctl", "kill", "-s", "USR2", "secubox-interceptor"])

    return {"success": True, "message": "Recording stopped"}


@app.get("/stats")
async def get_traffic_stats():
    """Get traffic statistics"""
    stats = get_stats()
    flows = load_flows(1000)

    # Calculate additional stats
    by_host = {}
    by_method = {}
    by_status = {}
    by_content_type = {}

    for flow in flows:
        host = flow.get("host", "unknown")
        method = flow.get("method", "GET")
        status = str(flow.get("status_code", 0))
        content_type = flow.get("content_type", "unknown")

        by_host[host] = by_host.get(host, 0) + 1
        by_method[method] = by_method.get(method, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
        by_content_type[content_type] = by_content_type.get(content_type, 0) + 1

    # Top 10 hosts
    top_hosts = sorted(by_host.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "success": True,
        "total_flows": stats.get("total_flows", 0),
        "blocked_flows": stats.get("blocked_flows", 0),
        "modified_flows": stats.get("modified_flows", 0),
        "active_sessions": stats.get("active_sessions", 0),
        "bytes_inspected": stats.get("bytes_inspected", 0),
        "by_method": by_method,
        "by_status": by_status,
        "by_content_type": dict(list(by_content_type.items())[:10]),
        "top_hosts": dict(top_hosts),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/logs")
async def get_logs(limit: int = 100, level: Optional[str] = None):
    """Get interceptor logs"""
    log_file = LOGS_DIR / "interceptor.log"
    logs = []

    if log_file.exists():
        try:
            lines = log_file.read_text().strip().split("\n")
            for line in lines[-limit:]:
                if level and level.upper() not in line.upper():
                    continue
                logs.append(line)
        except:
            pass

    return {
        "success": True,
        "count": len(logs),
        "logs": logs,
        "timestamp": datetime.now().isoformat()
    }


# Service control endpoints
@app.post("/start")
async def start_service(user: dict = Depends(require_jwt)):
    """Start interceptor service"""
    config = load_config()
    config["enabled"] = True
    save_config(config)

    run_cmd(["systemctl", "start", "secubox-interceptor"])
    return {"success": True, "message": "Interceptor started"}


@app.post("/stop")
async def stop_service(user: dict = Depends(require_jwt)):
    """Stop interceptor service"""
    run_cmd(["systemctl", "stop", "secubox-interceptor"])
    return {"success": True, "message": "Interceptor stopped"}


@app.post("/restart")
async def restart_service(user: dict = Depends(require_jwt)):
    """Restart interceptor service"""
    run_cmd(["systemctl", "restart", "secubox-interceptor"])
    return {"success": True, "message": "Interceptor restarted"}


@app.get("/info")
async def get_info():
    """Get module info"""
    return {
        "module": "secubox-interceptor",
        "version": "1.0.0",
        "description": "Traffic interception and analysis module"
    }
