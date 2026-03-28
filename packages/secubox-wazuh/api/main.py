"""SecuBox Wazuh API - SIEM integration."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import json
import os
import requests
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI(title="SecuBox Wazuh API", version="1.0.0")

WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://127.0.0.1:55000")
WAZUH_USER = os.environ.get("WAZUH_USER", "wazuh")
WAZUH_PASS = os.environ.get("WAZUH_PASS", "wazuh")
OSSEC_CONF = "/var/ossec/etc/ossec.conf"
ALERTS_LOG = "/var/ossec/logs/alerts/alerts.json"


class AgentRegister(BaseModel):
    name: str
    ip: str = "any"
    groups: list = []


class ManagerConfig(BaseModel):
    manager_ip: str
    agent_name: str = ""
    groups: list = []


def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def is_wazuh_manager_running() -> bool:
    """Check if Wazuh manager is running."""
    _, _, code = run_cmd(["systemctl", "is-active", "--quiet", "wazuh-manager"])
    return code == 0


def is_wazuh_agent_running() -> bool:
    """Check if Wazuh agent is running."""
    _, _, code = run_cmd(["systemctl", "is-active", "--quiet", "wazuh-agent"])
    return code == 0


def get_wazuh_version() -> str:
    """Get Wazuh version."""
    stdout, _, code = run_cmd(["/var/ossec/bin/wazuh-control", "info", "-v"])
    if code == 0:
        return stdout.strip()
    return "unknown"


def get_agent_status() -> dict:
    """Get local agent status."""
    stdout, _, code = run_cmd(["/var/ossec/bin/wazuh-control", "status"])

    services = {}
    if code == 0:
        for line in stdout.strip().split('\n'):
            if ' is ' in line:
                parts = line.split(' is ')
                if len(parts) == 2:
                    services[parts[0].strip()] = parts[1].strip()

    return services


def get_agent_info() -> dict:
    """Get agent info from client.keys."""
    info = {}
    keys_file = "/var/ossec/etc/client.keys"

    if os.path.exists(keys_file):
        try:
            with open(keys_file, 'r') as f:
                line = f.readline().strip()
                if line:
                    parts = line.split()
                    if len(parts) >= 3:
                        info["id"] = parts[0]
                        info["name"] = parts[1]
                        info["ip"] = parts[2]
        except Exception:
            pass

    return info


def get_recent_alerts(count: int = 50) -> list:
    """Get recent alerts from alerts.json."""
    alerts = []

    if not os.path.exists(ALERTS_LOG):
        return alerts

    try:
        # Read last N lines
        with open(ALERTS_LOG, 'r') as f:
            lines = f.readlines()

        for line in lines[-count:]:
            try:
                alert = json.loads(line.strip())
                alerts.append(alert)
            except json.JSONDecodeError:
                continue
    except Exception:
        pass

    return alerts


def get_alert_stats() -> dict:
    """Get alert statistics."""
    alerts = get_recent_alerts(1000)

    stats = {
        "total": len(alerts),
        "by_level": {},
        "by_rule": {},
        "last_24h": 0
    }

    now = datetime.utcnow()
    day_ago = now - timedelta(hours=24)

    for alert in alerts:
        # By level
        level = alert.get("rule", {}).get("level", 0)
        stats["by_level"][level] = stats["by_level"].get(level, 0) + 1

        # By rule
        rule_id = alert.get("rule", {}).get("id", "unknown")
        if rule_id not in stats["by_rule"]:
            stats["by_rule"][rule_id] = {
                "count": 0,
                "description": alert.get("rule", {}).get("description", "")
            }
        stats["by_rule"][rule_id]["count"] += 1

        # Last 24h
        timestamp = alert.get("timestamp", "")
        if timestamp:
            try:
                alert_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                if alert_time.replace(tzinfo=None) > day_ago:
                    stats["last_24h"] += 1
            except Exception:
                pass

    # Sort by_rule by count
    sorted_rules = sorted(stats["by_rule"].items(), key=lambda x: x[1]["count"], reverse=True)
    stats["top_rules"] = [{"id": k, **v} for k, v in sorted_rules[:10]]

    return stats


@app.get("/health")
def health():
    return {"status": "ok", "service": "wazuh"}


@app.get("/status")
def get_status():
    """Get Wazuh status."""
    manager_running = is_wazuh_manager_running()
    agent_running = is_wazuh_agent_running()

    # Determine mode
    mode = "none"
    if manager_running:
        mode = "manager"
    elif agent_running:
        mode = "agent"

    agent_info = get_agent_info()
    services = get_agent_status()

    return {
        "mode": mode,
        "version": get_wazuh_version(),
        "manager_running": manager_running,
        "agent_running": agent_running,
        "agent": agent_info,
        "services": services
    }


@app.get("/alerts")
def list_alerts(count: int = 50, level: int = None):
    """Get recent alerts."""
    alerts = get_recent_alerts(count)

    if level is not None:
        alerts = [a for a in alerts if a.get("rule", {}).get("level", 0) >= level]

    return {"alerts": alerts, "count": len(alerts)}


@app.get("/alerts/stats")
def get_alerts_stats():
    """Get alert statistics."""
    return get_alert_stats()


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    """Get specific alert by ID."""
    alerts = get_recent_alerts(1000)

    for alert in alerts:
        if alert.get("id") == alert_id:
            return alert

    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/agent/start")
def start_agent():
    """Start Wazuh agent."""
    stdout, stderr, code = run_cmd(["systemctl", "start", "wazuh-agent"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to start: {stderr}")
    return {"status": "started"}


@app.post("/agent/stop")
def stop_agent():
    """Stop Wazuh agent."""
    stdout, stderr, code = run_cmd(["systemctl", "stop", "wazuh-agent"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to stop: {stderr}")
    return {"status": "stopped"}


@app.post("/agent/restart")
def restart_agent():
    """Restart Wazuh agent."""
    stdout, stderr, code = run_cmd(["systemctl", "restart", "wazuh-agent"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to restart: {stderr}")
    return {"status": "restarted"}


@app.post("/agent/register")
def register_agent(config: ManagerConfig):
    """Register agent with Wazuh manager."""
    # Import agent key using agent-auth
    cmd = [
        "/var/ossec/bin/agent-auth",
        "-m", config.manager_ip
    ]

    if config.agent_name:
        cmd.extend(["-A", config.agent_name])

    if config.groups:
        cmd.extend(["-G", ",".join(config.groups)])

    stdout, stderr, code = run_cmd(cmd, timeout=60)

    if code != 0:
        raise HTTPException(status_code=500, detail=f"Registration failed: {stderr}")

    # Update manager IP in ossec.conf
    if os.path.exists(OSSEC_CONF):
        try:
            with open(OSSEC_CONF, 'r') as f:
                content = f.read()

            # Simple replacement - in production use XML parser
            import re
            content = re.sub(
                r'<address>.*?</address>',
                f'<address>{config.manager_ip}</address>',
                content
            )

            with open(OSSEC_CONF, 'w') as f:
                f.write(content)
        except Exception as e:
            pass

    return {"status": "registered", "manager": config.manager_ip}


@app.post("/manager/start")
def start_manager():
    """Start Wazuh manager."""
    stdout, stderr, code = run_cmd(["systemctl", "start", "wazuh-manager"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to start: {stderr}")
    return {"status": "started"}


@app.post("/manager/stop")
def stop_manager():
    """Stop Wazuh manager."""
    stdout, stderr, code = run_cmd(["systemctl", "stop", "wazuh-manager"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to stop: {stderr}")
    return {"status": "stopped"}


@app.post("/manager/restart")
def restart_manager():
    """Restart Wazuh manager."""
    stdout, stderr, code = run_cmd(["systemctl", "restart", "wazuh-manager"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to restart: {stderr}")
    return {"status": "restarted"}


@app.get("/agents")
def list_agents():
    """List connected agents (manager mode only)."""
    if not is_wazuh_manager_running():
        raise HTTPException(status_code=503, detail="Manager not running")

    stdout, stderr, code = run_cmd(["/var/ossec/bin/agent_control", "-l"])

    agents = []
    if code == 0:
        for line in stdout.strip().split('\n'):
            if 'ID:' in line:
                # Parse agent line
                parts = line.split(',')
                agent = {}
                for part in parts:
                    if ':' in part:
                        key, value = part.split(':', 1)
                        agent[key.strip().lower()] = value.strip()
                agents.append(agent)

    return {"agents": agents}


@app.get("/syscheck")
def get_syscheck_status():
    """Get file integrity monitoring status."""
    stdout, stderr, code = run_cmd(["/var/ossec/bin/syscheck_control", "-l"])

    files = []
    if code == 0:
        for line in stdout.strip().split('\n')[2:]:  # Skip header
            if line.strip():
                files.append(line.strip())

    return {"monitored_files": len(files), "files": files[:100]}


@app.get("/rootcheck")
def get_rootcheck_status():
    """Get rootkit detection status."""
    stdout, stderr, code = run_cmd(["/var/ossec/bin/rootcheck_control", "-l"])

    return {"output": stdout if code == 0 else stderr}


@app.get("/logs")
def get_logs(lines: int = 50):
    """Get Wazuh logs."""
    log_file = "/var/ossec/logs/ossec.log"

    if not os.path.exists(log_file):
        return {"logs": []}

    try:
        with open(log_file, 'r') as f:
            all_lines = f.readlines()
        return {"logs": all_lines[-lines:]}
    except Exception as e:
        return {"logs": [], "error": str(e)}


@app.get("/rules")
def list_rules():
    """List active detection rules."""
    rules_dir = "/var/ossec/ruleset/rules"

    rules = []
    if os.path.exists(rules_dir):
        for entry in os.listdir(rules_dir):
            if entry.endswith('.xml'):
                rules.append({
                    "name": entry,
                    "path": os.path.join(rules_dir, entry)
                })

    return {"rules": sorted(rules, key=lambda x: x["name"])}


@app.get("/decoders")
def list_decoders():
    """List active decoders."""
    decoders_dir = "/var/ossec/ruleset/decoders"

    decoders = []
    if os.path.exists(decoders_dir):
        for entry in os.listdir(decoders_dir):
            if entry.endswith('.xml'):
                decoders.append({
                    "name": entry,
                    "path": os.path.join(decoders_dir, entry)
                })

    return {"decoders": sorted(decoders, key=lambda x: x["name"])}
