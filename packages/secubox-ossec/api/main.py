"""SecuBox OSSEC API - Host-based Intrusion Detection System."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import json
import os
import re
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI(title="SecuBox OSSEC API", version="1.0.0")

OSSEC_DIR = "/var/ossec"
OSSEC_CONF = f"{OSSEC_DIR}/etc/ossec.conf"
ALERTS_LOG = f"{OSSEC_DIR}/logs/alerts/alerts.log"
OSSEC_LOG = f"{OSSEC_DIR}/logs/ossec.log"
SYSCHECK_DIR = f"{OSSEC_DIR}/queue/syscheck"


class MonitorPath(BaseModel):
    path: str
    realtime: bool = False
    report_changes: bool = True
    check_all: bool = True


class ActiveResponse(BaseModel):
    name: str
    enabled: bool


def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def is_ossec_running() -> bool:
    """Check if OSSEC is running."""
    control_script = f"{OSSEC_DIR}/bin/ossec-control"
    if os.path.exists(control_script):
        stdout, _, code = run_cmd([control_script, "status"])
        return "is running" in stdout.lower()
    return False


def get_ossec_version() -> str:
    """Get OSSEC version."""
    version_file = f"{OSSEC_DIR}/etc/ossec-init.conf"
    if os.path.exists(version_file):
        try:
            with open(version_file, 'r') as f:
                for line in f:
                    if 'VERSION=' in line:
                        return line.split('=')[1].strip().strip('"')
        except Exception:
            pass
    return "unknown"


def get_service_status() -> dict:
    """Get status of OSSEC services."""
    services = {}
    control_script = f"{OSSEC_DIR}/bin/ossec-control"

    if os.path.exists(control_script):
        stdout, _, code = run_cmd([control_script, "status"])
        if code == 0:
            for line in stdout.strip().split('\n'):
                if ' is ' in line:
                    parts = line.split(' is ')
                    if len(parts) == 2:
                        name = parts[0].strip()
                        status = 'running' if 'running' in parts[1].lower() else 'stopped'
                        services[name] = status

    return services


def parse_alerts_log(lines: int = 100) -> list:
    """Parse OSSEC alerts log."""
    alerts = []

    if not os.path.exists(ALERTS_LOG):
        return alerts

    try:
        with open(ALERTS_LOG, 'r') as f:
            content = f.read()

        # Split by alert separator
        alert_blocks = content.split('\n\n')

        for block in alert_blocks[-lines:]:
            if not block.strip():
                continue

            alert = {}
            lines_list = block.strip().split('\n')

            for line in lines_list:
                # Parse timestamp and rule
                if line.startswith('**'):
                    match = re.search(r'\*\* Alert (\d+\.\d+):.*- (\d+)', line)
                    if match:
                        alert['timestamp'] = match.group(1)
                        alert['rule_id'] = match.group(2)

                # Parse rule info
                elif 'Rule:' in line:
                    match = re.search(r"Rule: (\d+) \(level (\d+)\) -> '([^']*)'", line)
                    if match:
                        alert['rule_id'] = match.group(1)
                        alert['level'] = int(match.group(2))
                        alert['description'] = match.group(3)

                # Parse source
                elif 'Src IP:' in line:
                    alert['src_ip'] = line.split('Src IP:')[1].strip()

                elif 'User:' in line:
                    alert['user'] = line.split('User:')[1].strip()

                # Log content
                elif not line.startswith('**') and not line.startswith('Rule:'):
                    if 'log' not in alert:
                        alert['log'] = []
                    alert['log'].append(line)

            if alert:
                alerts.append(alert)

    except Exception:
        pass

    return alerts


def get_alert_stats() -> dict:
    """Get alert statistics."""
    alerts = parse_alerts_log(500)

    stats = {
        "total": len(alerts),
        "by_level": {},
        "by_rule": {},
        "critical": 0,
        "warning": 0,
        "info": 0
    }

    for alert in alerts:
        level = alert.get('level', 0)

        # By level
        stats["by_level"][level] = stats["by_level"].get(level, 0) + 1

        # Categorize
        if level >= 12:
            stats["critical"] += 1
        elif level >= 7:
            stats["warning"] += 1
        else:
            stats["info"] += 1

        # By rule
        rule_id = alert.get('rule_id', 'unknown')
        if rule_id not in stats["by_rule"]:
            stats["by_rule"][rule_id] = {
                "count": 0,
                "description": alert.get('description', '')
            }
        stats["by_rule"][rule_id]["count"] += 1

    return stats


def get_syscheck_files() -> list:
    """Get list of files being monitored by syscheck."""
    files = []

    if os.path.exists(OSSEC_CONF):
        try:
            with open(OSSEC_CONF, 'r') as f:
                content = f.read()

            # Parse directories from syscheck config
            import xml.etree.ElementTree as ET
            root = ET.fromstring(f"<root>{content}</root>")

            for syscheck in root.findall('.//syscheck'):
                for directories in syscheck.findall('directories'):
                    files.append({
                        "path": directories.text,
                        "realtime": directories.get('realtime', 'no'),
                        "report_changes": directories.get('report_changes', 'no')
                    })
        except Exception:
            pass

    return files


def get_rootcheck_status() -> dict:
    """Get rootcheck scan status."""
    rootcheck_db = f"{OSSEC_DIR}/queue/rootcheck"
    status = {
        "enabled": True,
        "last_scan": None,
        "issues": []
    }

    # Check for rootcheck results
    if os.path.exists(rootcheck_db):
        try:
            for entry in os.listdir(rootcheck_db):
                path = os.path.join(rootcheck_db, entry)
                if os.path.isfile(path):
                    stat = os.stat(path)
                    status["last_scan"] = datetime.fromtimestamp(stat.st_mtime).isoformat()

                    with open(path, 'r') as f:
                        for line in f:
                            if line.strip() and not line.startswith('#'):
                                status["issues"].append(line.strip())
                    break
        except Exception:
            pass

    return status


@app.get("/health")
def health():
    return {"status": "ok", "service": "ossec"}


@app.get("/status")
def get_status():
    """Get OSSEC status."""
    running = is_ossec_running()
    services = get_service_status()
    version = get_ossec_version()

    return {
        "running": running,
        "version": version,
        "ossec_dir": OSSEC_DIR,
        "services": services
    }


@app.post("/start")
def start_ossec():
    """Start OSSEC services."""
    control_script = f"{OSSEC_DIR}/bin/ossec-control"

    if not os.path.exists(control_script):
        raise HTTPException(status_code=404, detail="OSSEC not installed")

    stdout, stderr, code = run_cmd([control_script, "start"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to start: {stderr}")

    return {"status": "started"}


@app.post("/stop")
def stop_ossec():
    """Stop OSSEC services."""
    control_script = f"{OSSEC_DIR}/bin/ossec-control"

    if not os.path.exists(control_script):
        raise HTTPException(status_code=404, detail="OSSEC not installed")

    stdout, stderr, code = run_cmd([control_script, "stop"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to stop: {stderr}")

    return {"status": "stopped"}


@app.post("/restart")
def restart_ossec():
    """Restart OSSEC services."""
    control_script = f"{OSSEC_DIR}/bin/ossec-control"

    if not os.path.exists(control_script):
        raise HTTPException(status_code=404, detail="OSSEC not installed")

    stdout, stderr, code = run_cmd([control_script, "restart"])
    if code != 0:
        raise HTTPException(status_code=500, detail=f"Failed to restart: {stderr}")

    return {"status": "restarted"}


@app.get("/alerts")
def list_alerts(count: int = 50, level: int = None):
    """Get recent alerts."""
    alerts = parse_alerts_log(count * 2)  # Get more to filter

    if level is not None:
        alerts = [a for a in alerts if a.get('level', 0) >= level]

    return {"alerts": alerts[-count:], "count": len(alerts[-count:])}


@app.get("/alerts/stats")
def get_alerts_stats():
    """Get alert statistics."""
    return get_alert_stats()


@app.get("/syscheck")
def get_syscheck():
    """Get file integrity monitoring configuration."""
    files = get_syscheck_files()

    return {
        "monitored_paths": files,
        "count": len(files)
    }


@app.post("/syscheck/scan")
def run_syscheck_scan():
    """Trigger a syscheck scan."""
    agent_control = f"{OSSEC_DIR}/bin/agent_control"

    if os.path.exists(agent_control):
        stdout, stderr, code = run_cmd([agent_control, "-r", "-a"])
        return {"status": "scan_triggered", "output": stdout}

    # Try syscheck_control
    syscheck_control = f"{OSSEC_DIR}/bin/syscheck_control"
    if os.path.exists(syscheck_control):
        stdout, stderr, code = run_cmd([syscheck_control, "-u", "000"])
        return {"status": "scan_triggered", "output": stdout}

    raise HTTPException(status_code=404, detail="Syscheck control not found")


@app.get("/rootcheck")
def get_rootcheck():
    """Get rootkit detection status."""
    return get_rootcheck_status()


@app.post("/rootcheck/scan")
def run_rootcheck_scan():
    """Trigger a rootcheck scan."""
    rootcheck_control = f"{OSSEC_DIR}/bin/rootcheck_control"

    if os.path.exists(rootcheck_control):
        stdout, stderr, code = run_cmd([rootcheck_control, "-u", "000"])
        return {"status": "scan_triggered", "output": stdout}

    raise HTTPException(status_code=404, detail="Rootcheck control not found")


@app.get("/logs")
def get_logs(lines: int = 50):
    """Get OSSEC logs."""
    if not os.path.exists(OSSEC_LOG):
        return {"logs": []}

    try:
        with open(OSSEC_LOG, 'r') as f:
            all_lines = f.readlines()
        return {"logs": all_lines[-lines:]}
    except Exception as e:
        return {"logs": [], "error": str(e)}


@app.get("/rules")
def list_rules():
    """List detection rules."""
    rules_dir = f"{OSSEC_DIR}/rules"
    rules = []

    if os.path.exists(rules_dir):
        for entry in os.listdir(rules_dir):
            if entry.endswith('.xml'):
                path = os.path.join(rules_dir, entry)
                stat = os.stat(path)
                rules.append({
                    "name": entry,
                    "path": path,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })

    return {"rules": sorted(rules, key=lambda x: x["name"])}


@app.get("/decoders")
def list_decoders():
    """List log decoders."""
    decoders_dir = f"{OSSEC_DIR}/etc/decoders"
    decoders = []

    # Check both etc/decoders and rules directory
    for dir_path in [decoders_dir, f"{OSSEC_DIR}/rules"]:
        if os.path.exists(dir_path):
            for entry in os.listdir(dir_path):
                if 'decoder' in entry.lower() and entry.endswith('.xml'):
                    path = os.path.join(dir_path, entry)
                    decoders.append({
                        "name": entry,
                        "path": path
                    })

    return {"decoders": sorted(decoders, key=lambda x: x["name"])}


@app.get("/active-response")
def list_active_responses():
    """List active response scripts."""
    ar_dir = f"{OSSEC_DIR}/active-response/bin"
    responses = []

    if os.path.exists(ar_dir):
        for entry in os.listdir(ar_dir):
            path = os.path.join(ar_dir, entry)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                responses.append({
                    "name": entry,
                    "path": path,
                    "executable": True
                })

    return {"responses": sorted(responses, key=lambda x: x["name"])}


@app.get("/agents")
def list_agents():
    """List connected agents (server mode)."""
    agent_control = f"{OSSEC_DIR}/bin/agent_control"

    if not os.path.exists(agent_control):
        return {"agents": [], "mode": "local"}

    stdout, stderr, code = run_cmd([agent_control, "-l"])

    agents = []
    if code == 0:
        for line in stdout.strip().split('\n'):
            if 'ID:' in line:
                parts = line.split(',')
                agent = {}
                for part in parts:
                    if ':' in part:
                        key, value = part.split(':', 1)
                        agent[key.strip().lower()] = value.strip()
                agents.append(agent)

    return {"agents": agents, "mode": "server" if agents else "local"}
