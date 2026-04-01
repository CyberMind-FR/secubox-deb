"""
SecuBox-Deb :: SOC Agent Command Handler
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Handles remote commands from SOC gateway with security validation.
"""

import subprocess
import logging
import hmac
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from enum import Enum

logger = logging.getLogger("secubox.soc-agent.command")

# Audit log
AUDIT_LOG = Path("/var/log/secubox/soc-agent-audit.log")

# Allowed commands whitelist
ALLOWED_COMMANDS = {
    # Service management
    "service.restart": ["systemctl", "restart"],
    "service.stop": ["systemctl", "stop"],
    "service.start": ["systemctl", "start"],
    "service.status": ["systemctl", "status"],

    # CrowdSec management
    "crowdsec.ban": ["cscli", "decisions", "add", "-i"],
    "crowdsec.unban": ["cscli", "decisions", "delete", "-i"],
    "crowdsec.sync": ["cscli", "hub", "update"],

    # System info
    "system.reboot": ["systemctl", "reboot"],
    "system.update": ["apt-get", "update"],

    # Firewall
    "firewall.reload": ["nft", "-f", "/etc/nftables.conf"],
}

# Services that can be managed remotely
ALLOWED_SERVICES = {
    "nginx", "haproxy", "crowdsec", "suricata", "netdata",
    "secubox-hub", "secubox-watchdog", "secubox-soc-agent"
}

# Commands requiring confirmation
DANGEROUS_COMMANDS = {"system.reboot", "firewall.reload"}


class CommandStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    REJECTED = "rejected"


class Command:
    """Represents a remote command."""

    def __init__(
        self,
        cmd_id: str,
        action: str,
        args: List[str] = None,
        from_node: str = None,
        signature: str = None
    ):
        self.id = cmd_id
        self.action = action
        self.args = args or []
        self.from_node = from_node
        self.signature = signature
        self.status = CommandStatus.PENDING
        self.result: Optional[str] = None
        self.error: Optional[str] = None
        self.received_at = datetime.utcnow().isoformat() + "Z"
        self.executed_at: Optional[str] = None


def audit_log(
    action: str,
    command: Command,
    result: str,
    success: bool
):
    """Write to audit log."""
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "action": action,
        "command_id": command.id,
        "from_node": command.from_node,
        "args": command.args,
        "result": result[:500] if result else None,
        "success": success
    }

    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def validate_command(command: Command, node_token: str) -> bool:
    """Validate command signature."""
    if not command.signature:
        logger.warning(f"Command {command.id} missing signature")
        return False

    # Reconstruct signed data
    sign_data = f"{command.id}:{command.action}:{':'.join(command.args)}"
    expected_sig = hmac.new(
        node_token.encode(),
        sign_data.encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(command.signature, expected_sig)


def validate_action(action: str, args: List[str]) -> tuple:
    """Validate that action is allowed with given args."""
    if action not in ALLOWED_COMMANDS:
        return False, f"Unknown action: {action}"

    # Validate service names
    if action.startswith("service."):
        if not args:
            return False, "Service name required"
        service = args[0]
        if service not in ALLOWED_SERVICES:
            return False, f"Service not allowed: {service}"

    # Validate IP addresses for ban/unban
    if action in ("crowdsec.ban", "crowdsec.unban"):
        if not args:
            return False, "IP address required"
        ip = args[0]
        # Basic IP validation
        parts = ip.split(".")
        if len(parts) != 4:
            return False, f"Invalid IP: {ip}"

    return True, None


def build_command(action: str, args: List[str]) -> List[str]:
    """Build system command from action and args."""
    base_cmd = ALLOWED_COMMANDS[action].copy()

    if action.startswith("service."):
        # Insert service name
        base_cmd.append(args[0])
    elif action in ("crowdsec.ban", "crowdsec.unban"):
        # Insert IP
        base_cmd.append(args[0])

    return base_cmd


async def execute_command(
    command: Command,
    node_token: str
) -> Dict[str, Any]:
    """Execute a validated remote command."""

    # Validate signature
    if not validate_command(command, node_token):
        command.status = CommandStatus.REJECTED
        command.error = "Invalid signature"
        audit_log("rejected", command, "Invalid signature", False)
        return {
            "id": command.id,
            "status": "rejected",
            "error": "Invalid signature"
        }

    # Validate action
    valid, error = validate_action(command.action, command.args)
    if not valid:
        command.status = CommandStatus.REJECTED
        command.error = error
        audit_log("rejected", command, error, False)
        return {
            "id": command.id,
            "status": "rejected",
            "error": error
        }

    # Build and execute
    command.status = CommandStatus.RUNNING
    command.executed_at = datetime.utcnow().isoformat() + "Z"

    try:
        cmd = build_command(command.action, command.args)
        logger.info(f"Executing: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode == 0:
            command.status = CommandStatus.SUCCESS
            command.result = result.stdout
            audit_log("executed", command, result.stdout, True)
            return {
                "id": command.id,
                "status": "success",
                "output": result.stdout[:1000]
            }
        else:
            command.status = CommandStatus.FAILED
            command.error = result.stderr
            audit_log("failed", command, result.stderr, False)
            return {
                "id": command.id,
                "status": "failed",
                "error": result.stderr[:500]
            }

    except subprocess.TimeoutExpired:
        command.status = CommandStatus.FAILED
        command.error = "Command timed out"
        audit_log("timeout", command, "Timeout", False)
        return {
            "id": command.id,
            "status": "failed",
            "error": "Command timed out"
        }
    except Exception as e:
        command.status = CommandStatus.FAILED
        command.error = str(e)
        audit_log("error", command, str(e), False)
        return {
            "id": command.id,
            "status": "failed",
            "error": str(e)
        }


def get_allowed_actions() -> Dict[str, Any]:
    """Get list of allowed remote actions."""
    return {
        "actions": list(ALLOWED_COMMANDS.keys()),
        "services": list(ALLOWED_SERVICES),
        "dangerous": list(DANGEROUS_COMMANDS)
    }


def get_audit_log(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent audit log entries."""
    entries = []

    if not AUDIT_LOG.exists():
        return entries

    try:
        with open(AUDIT_LOG, "r") as f:
            lines = f.readlines()[-limit:]

        for line in lines:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    except Exception as e:
        logger.error(f"Failed to read audit log: {e}")

    return entries
