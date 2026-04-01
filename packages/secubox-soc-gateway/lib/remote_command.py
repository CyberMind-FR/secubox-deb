"""
SecuBox-Deb :: SOC Gateway Remote Command
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Executes commands on remote edge nodes through the agent API.
"""

import hmac
import hashlib
import json
import secrets
import logging
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum

import httpx

from .node_registry import NodeRegistry, NodeInfo

logger = logging.getLogger("secubox.soc-gateway.remote")

# Storage
DATA_DIR = Path("/var/lib/secubox/soc-gateway")
COMMAND_HISTORY_FILE = DATA_DIR / "command_history.json"


class CommandStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class RemoteCommand:
    """A command to be executed on a remote node."""
    id: str
    node_id: str
    action: str
    args: List[str]
    status: str
    created_at: str
    sent_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[str] = None
    error: Optional[str] = None
    created_by: str = "admin"


class RemoteCommandManager:
    """Manages remote command execution on edge nodes."""

    def __init__(self, registry: NodeRegistry):
        self.registry = registry
        self.commands: Dict[str, RemoteCommand] = {}
        self.pending_queue: List[str] = []
        self._load_history()

    def _load_history(self):
        """Load command history from file."""
        if COMMAND_HISTORY_FILE.exists():
            try:
                data = json.loads(COMMAND_HISTORY_FILE.read_text())
                for cmd_id, cmd_data in data.items():
                    self.commands[cmd_id] = RemoteCommand(**cmd_data)
            except Exception as e:
                logger.error(f"Failed to load command history: {e}")

    def _save_history(self):
        """Save command history to file."""
        # Keep last 500 commands
        sorted_cmds = sorted(
            self.commands.values(),
            key=lambda c: c.created_at,
            reverse=True
        )[:500]

        data = {c.id: asdict(c) for c in sorted_cmds}
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        COMMAND_HISTORY_FILE.write_text(json.dumps(data, indent=2))

    def create_command(
        self,
        node_id: str,
        action: str,
        args: List[str] = None,
        created_by: str = "admin"
    ) -> RemoteCommand:
        """Create a new remote command."""
        # Verify node exists
        node = self.registry.get_node(node_id)
        if not node:
            raise ValueError(f"Node not found: {node_id}")

        cmd_id = f"CMD-{secrets.token_hex(6).upper()}"
        now = datetime.utcnow().isoformat() + "Z"

        cmd = RemoteCommand(
            id=cmd_id,
            node_id=node_id,
            action=action,
            args=args or [],
            status=CommandStatus.PENDING.value,
            created_at=now,
            created_by=created_by
        )

        self.commands[cmd_id] = cmd
        self.pending_queue.append(cmd_id)
        self._save_history()

        return cmd

    def sign_command(self, cmd: RemoteCommand, node_token: str) -> str:
        """Create signature for command."""
        sign_data = f"{cmd.id}:{cmd.action}:{':'.join(cmd.args)}"
        return hmac.new(
            node_token.encode(),
            sign_data.encode(),
            hashlib.sha256
        ).hexdigest()

    async def execute_command(
        self,
        cmd_id: str,
        node_token: str,
        node_url: str
    ) -> Dict[str, Any]:
        """Execute a command on a remote node."""
        cmd = self.commands.get(cmd_id)
        if not cmd:
            return {"error": "Command not found"}

        # Sign the command
        signature = self.sign_command(cmd, node_token)

        payload = {
            "id": cmd.id,
            "action": cmd.action,
            "args": cmd.args,
            "signature": signature,
            "from_node": "soc-gateway"
        }

        cmd.status = CommandStatus.SENT.value
        cmd.sent_at = datetime.utcnow().isoformat() + "Z"

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{node_url}/api/v1/soc-agent/command",
                    json=payload
                )
                result = response.json()

                if result.get("status") == "success":
                    cmd.status = CommandStatus.SUCCESS.value
                    cmd.result = result.get("output", "")
                else:
                    cmd.status = CommandStatus.FAILED.value
                    cmd.error = result.get("error", "Unknown error")

                cmd.completed_at = datetime.utcnow().isoformat() + "Z"
                self._save_history()

                return {
                    "command_id": cmd.id,
                    "status": cmd.status,
                    "result": cmd.result,
                    "error": cmd.error
                }

        except httpx.TimeoutException:
            cmd.status = CommandStatus.TIMEOUT.value
            cmd.error = "Request timed out"
            cmd.completed_at = datetime.utcnow().isoformat() + "Z"
            self._save_history()
            return {"command_id": cmd.id, "status": "timeout", "error": "Request timed out"}

        except Exception as e:
            cmd.status = CommandStatus.FAILED.value
            cmd.error = str(e)
            cmd.completed_at = datetime.utcnow().isoformat() + "Z"
            self._save_history()
            return {"command_id": cmd.id, "status": "failed", "error": str(e)}

    async def broadcast_command(
        self,
        action: str,
        args: List[str] = None,
        node_ids: List[str] = None,
        region: str = None
    ) -> Dict[str, Any]:
        """Broadcast a command to multiple nodes."""
        # Get target nodes
        if node_ids:
            nodes = [self.registry.get_node(nid) for nid in node_ids]
            nodes = [n for n in nodes if n is not None]
        else:
            nodes = self.registry.get_all_nodes(status="online", region=region)

        if not nodes:
            return {"error": "No target nodes found"}

        results = []
        for node in nodes:
            try:
                cmd = self.create_command(
                    node_id=node.node_id,
                    action=action,
                    args=args,
                    created_by="soc-gateway"
                )

                # Note: In production, you'd need to look up the node URL
                # For now, we just create the commands
                results.append({
                    "node_id": node.node_id,
                    "command_id": cmd.id,
                    "status": "queued"
                })
            except Exception as e:
                results.append({
                    "node_id": node.node_id,
                    "status": "failed",
                    "error": str(e)
                })

        return {
            "action": action,
            "target_nodes": len(nodes),
            "results": results
        }

    def get_command(self, cmd_id: str) -> Optional[Dict[str, Any]]:
        """Get command details."""
        cmd = self.commands.get(cmd_id)
        if cmd:
            return asdict(cmd)
        return None

    def get_commands(
        self,
        node_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get command history with optional filters."""
        commands = list(self.commands.values())

        if node_id:
            commands = [c for c in commands if c.node_id == node_id]

        if status:
            commands = [c for c in commands if c.status == status]

        # Sort by created_at descending
        commands.sort(key=lambda c: c.created_at, reverse=True)

        return [asdict(c) for c in commands[:limit]]

    def get_pending_commands(self) -> List[Dict[str, Any]]:
        """Get commands waiting to be executed."""
        pending = [
            self.commands.get(cmd_id)
            for cmd_id in self.pending_queue
            if cmd_id in self.commands
        ]
        return [asdict(c) for c in pending if c]
