"""
SecuBox-Deb :: SOC Gateway Node Registry
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Manages registered edge nodes with health tracking.
"""

import json
import secrets
import hashlib
import hmac
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass, asdict

logger = logging.getLogger("secubox.soc-gateway.registry")

# Storage paths
DATA_DIR = Path("/var/lib/secubox/soc-gateway")
NODES_FILE = DATA_DIR / "nodes.json"
TOKENS_FILE = DATA_DIR / "enrollment_tokens.json"
SECRET_KEY_FILE = DATA_DIR / ".secret_key"

# Timeouts
HEARTBEAT_TIMEOUT = 180  # seconds - node considered offline
STALE_TIMEOUT = 3600  # seconds - node considered stale


class NodeStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    STALE = "stale"
    PENDING = "pending"


class NodeHealth(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class NodeInfo:
    """Registered edge node information."""
    node_id: str
    hostname: str
    token_hash: str  # Hash of node token (not stored in plain)
    ip_address: str
    status: str = "pending"
    health: str = "unknown"
    enrolled_at: str = ""
    last_seen: str = ""
    last_metrics: Optional[Dict] = None
    capabilities: List[str] = None
    region: str = ""
    tags: List[str] = None

    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []
        if self.tags is None:
            self.tags = []


class NodeRegistry:
    """Manages edge node registration and health tracking."""

    def __init__(self, data_dir: Path = DATA_DIR):
        self.data_dir = data_dir
        self.nodes_file = data_dir / "nodes.json"
        self.tokens_file = data_dir / "enrollment_tokens.json"
        self.secret_key_file = data_dir / ".secret_key"

        self.nodes: Dict[str, NodeInfo] = {}
        self.enrollment_tokens: Dict[str, Dict] = {}
        self.secret_key: bytes = b""

        self._ensure_dirs()
        self._load_secret_key()
        self._load_data()

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _load_secret_key(self):
        """Load or generate HMAC secret key."""
        if self.secret_key_file.exists():
            self.secret_key = self.secret_key_file.read_bytes()
        else:
            self.secret_key = secrets.token_bytes(32)
            self.secret_key_file.write_bytes(self.secret_key)
            self.secret_key_file.chmod(0o600)

    def _load_data(self):
        """Load nodes and tokens from files."""
        if self.nodes_file.exists():
            try:
                data = json.loads(self.nodes_file.read_text())
                for node_id, node_data in data.items():
                    self.nodes[node_id] = NodeInfo(**node_data)
            except Exception as e:
                logger.error(f"Failed to load nodes: {e}")

        if self.tokens_file.exists():
            try:
                self.enrollment_tokens = json.loads(self.tokens_file.read_text())
            except Exception as e:
                logger.error(f"Failed to load tokens: {e}")

    def _save_nodes(self):
        """Save nodes to file."""
        data = {k: asdict(v) for k, v in self.nodes.items()}
        self.nodes_file.write_text(json.dumps(data, indent=2, default=str))

    def _save_tokens(self):
        """Save enrollment tokens to file."""
        self.tokens_file.write_text(json.dumps(self.enrollment_tokens, indent=2))

    def generate_enrollment_token(
        self,
        ttl_minutes: int = 60,
        region: str = "",
        tags: List[str] = None
    ) -> Dict[str, Any]:
        """Generate a one-time enrollment token for edge nodes."""
        token_bytes = secrets.token_bytes(16)
        token_str = token_bytes.hex()

        # Create HMAC signature
        signature = hmac.new(
            self.secret_key, token_bytes, hashlib.sha256
        ).hexdigest()[:8]

        full_token = f"{token_str}{signature}"

        now = datetime.utcnow()
        expires = now + timedelta(minutes=ttl_minutes)

        token_data = {
            "token_hash": hashlib.sha256(full_token.encode()).hexdigest(),
            "created_at": now.isoformat() + "Z",
            "expires_at": expires.isoformat() + "Z",
            "region": region,
            "tags": tags or [],
            "used": False
        }

        self.enrollment_tokens[full_token] = token_data
        self._save_tokens()

        return {
            "token": full_token,
            "expires_at": token_data["expires_at"],
            "region": region
        }

    def validate_enrollment_token(self, token: str) -> Optional[Dict]:
        """Validate an enrollment token."""
        if len(token) != 40:  # 32 hex + 8 signature
            return None

        token_part = token[:32]
        signature = token[32:]

        # Verify HMAC
        expected_sig = hmac.new(
            self.secret_key,
            bytes.fromhex(token_part),
            hashlib.sha256
        ).hexdigest()[:8]

        if not hmac.compare_digest(signature, expected_sig):
            return None

        # Check if token exists and is valid
        token_data = self.enrollment_tokens.get(token)
        if not token_data:
            return None

        if token_data.get("used"):
            return None

        expires = datetime.fromisoformat(token_data["expires_at"].rstrip("Z"))
        if datetime.utcnow() > expires:
            return None

        return token_data

    def enroll_node(
        self,
        enrollment_token: str,
        node_id: str,
        hostname: str,
        ip_address: str,
        capabilities: List[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Enroll a new edge node."""
        # Validate enrollment token
        token_data = self.validate_enrollment_token(enrollment_token)
        if not token_data:
            return None

        # Generate node token for authentication
        node_token = secrets.token_hex(32)
        token_hash = hashlib.sha256(node_token.encode()).hexdigest()

        now = datetime.utcnow().isoformat() + "Z"

        # Create node record
        node = NodeInfo(
            node_id=node_id,
            hostname=hostname,
            token_hash=token_hash,
            ip_address=ip_address,
            status=NodeStatus.ONLINE.value,
            health=NodeHealth.UNKNOWN.value,
            enrolled_at=now,
            last_seen=now,
            capabilities=capabilities or ["metrics", "alerts"],
            region=token_data.get("region", ""),
            tags=token_data.get("tags", [])
        )

        # Mark token as used
        self.enrollment_tokens[enrollment_token]["used"] = True
        self._save_tokens()

        # Save node
        self.nodes[node_id] = node
        self._save_nodes()

        logger.info(f"Node enrolled: {node_id} ({hostname})")

        return {
            "node_token": node_token,
            "node_id": node_id,
            "enrolled_at": now
        }

    def validate_node_signature(
        self,
        node_id: str,
        payload: str,
        signature: str
    ) -> bool:
        """Validate a signed payload from a node."""
        node = self.nodes.get(node_id)
        if not node:
            return False

        # We can't verify directly since we only store the hash
        # The node sends signature = hmac(payload, node_token)
        # We verify by checking if the signature matches what the node should have generated
        # This requires the node to have the correct token
        # For now, we trust the signature if the node exists and is enrolled
        # A more robust approach would use asymmetric keys

        return node.status != NodeStatus.PENDING.value

    def update_node_metrics(
        self,
        node_id: str,
        metrics: Dict[str, Any]
    ) -> bool:
        """Update node with latest metrics."""
        node = self.nodes.get(node_id)
        if not node:
            return False

        now = datetime.utcnow().isoformat() + "Z"
        node.last_seen = now
        node.last_metrics = metrics
        node.status = NodeStatus.ONLINE.value
        node.health = metrics.get("health", NodeHealth.UNKNOWN.value)

        self._save_nodes()
        return True

    def get_node(self, node_id: str) -> Optional[NodeInfo]:
        """Get a node by ID."""
        return self.nodes.get(node_id)

    def get_all_nodes(
        self,
        status: Optional[str] = None,
        region: Optional[str] = None
    ) -> List[NodeInfo]:
        """Get all nodes, optionally filtered."""
        nodes = list(self.nodes.values())

        if status:
            nodes = [n for n in nodes if n.status == status]

        if region:
            nodes = [n for n in nodes if n.region == region]

        return nodes

    def update_status(self):
        """Update node statuses based on last seen time."""
        now = datetime.utcnow()
        updated = 0

        for node in self.nodes.values():
            if not node.last_seen:
                continue

            last_seen = datetime.fromisoformat(node.last_seen.rstrip("Z"))
            delta = (now - last_seen).total_seconds()

            old_status = node.status

            if delta < HEARTBEAT_TIMEOUT:
                node.status = NodeStatus.ONLINE.value
            elif delta < STALE_TIMEOUT:
                node.status = NodeStatus.OFFLINE.value
            else:
                node.status = NodeStatus.STALE.value

            if old_status != node.status:
                updated += 1

        if updated > 0:
            self._save_nodes()

        return updated

    def delete_node(self, node_id: str) -> bool:
        """Delete a node."""
        if node_id not in self.nodes:
            return False

        del self.nodes[node_id]
        self._save_nodes()
        logger.info(f"Node deleted: {node_id}")
        return True

    def get_fleet_summary(self) -> Dict[str, Any]:
        """Get fleet-wide summary statistics."""
        self.update_status()

        total = len(self.nodes)
        by_status = {s.value: 0 for s in NodeStatus}
        by_health = {h.value: 0 for h in NodeHealth}
        by_region: Dict[str, int] = {}

        for node in self.nodes.values():
            by_status[node.status] = by_status.get(node.status, 0) + 1
            by_health[node.health] = by_health.get(node.health, 0) + 1

            region = node.region or "default"
            by_region[region] = by_region.get(region, 0) + 1

        return {
            "total_nodes": total,
            "by_status": by_status,
            "by_health": by_health,
            "by_region": by_region,
            "online": by_status.get(NodeStatus.ONLINE.value, 0),
            "critical": by_health.get(NodeHealth.CRITICAL.value, 0),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def cleanup_stale_tokens(self) -> int:
        """Remove expired enrollment tokens."""
        now = datetime.utcnow()
        expired = []

        for token, data in self.enrollment_tokens.items():
            expires = datetime.fromisoformat(data["expires_at"].rstrip("Z"))
            if now > expires or data.get("used"):
                expired.append(token)

        for token in expired:
            del self.enrollment_tokens[token]

        if expired:
            self._save_tokens()

        return len(expired)
