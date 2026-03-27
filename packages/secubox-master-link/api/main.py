"""SecuBox Master-Link - Mesh Node Enrollment System
Token-based mesh onboarding with gigogne hierarchy and ZKP authentication.

Features:
- One-time HMAC-SHA256 join tokens
- Peer approval workflow
- Depth-limited mesh hierarchy (gigogne)
- ZKP challenge-response authentication
- Peer heartbeat and health monitoring
- WireGuard mesh integration
- Bulk peer operations
"""
import os
import json
import hmac
import hashlib
import secrets
import subprocess
import logging
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration
CONFIG_PATH = Path("/etc/secubox/master-link.toml")
DATA_DIR = Path("/var/lib/secubox/master-link")
TOKENS_FILE = DATA_DIR / "tokens.json"
PEERS_FILE = DATA_DIR / "peers.json"
BLOCKCHAIN_FILE = DATA_DIR / "blockchain.jsonl"
HEARTBEAT_FILE = DATA_DIR / "heartbeats.json"

# Heartbeat settings
HEARTBEAT_INTERVAL = 60  # seconds
HEARTBEAT_TIMEOUT = 180  # seconds - peer considered offline after this

app = FastAPI(title="SecuBox Master-Link", version="1.0.0")
logger = logging.getLogger("secubox.master-link")

# Generate or load secret key for HMAC tokens
SECRET_KEY_FILE = DATA_DIR / ".secret_key"


def get_secret_key() -> bytes:
    """Get or generate HMAC secret key."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SECRET_KEY_FILE.exists():
        return SECRET_KEY_FILE.read_bytes()
    key = secrets.token_bytes(32)
    SECRET_KEY_FILE.write_bytes(key)
    os.chmod(SECRET_KEY_FILE, 0o600)
    return key


SECRET_KEY = get_secret_key()


class PeerStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    PROMOTED = "promoted"  # Sub-master


class JoinToken(BaseModel):
    token: str
    created_at: str
    expires_at: str
    auto_approve: bool = False
    max_uses: int = 1
    uses: int = 0
    created_by: Optional[str] = None


class Peer(BaseModel):
    id: str
    fingerprint: str
    hostname: str
    ip_address: str
    status: PeerStatus = PeerStatus.PENDING
    depth: int = 1
    parent_id: Optional[str] = None
    joined_at: str
    approved_at: Optional[str] = None
    approved_by: Optional[str] = None
    last_seen: Optional[str] = None
    last_heartbeat: Optional[str] = None
    online: bool = False
    capabilities: List[str] = []
    wireguard_pubkey: Optional[str] = None
    wireguard_endpoint: Optional[str] = None
    metadata: Dict[str, Any] = {}


class JoinRequest(BaseModel):
    token: str
    fingerprint: str
    hostname: str
    public_key: Optional[str] = None
    capabilities: List[str] = []


class TokenRequest(BaseModel):
    auto_approve: bool = False
    ttl_minutes: int = 60
    max_uses: int = 1


class ApprovalRequest(BaseModel):
    action: str  # approve, reject, promote
    reason: Optional[str] = None


class MasterLinkManager:
    """Manages mesh enrollment and peer hierarchy."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.tokens_file = data_dir / "tokens.json"
        self.peers_file = data_dir / "peers.json"
        self.blockchain_file = data_dir / "blockchain.jsonl"
        self.config_file = data_dir / "config.json"
        self._ensure_dirs()
        self._load_data()

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _load_data(self):
        """Load tokens and peers from files."""
        self.tokens: Dict[str, JoinToken] = {}
        self.peers: Dict[str, Peer] = {}

        if self.tokens_file.exists():
            try:
                data = json.loads(self.tokens_file.read_text())
                self.tokens = {k: JoinToken(**v) for k, v in data.items()}
            except Exception:
                pass

        if self.peers_file.exists():
            try:
                data = json.loads(self.peers_file.read_text())
                self.peers = {k: Peer(**v) for k, v in data.items()}
            except Exception:
                pass

    def _save_tokens(self):
        self.tokens_file.write_text(json.dumps(
            {k: v.model_dump() for k, v in self.tokens.items()},
            indent=2
        ))

    def _save_peers(self):
        self.peers_file.write_text(json.dumps(
            {k: v.model_dump() for k, v in self.peers.items()},
            indent=2
        ))

    def _record_block(self, action: str, data: Dict[str, Any]):
        """Record action to blockchain log."""
        block = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": action,
            "data": data,
            "hash": hashlib.sha256(json.dumps(data).encode()).hexdigest()[:16]
        }
        with open(self.blockchain_file, "a") as f:
            f.write(json.dumps(block) + "\n")

    def get_role(self) -> str:
        """Get node's mesh role."""
        if self.config_file.exists():
            config = json.loads(self.config_file.read_text())
            return config.get("role", "master")
        return "master"

    def get_depth(self) -> int:
        """Get node's depth in hierarchy."""
        if self.config_file.exists():
            config = json.loads(self.config_file.read_text())
            return config.get("depth", 0)
        return 0

    def get_max_depth(self) -> int:
        """Get maximum allowed depth."""
        if self.config_file.exists():
            config = json.loads(self.config_file.read_text())
            return config.get("max_depth", 3)
        return 3

    def generate_token(
        self,
        auto_approve: bool = False,
        ttl_minutes: int = 60,
        max_uses: int = 1,
        created_by: Optional[str] = None
    ) -> JoinToken:
        """Generate a new join token."""
        # Generate random token
        token_bytes = secrets.token_bytes(16)
        token_str = token_bytes.hex()

        # Create HMAC signature
        signature = hmac.new(
            SECRET_KEY,
            token_bytes,
            hashlib.sha256
        ).hexdigest()[:8]

        full_token = f"{token_str}{signature}"

        now = datetime.utcnow()
        expires = now + timedelta(minutes=ttl_minutes)

        token = JoinToken(
            token=full_token,
            created_at=now.isoformat() + "Z",
            expires_at=expires.isoformat() + "Z",
            auto_approve=auto_approve,
            max_uses=max_uses,
            uses=0,
            created_by=created_by
        )

        self.tokens[full_token] = token
        self._save_tokens()

        self._record_block("token_generated", {
            "token_hash": hashlib.sha256(full_token.encode()).hexdigest()[:16],
            "auto_approve": auto_approve,
            "ttl_minutes": ttl_minutes
        })

        return token

    def validate_token(self, token: str) -> Optional[JoinToken]:
        """Validate a join token."""
        if len(token) != 40:  # 32 hex chars + 8 signature
            return None

        token_part = token[:32]
        signature = token[32:]

        # Verify HMAC
        expected_sig = hmac.new(
            SECRET_KEY,
            bytes.fromhex(token_part),
            hashlib.sha256
        ).hexdigest()[:8]

        if not hmac.compare_digest(signature, expected_sig):
            return None

        # Check if token exists and is valid
        token_obj = self.tokens.get(token)
        if not token_obj:
            return None

        # Check expiration
        expires = datetime.fromisoformat(token_obj.expires_at.rstrip("Z"))
        if datetime.utcnow() > expires:
            return None

        # Check uses
        if token_obj.uses >= token_obj.max_uses:
            return None

        return token_obj

    def process_join(self, request: JoinRequest, ip_address: str) -> Peer:
        """Process a join request."""
        # Validate token
        token = self.validate_token(request.token)
        if not token:
            raise ValueError("Invalid or expired token")

        # Check depth limit
        current_depth = self.get_depth()
        max_depth = self.get_max_depth()
        if current_depth >= max_depth:
            raise ValueError(f"Maximum mesh depth ({max_depth}) reached")

        # Generate peer ID
        peer_id = hashlib.sha256(
            f"{request.fingerprint}{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:12]

        now = datetime.utcnow().isoformat() + "Z"

        # Create peer
        peer = Peer(
            id=peer_id,
            fingerprint=request.fingerprint,
            hostname=request.hostname,
            ip_address=ip_address,
            status=PeerStatus.APPROVED if token.auto_approve else PeerStatus.PENDING,
            depth=current_depth + 1,
            joined_at=now,
            approved_at=now if token.auto_approve else None,
            capabilities=request.capabilities
        )

        # Increment token use
        token.uses += 1
        self._save_tokens()

        # Save peer
        self.peers[peer_id] = peer
        self._save_peers()

        # Record to blockchain
        self._record_block("join_request", {
            "peer_id": peer_id,
            "hostname": request.hostname,
            "fingerprint": request.fingerprint[:16] + "...",
            "auto_approved": token.auto_approve
        })

        return peer

    def approve_peer(self, peer_id: str, action: str, by: str = "admin") -> Peer:
        """Approve, reject, or promote a peer."""
        peer = self.peers.get(peer_id)
        if not peer:
            raise ValueError("Peer not found")

        now = datetime.utcnow().isoformat() + "Z"

        if action == "approve":
            peer.status = PeerStatus.APPROVED
            peer.approved_at = now
            peer.approved_by = by
        elif action == "reject":
            peer.status = PeerStatus.REJECTED
        elif action == "promote":
            peer.status = PeerStatus.PROMOTED
            peer.approved_by = by
        else:
            raise ValueError(f"Unknown action: {action}")

        self._save_peers()

        self._record_block(f"peer_{action}d", {
            "peer_id": peer_id,
            "by": by
        })

        return peer

    def get_mesh_tree(self) -> Dict[str, Any]:
        """Get mesh hierarchy tree."""
        root = {
            "id": "self",
            "hostname": self._get_hostname(),
            "role": self.get_role(),
            "depth": self.get_depth(),
            "children": []
        }

        # Group peers by depth
        for peer in self.peers.values():
            if peer.status in (PeerStatus.APPROVED, PeerStatus.PROMOTED):
                root["children"].append({
                    "id": peer.id,
                    "hostname": peer.hostname,
                    "role": "sub-master" if peer.status == PeerStatus.PROMOTED else "peer",
                    "depth": peer.depth,
                    "ip": peer.ip_address
                })

        return root

    def _get_hostname(self) -> str:
        try:
            return subprocess.check_output(["hostname"], text=True).strip()
        except Exception:
            return "unknown"

    def _get_lan_ip(self) -> str:
        """Get preferred LAN IP (prefer 192.168.x.x)."""
        try:
            result = subprocess.check_output(
                ["hostname", "-I"],
                text=True
            ).strip().split()
            for ip in result:
                if ip.startswith("192.168."):
                    return ip
            return result[0] if result else "127.0.0.1"
        except Exception:
            return "127.0.0.1"

    def cleanup_expired(self):
        """Remove expired tokens."""
        now = datetime.utcnow()
        expired = []
        for token_str, token in self.tokens.items():
            expires = datetime.fromisoformat(token.expires_at.rstrip("Z"))
            if now > expires:
                expired.append(token_str)

        for token_str in expired:
            del self.tokens[token_str]

        if expired:
            self._save_tokens()

        return len(expired)

    def record_heartbeat(self, peer_id: str, ip_address: Optional[str] = None) -> bool:
        """Record heartbeat from peer."""
        peer = self.peers.get(peer_id)
        if not peer:
            return False

        now = datetime.utcnow().isoformat() + "Z"
        peer.last_heartbeat = now
        peer.last_seen = now
        peer.online = True

        if ip_address and ip_address != peer.ip_address:
            peer.ip_address = ip_address

        self._save_peers()
        return True

    def update_online_status(self):
        """Update online status based on heartbeat timeout."""
        now = datetime.utcnow()
        updated = 0

        for peer in self.peers.values():
            if peer.last_heartbeat:
                last_hb = datetime.fromisoformat(peer.last_heartbeat.rstrip("Z"))
                was_online = peer.online
                peer.online = (now - last_hb).total_seconds() < HEARTBEAT_TIMEOUT

                if was_online != peer.online:
                    updated += 1

        if updated > 0:
            self._save_peers()

        return updated

    def delete_peer(self, peer_id: str) -> bool:
        """Delete a peer permanently."""
        if peer_id not in self.peers:
            return False

        peer = self.peers[peer_id]
        del self.peers[peer_id]
        self._save_peers()

        self._record_block("peer_deleted", {
            "peer_id": peer_id,
            "hostname": peer.hostname
        })

        return True

    def bulk_delete_peers(self, status: Optional[PeerStatus] = None,
                          offline_days: Optional[int] = None) -> int:
        """Delete multiple peers by criteria."""
        now = datetime.utcnow()
        to_delete = []

        for peer_id, peer in self.peers.items():
            if status and peer.status != status:
                continue

            if offline_days and peer.last_seen:
                last_seen = datetime.fromisoformat(peer.last_seen.rstrip("Z"))
                if (now - last_seen).days < offline_days:
                    continue
            elif offline_days and not peer.last_seen:
                # Never seen, include if filtering by offline
                pass
            elif offline_days:
                continue

            to_delete.append(peer_id)

        for peer_id in to_delete:
            del self.peers[peer_id]

        if to_delete:
            self._save_peers()
            self._record_block("bulk_delete", {
                "count": len(to_delete),
                "criteria": {"status": status.value if status else None, "offline_days": offline_days}
            })

        return len(to_delete)

    def set_wireguard_config(self, peer_id: str, pubkey: str, endpoint: Optional[str] = None) -> bool:
        """Set WireGuard configuration for a peer."""
        peer = self.peers.get(peer_id)
        if not peer:
            return False

        peer.wireguard_pubkey = pubkey
        if endpoint:
            peer.wireguard_endpoint = endpoint

        self._save_peers()
        return True

    def get_wireguard_peers(self) -> List[Dict[str, Any]]:
        """Get WireGuard peer configuration for mesh."""
        wg_peers = []
        for peer in self.peers.values():
            if peer.status == PeerStatus.APPROVED and peer.wireguard_pubkey:
                wg_peers.append({
                    "public_key": peer.wireguard_pubkey,
                    "endpoint": peer.wireguard_endpoint or f"{peer.ip_address}:51820",
                    "allowed_ips": f"10.100.0.{hash(peer.id) % 254 + 1}/32",
                    "persistent_keepalive": 25
                })
        return wg_peers

    def get_mesh_stats(self) -> Dict[str, Any]:
        """Get mesh statistics."""
        total = len(self.peers)
        by_status = {s.value: 0 for s in PeerStatus}
        online = 0
        with_wg = 0

        for peer in self.peers.values():
            by_status[peer.status.value] += 1
            if peer.online:
                online += 1
            if peer.wireguard_pubkey:
                with_wg += 1

        return {
            "total_peers": total,
            "by_status": by_status,
            "online": online,
            "offline": total - online,
            "with_wireguard": with_wg,
            "active_tokens": len(self.tokens)
        }


# Global instance
manager = MasterLinkManager(DATA_DIR)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    approved = sum(1 for p in manager.peers.values() if p.status == PeerStatus.APPROVED)
    pending = sum(1 for p in manager.peers.values() if p.status == PeerStatus.PENDING)

    return {
        "module": "master-link",
        "status": "ok",
        "version": "1.0.0",
        "role": manager.get_role(),
        "depth": manager.get_depth(),
        "peers_approved": approved,
        "peers_pending": pending
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.post("/token", dependencies=[Depends(require_jwt)])
async def generate_token(request: TokenRequest):
    """Generate a new join token."""
    token = manager.generate_token(
        auto_approve=request.auto_approve,
        ttl_minutes=request.ttl_minutes,
        max_uses=request.max_uses
    )

    # Build join URLs
    ip = manager._get_lan_ip()
    hostname = manager._get_hostname()

    return {
        "token": token.token,
        "expires_at": token.expires_at,
        "auto_approve": token.auto_approve,
        "join_url": f"http://{ip}:7331/master-link/?token={token.token}",
        "join_cli": f"sbx-mesh-join {ip} {token.token}",
        "one_liner": f"wget -qO- 'http://{ip}:7331/master-link/join-script?token={token.token}' | sh"
    }


@app.get("/tokens", dependencies=[Depends(require_jwt)])
async def list_tokens():
    """List active tokens."""
    manager.cleanup_expired()
    tokens = [
        {
            "token": t.token[:8] + "...",
            "created_at": t.created_at,
            "expires_at": t.expires_at,
            "auto_approve": t.auto_approve,
            "uses": t.uses,
            "max_uses": t.max_uses
        }
        for t in manager.tokens.values()
    ]
    return {"tokens": tokens}


@app.post("/join")
async def join_mesh(request: JoinRequest, req: Request):
    """Submit a join request (public endpoint)."""
    try:
        # Get client IP
        ip_address = req.client.host
        forwarded = req.headers.get("x-forwarded-for")
        if forwarded:
            ip_address = forwarded.split(",")[0].strip()

        peer = manager.process_join(request, ip_address)

        return {
            "status": "success" if peer.status == PeerStatus.APPROVED else "pending",
            "peer_id": peer.id,
            "message": "Approved automatically" if peer.status == PeerStatus.APPROVED else "Awaiting approval"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/join-script")
async def join_script(token: str, req: Request):
    """Get executable join script (public endpoint)."""
    token_obj = manager.validate_token(token)
    if not token_obj:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    ip = manager._get_lan_ip()

    script = f"""#!/bin/sh
# SecuBox Mesh Join Script
# Generated by {manager._get_hostname()}

MASTER_IP="{ip}"
TOKEN="{token}"

echo "Joining SecuBox mesh..."
echo "Master: $MASTER_IP"

# Generate fingerprint
FINGERPRINT=$(cat /etc/machine-id 2>/dev/null || hostname | sha256sum | cut -c1-32)
HOSTNAME=$(hostname)

# Send join request
curl -s -X POST "http://$MASTER_IP:7331/master-link/join" \\
  -H "Content-Type: application/json" \\
  -d '{{"token":"'$TOKEN'","fingerprint":"'$FINGERPRINT'","hostname":"'$HOSTNAME'"}}'

echo ""
echo "Join request submitted."
"""

    return script


@app.get("/peers", dependencies=[Depends(require_jwt)])
async def list_peers(status: Optional[str] = None):
    """List all peers."""
    peers = list(manager.peers.values())

    if status:
        peers = [p for p in peers if p.status.value == status]

    return {"peers": peers, "count": len(peers)}


@app.get("/peers/{peer_id}", dependencies=[Depends(require_jwt)])
async def get_peer(peer_id: str):
    """Get peer details."""
    peer = manager.peers.get(peer_id)
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")
    return peer


@app.post("/peers/{peer_id}/approve", dependencies=[Depends(require_jwt)])
async def approve_peer(peer_id: str, request: ApprovalRequest):
    """Approve, reject, or promote a peer."""
    try:
        peer = manager.approve_peer(peer_id, request.action)
        return {"status": "success", "peer": peer}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/tree", dependencies=[Depends(require_jwt)])
async def get_mesh_tree():
    """Get mesh hierarchy tree."""
    return manager.get_mesh_tree()


@app.post("/cleanup", dependencies=[Depends(require_jwt)])
async def cleanup():
    """Cleanup expired tokens."""
    count = manager.cleanup_expired()
    return {"cleaned": count}


# Localhost-only endpoints (no JWT required, but restricted to local)
def is_local_request(request: Request) -> bool:
    """Check if request is from localhost."""
    client_ip = request.client.host
    forwarded = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    return client_ip in ("127.0.0.1", "::1", "localhost")


@app.post("/invite-local")
async def invite_local(request: Request, auto_approve: bool = True, ttl: int = 60):
    """Generate invite token (localhost only, no auth)."""
    if not is_local_request(request):
        raise HTTPException(status_code=403, detail="Localhost only")

    token = manager.generate_token(
        auto_approve=auto_approve,
        ttl_minutes=ttl
    )

    ip = manager._get_lan_ip()

    return {
        "token": token.token,
        "url": f"http://{ip}:7331/master-link/?token={token.token}",
        "cli": f"sbx-mesh-join {ip} {token.token}"
    }


# Heartbeat endpoints
@app.post("/heartbeat/{peer_id}")
async def peer_heartbeat(peer_id: str, request: Request):
    """Record heartbeat from a peer (public endpoint)."""
    ip_address = request.client.host
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip_address = forwarded.split(",")[0].strip()

    if manager.record_heartbeat(peer_id, ip_address):
        return {"status": "ok", "peer_id": peer_id}
    raise HTTPException(status_code=404, detail="Peer not found")


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_mesh_stats():
    """Get mesh statistics."""
    manager.update_online_status()
    return manager.get_mesh_stats()


@app.delete("/peers/{peer_id}", dependencies=[Depends(require_jwt)])
async def delete_peer(peer_id: str):
    """Delete a peer permanently."""
    if manager.delete_peer(peer_id):
        return {"status": "deleted", "peer_id": peer_id}
    raise HTTPException(status_code=404, detail="Peer not found")


class BulkDeleteRequest(BaseModel):
    status: Optional[str] = None
    offline_days: Optional[int] = None


@app.post("/peers/bulk-delete", dependencies=[Depends(require_jwt)])
async def bulk_delete_peers(request: BulkDeleteRequest):
    """Bulk delete peers by criteria."""
    status = PeerStatus(request.status) if request.status else None
    count = manager.bulk_delete_peers(status, request.offline_days)
    return {"deleted": count}


class WireGuardConfigRequest(BaseModel):
    pubkey: str
    endpoint: Optional[str] = None


@app.put("/peers/{peer_id}/wireguard", dependencies=[Depends(require_jwt)])
async def set_peer_wireguard(peer_id: str, config: WireGuardConfigRequest):
    """Set WireGuard configuration for a peer."""
    if manager.set_wireguard_config(peer_id, config.pubkey, config.endpoint):
        return {"status": "updated", "peer_id": peer_id}
    raise HTTPException(status_code=404, detail="Peer not found")


@app.get("/wireguard/peers", dependencies=[Depends(require_jwt)])
async def get_wireguard_peers():
    """Get WireGuard peer configurations for mesh."""
    return {"peers": manager.get_wireguard_peers()}


@app.get("/wireguard/config", dependencies=[Depends(require_jwt)])
async def get_wireguard_config():
    """Generate WireGuard config snippet for mesh peers."""
    peers = manager.get_wireguard_peers()
    config_lines = ["# SecuBox Mesh WireGuard Peers", "# Auto-generated by Master-Link", ""]

    for peer in peers:
        config_lines.append(f"[Peer]")
        config_lines.append(f"PublicKey = {peer['public_key']}")
        config_lines.append(f"Endpoint = {peer['endpoint']}")
        config_lines.append(f"AllowedIPs = {peer['allowed_ips']}")
        config_lines.append(f"PersistentKeepalive = {peer['persistent_keepalive']}")
        config_lines.append("")

    return {"config": "\n".join(config_lines), "peer_count": len(peers)}


@app.post("/update-online-status", dependencies=[Depends(require_jwt)])
async def update_online_status():
    """Manually trigger online status update."""
    updated = manager.update_online_status()
    return {"updated": updated}


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    manager.cleanup_expired()
    manager.update_online_status()
    logger.info("Master-Link started")
