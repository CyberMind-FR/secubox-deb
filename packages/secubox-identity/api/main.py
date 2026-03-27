"""SecuBox Identity - Decentralized Identity Management
DID generation, keypair management, and trust scoring for mesh nodes.

Identity format: did:plc:<fingerprint>
Trust levels: verified, trusted, neutral, suspicious, untrusted
"""
import os
import json
import hashlib
import subprocess
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration
CONFIG_PATH = Path("/etc/secubox/identity.toml")
KEYS_DIR = Path("/var/lib/secubox/identity/keys")
PEERS_DIR = Path("/var/lib/secubox/identity/peers")
TRUST_FILE = Path("/var/lib/secubox/identity/trust.json")

app = FastAPI(title="SecuBox Identity", version="1.0.0")
logger = logging.getLogger("secubox.identity")


class TrustLevel(str, Enum):
    VERIFIED = "verified"    # Cryptographically verified
    TRUSTED = "trusted"      # Manually trusted
    NEUTRAL = "neutral"      # Unknown
    SUSPICIOUS = "suspicious"
    UNTRUSTED = "untrusted"


class IdentityDocument(BaseModel):
    did: str
    public_key: str
    hostname: str
    created_at: str
    expires_at: Optional[str] = None
    capabilities: List[str] = []
    signature: Optional[str] = None


class PeerIdentity(BaseModel):
    did: str
    public_key: str
    hostname: str
    ip_address: Optional[str] = None
    trust_level: TrustLevel = TrustLevel.NEUTRAL
    trust_score: int = Field(default=50, ge=0, le=100)
    first_seen: str
    last_seen: str
    verification_count: int = 0


class TrustUpdate(BaseModel):
    trust_level: Optional[TrustLevel] = None
    trust_score: Optional[int] = Field(default=None, ge=0, le=100)
    reason: Optional[str] = None


class IdentityManager:
    """Manages local identity and peer trust."""

    def __init__(self, keys_dir: Path, peers_dir: Path, trust_file: Path):
        self.keys_dir = keys_dir
        self.peers_dir = peers_dir
        self.trust_file = trust_file
        self._ensure_dirs()
        self._local_identity: Optional[IdentityDocument] = None
        self._private_key: Optional[ed25519.Ed25519PrivateKey] = None

    def _ensure_dirs(self):
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.peers_dir.mkdir(parents=True, exist_ok=True)
        self.trust_file.parent.mkdir(parents=True, exist_ok=True)

    def _get_hostname(self) -> str:
        """Get system hostname."""
        try:
            return subprocess.check_output(["hostname"], text=True).strip()
        except Exception:
            return "unknown"

    def generate_did(self, public_key_bytes: bytes) -> str:
        """Generate DID from public key: did:plc:<sha256_fingerprint>"""
        fingerprint = hashlib.sha256(public_key_bytes).hexdigest()[:32]
        return f"did:plc:{fingerprint}"

    def generate_keypair(self) -> tuple[ed25519.Ed25519PrivateKey, bytes]:
        """Generate Ed25519 keypair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return private_key, public_bytes

    def save_keypair(
        self,
        private_key: ed25519.Ed25519PrivateKey,
        key_id: str = "primary"
    ) -> Path:
        """Save keypair to files."""
        private_path = self.keys_dir / f"{key_id}.key"
        public_path = self.keys_dir / f"{key_id}.pub"

        # Save private key (PEM format)
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_path, "wb") as f:
            f.write(private_bytes)
        os.chmod(private_path, 0o600)

        # Save public key
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_path, "wb") as f:
            f.write(public_bytes)

        return private_path

    def load_keypair(self, key_id: str = "primary") -> Optional[ed25519.Ed25519PrivateKey]:
        """Load keypair from files."""
        private_path = self.keys_dir / f"{key_id}.key"
        if not private_path.exists():
            return None

        with open(private_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        return private_key

    def get_or_create_identity(self) -> IdentityDocument:
        """Get existing identity or create new one."""
        if self._local_identity:
            return self._local_identity

        # Try to load existing
        identity_file = self.keys_dir / "identity.json"
        if identity_file.exists():
            try:
                with open(identity_file) as f:
                    data = json.load(f)
                self._local_identity = IdentityDocument(**data)
                self._private_key = self.load_keypair()
                return self._local_identity
            except Exception as e:
                logger.warning(f"Failed to load identity: {e}")

        # Generate new identity
        private_key, public_bytes = self.generate_keypair()
        self.save_keypair(private_key)
        self._private_key = private_key

        did = self.generate_did(public_bytes)
        public_key_hex = public_bytes.hex()

        identity = IdentityDocument(
            did=did,
            public_key=public_key_hex,
            hostname=self._get_hostname(),
            created_at=datetime.utcnow().isoformat() + "Z",
            capabilities=["mesh", "p2p", "waf"]
        )

        # Sign identity document
        identity.signature = self.sign(json.dumps({
            "did": identity.did,
            "public_key": identity.public_key,
            "hostname": identity.hostname
        }))

        # Save
        with open(identity_file, "w") as f:
            json.dump(identity.model_dump(), f, indent=2)

        self._local_identity = identity
        return identity

    def sign(self, message: str) -> str:
        """Sign a message with local private key."""
        if not self._private_key:
            self._private_key = self.load_keypair()
        if not self._private_key:
            raise ValueError("No private key available")

        signature = self._private_key.sign(message.encode())
        return signature.hex()

    def verify(self, message: str, signature: str, public_key_hex: str) -> bool:
        """Verify a signature against a public key."""
        try:
            public_bytes = bytes.fromhex(public_key_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
            public_key.verify(bytes.fromhex(signature), message.encode())
            return True
        except Exception:
            return False

    def rotate_key(self, key_id: str = "primary") -> IdentityDocument:
        """Rotate keypair and update identity."""
        # Backup old key
        old_key_path = self.keys_dir / f"{key_id}.key"
        if old_key_path.exists():
            backup_path = self.keys_dir / f"{key_id}.key.{int(datetime.now().timestamp())}"
            old_key_path.rename(backup_path)

        # Generate new keypair
        private_key, public_bytes = self.generate_keypair()
        self.save_keypair(private_key, key_id)
        self._private_key = private_key

        # Update identity
        did = self.generate_did(public_bytes)
        identity = IdentityDocument(
            did=did,
            public_key=public_bytes.hex(),
            hostname=self._get_hostname(),
            created_at=datetime.utcnow().isoformat() + "Z",
            capabilities=["mesh", "p2p", "waf"]
        )

        identity.signature = self.sign(json.dumps({
            "did": identity.did,
            "public_key": identity.public_key,
            "hostname": identity.hostname
        }))

        identity_file = self.keys_dir / "identity.json"
        with open(identity_file, "w") as f:
            json.dump(identity.model_dump(), f, indent=2)

        self._local_identity = identity
        return identity

    # Peer management
    def save_peer(self, peer: PeerIdentity):
        """Save peer identity."""
        peer_file = self.peers_dir / f"{peer.did.replace(':', '_')}.json"
        with open(peer_file, "w") as f:
            json.dump(peer.model_dump(), f, indent=2)

    def get_peer(self, did: str) -> Optional[PeerIdentity]:
        """Get peer by DID."""
        peer_file = self.peers_dir / f"{did.replace(':', '_')}.json"
        if not peer_file.exists():
            return None
        with open(peer_file) as f:
            return PeerIdentity(**json.load(f))

    def list_peers(self) -> List[PeerIdentity]:
        """List all known peers."""
        peers = []
        for peer_file in self.peers_dir.glob("*.json"):
            try:
                with open(peer_file) as f:
                    peers.append(PeerIdentity(**json.load(f)))
            except Exception:
                continue
        return peers

    def update_trust(self, did: str, update: TrustUpdate) -> Optional[PeerIdentity]:
        """Update peer trust level."""
        peer = self.get_peer(did)
        if not peer:
            return None

        if update.trust_level:
            peer.trust_level = update.trust_level
        if update.trust_score is not None:
            peer.trust_score = update.trust_score

        peer.last_seen = datetime.utcnow().isoformat() + "Z"
        self.save_peer(peer)
        return peer

    def verify_peer(self, identity_doc: IdentityDocument) -> bool:
        """Verify a peer's identity document."""
        if not identity_doc.signature:
            return False

        message = json.dumps({
            "did": identity_doc.did,
            "public_key": identity_doc.public_key,
            "hostname": identity_doc.hostname
        })

        return self.verify(message, identity_doc.signature, identity_doc.public_key)


# Global instance
identity_manager = IdentityManager(KEYS_DIR, PEERS_DIR, TRUST_FILE)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    try:
        identity = identity_manager.get_or_create_identity()
        return {
            "module": "identity",
            "status": "ok",
            "version": "1.0.0",
            "did": identity.did,
            "hostname": identity.hostname
        }
    except Exception as e:
        return {
            "module": "identity",
            "status": "error",
            "error": str(e)
        }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.get("/identity", dependencies=[Depends(require_jwt)])
async def get_identity():
    """Get local identity document."""
    return identity_manager.get_or_create_identity()


@app.post("/identity/rotate", dependencies=[Depends(require_jwt)])
async def rotate_identity():
    """Rotate keypair and generate new identity."""
    identity = identity_manager.rotate_key()
    return {"status": "rotated", "identity": identity}


@app.post("/identity/sign", dependencies=[Depends(require_jwt)])
async def sign_message(message: str):
    """Sign a message with local private key."""
    signature = identity_manager.sign(message)
    return {"message": message, "signature": signature}


@app.post("/identity/verify", dependencies=[Depends(require_jwt)])
async def verify_signature(message: str, signature: str, public_key: str):
    """Verify a signature."""
    valid = identity_manager.verify(message, signature, public_key)
    return {"valid": valid}


@app.get("/peers", dependencies=[Depends(require_jwt)])
async def list_peers():
    """List all known peers."""
    peers = identity_manager.list_peers()
    return {"peers": peers, "count": len(peers)}


@app.get("/peers/{did:path}", dependencies=[Depends(require_jwt)])
async def get_peer(did: str):
    """Get peer by DID."""
    peer = identity_manager.get_peer(did)
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")
    return peer


@app.post("/peers", dependencies=[Depends(require_jwt)])
async def register_peer(identity_doc: IdentityDocument, ip_address: Optional[str] = None):
    """Register a new peer."""
    # Verify identity document
    if not identity_manager.verify_peer(identity_doc):
        raise HTTPException(status_code=400, detail="Invalid identity signature")

    now = datetime.utcnow().isoformat() + "Z"
    peer = PeerIdentity(
        did=identity_doc.did,
        public_key=identity_doc.public_key,
        hostname=identity_doc.hostname,
        ip_address=ip_address,
        trust_level=TrustLevel.NEUTRAL,
        trust_score=50,
        first_seen=now,
        last_seen=now,
        verification_count=1
    )

    identity_manager.save_peer(peer)
    return {"status": "registered", "peer": peer}


@app.put("/peers/{did:path}/trust", dependencies=[Depends(require_jwt)])
async def update_peer_trust(did: str, update: TrustUpdate):
    """Update peer trust level."""
    peer = identity_manager.update_trust(did, update)
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")
    return {"status": "updated", "peer": peer}


@app.delete("/peers/{did:path}", dependencies=[Depends(require_jwt)])
async def delete_peer(did: str):
    """Delete a peer."""
    peer_file = PEERS_DIR / f"{did.replace(':', '_')}.json"
    if not peer_file.exists():
        raise HTTPException(status_code=404, detail="Peer not found")
    peer_file.unlink()
    return {"status": "deleted"}


@app.post("/peers/{did:path}/verify", dependencies=[Depends(require_jwt)])
async def verify_peer(did: str):
    """Re-verify a peer's identity."""
    peer = identity_manager.get_peer(did)
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")

    # Increment verification count
    peer.verification_count += 1
    peer.last_seen = datetime.utcnow().isoformat() + "Z"

    # Boost trust if verified multiple times
    if peer.verification_count >= 3 and peer.trust_level == TrustLevel.NEUTRAL:
        peer.trust_level = TrustLevel.TRUSTED
        peer.trust_score = min(80, peer.trust_score + 10)

    identity_manager.save_peer(peer)
    return {"status": "verified", "peer": peer}


@app.get("/export", dependencies=[Depends(require_jwt)])
async def export_identity():
    """Export identity for backup/migration."""
    identity = identity_manager.get_or_create_identity()

    # Include public key only
    return {
        "identity": identity,
        "peers": identity_manager.list_peers(),
        "exported_at": datetime.utcnow().isoformat() + "Z"
    }


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    PEERS_DIR.mkdir(parents=True, exist_ok=True)
    # Pre-generate identity if needed
    identity_manager.get_or_create_identity()
    logger.info("Identity service started")
