"""SecuBox Identity - Decentralized Identity Management
DID generation, keypair management, and trust scoring for mesh nodes.

Identity format: did:plc:<fingerprint>
Trust levels: verified, trusted, neutral, suspicious, untrusted

Enhanced features:
- Key import/export with optional encryption
- Trust score federation between peers
- Key expiration handling
- Multi-key support (primary, backup, signing)
"""
import os
import json
import hashlib
import subprocess
import logging
import base64
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration
CONFIG_PATH = Path("/etc/secubox/identity.toml")
KEYS_DIR = Path("/var/lib/secubox/identity/keys")
PEERS_DIR = Path("/var/lib/secubox/identity/peers")
TRUST_FILE = Path("/var/lib/secubox/identity/trust.json")
TRUST_HISTORY_FILE = Path("/var/lib/secubox/identity/trust_history.jsonl")

# Key expiration default (2 years)
DEFAULT_KEY_EXPIRY_DAYS = 730

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
    key_type: str = "ed25519"
    version: int = 1


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
    federated_scores: Dict[str, int] = {}  # DID -> their score for this peer
    capabilities: List[str] = []


class TrustUpdate(BaseModel):
    trust_level: Optional[TrustLevel] = None
    trust_score: Optional[int] = Field(default=None, ge=0, le=100)
    reason: Optional[str] = None


class TrustFederation(BaseModel):
    """Trust score shared from another peer."""
    from_did: str
    for_did: str
    score: int = Field(ge=0, le=100)
    reason: Optional[str] = None
    timestamp: str
    signature: str


class KeyExport(BaseModel):
    """Exported key bundle."""
    did: str
    public_key: str
    private_key_encrypted: Optional[str] = None  # Encrypted with passphrase
    identity_document: Dict[str, Any]
    exported_at: str
    salt: Optional[str] = None  # For key derivation


class KeyImport(BaseModel):
    """Import key bundle."""
    key_data: str  # JSON string or base64
    passphrase: Optional[str] = None


class IdentityManager:
    """Manages local identity and peer trust."""

    def __init__(self, keys_dir: Path, peers_dir: Path, trust_file: Path):
        self.keys_dir = keys_dir
        self.peers_dir = peers_dir
        self.trust_file = trust_file
        self.trust_history_file = trust_file.parent / "trust_history.jsonl"
        self._ensure_dirs()
        self._local_identity: Optional[IdentityDocument] = None
        self._private_key: Optional[ed25519.Ed25519PrivateKey] = None
        self._key_cache: Dict[str, ed25519.Ed25519PrivateKey] = {}

    def _ensure_dirs(self):
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.peers_dir.mkdir(parents=True, exist_ok=True)
        self.trust_file.parent.mkdir(parents=True, exist_ok=True)

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        """Derive encryption key from passphrase using scrypt."""
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))

    def _encrypt_key(self, private_bytes: bytes, passphrase: str) -> Tuple[str, str]:
        """Encrypt private key with passphrase."""
        salt = secrets.token_bytes(16)
        key = self._derive_key(passphrase, salt)
        f = Fernet(key)
        encrypted = f.encrypt(private_bytes)
        return base64.b64encode(encrypted).decode(), base64.b64encode(salt).decode()

    def _decrypt_key(self, encrypted_data: str, passphrase: str, salt: str) -> bytes:
        """Decrypt private key with passphrase."""
        salt_bytes = base64.b64decode(salt)
        key = self._derive_key(passphrase, salt_bytes)
        f = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_data)
        return f.decrypt(encrypted_bytes)

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

    def is_key_expired(self, identity: Optional[IdentityDocument] = None) -> bool:
        """Check if identity key is expired."""
        if identity is None:
            identity = self._local_identity
        if not identity or not identity.expires_at:
            return False
        try:
            expires = datetime.fromisoformat(identity.expires_at.replace("Z", "+00:00"))
            return datetime.utcnow().replace(tzinfo=expires.tzinfo) > expires
        except Exception:
            return False

    def get_key_expiry_days(self, identity: Optional[IdentityDocument] = None) -> int:
        """Get days until key expires, -1 if no expiry, 0 if expired."""
        if identity is None:
            identity = self._local_identity
        if not identity or not identity.expires_at:
            return -1
        try:
            expires = datetime.fromisoformat(identity.expires_at.replace("Z", "+00:00"))
            now = datetime.utcnow().replace(tzinfo=expires.tzinfo)
            delta = expires - now
            return max(0, delta.days)
        except Exception:
            return -1

    def export_identity(self, passphrase: Optional[str] = None) -> KeyExport:
        """Export identity for backup/migration."""
        identity = self.get_or_create_identity()

        export_data = KeyExport(
            did=identity.did,
            public_key=identity.public_key,
            identity_document=identity.model_dump(),
            exported_at=datetime.utcnow().isoformat() + "Z"
        )

        if passphrase:
            # Export encrypted private key
            if not self._private_key:
                self._private_key = self.load_keypair()
            if self._private_key:
                private_bytes = self._private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                encrypted, salt = self._encrypt_key(private_bytes, passphrase)
                export_data.private_key_encrypted = encrypted
                export_data.salt = salt

        return export_data

    def import_identity(self, key_import: KeyImport) -> IdentityDocument:
        """Import identity from backup."""
        try:
            # Parse key data
            key_data = json.loads(key_import.key_data)
        except json.JSONDecodeError:
            # Try base64 decode
            try:
                decoded = base64.b64decode(key_import.key_data)
                key_data = json.loads(decoded)
            except Exception:
                raise ValueError("Invalid key data format")

        # Verify required fields
        if "did" not in key_data or "public_key" not in key_data:
            raise ValueError("Missing required fields in key data")

        # Import private key if provided
        if key_data.get("private_key_encrypted") and key_import.passphrase:
            if not key_data.get("salt"):
                raise ValueError("Missing salt for encrypted key")

            try:
                private_bytes = self._decrypt_key(
                    key_data["private_key_encrypted"],
                    key_import.passphrase,
                    key_data["salt"]
                )
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)

                # Verify the key matches the public key
                public_bytes = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
                if public_bytes.hex() != key_data["public_key"]:
                    raise ValueError("Private key does not match public key")

                # Save keypair
                self.save_keypair(private_key)
                self._private_key = private_key
            except Exception as e:
                raise ValueError(f"Failed to decrypt private key: {e}")

        # Build identity document
        identity_data = key_data.get("identity_document", {})
        identity = IdentityDocument(
            did=key_data["did"],
            public_key=key_data["public_key"],
            hostname=identity_data.get("hostname", self._get_hostname()),
            created_at=identity_data.get("created_at", datetime.utcnow().isoformat() + "Z"),
            expires_at=identity_data.get("expires_at"),
            capabilities=identity_data.get("capabilities", ["mesh", "p2p", "waf"]),
            signature=identity_data.get("signature")
        )

        # Save identity
        identity_file = self.keys_dir / "identity.json"
        with open(identity_file, "w") as f:
            json.dump(identity.model_dump(), f, indent=2)

        self._local_identity = identity
        return identity

    # Trust Federation
    def receive_trust_federation(self, federation: TrustFederation) -> bool:
        """Receive and process trust score from another peer."""
        # Verify the federation message signature
        message = json.dumps({
            "from_did": federation.from_did,
            "for_did": federation.for_did,
            "score": federation.score,
            "timestamp": federation.timestamp
        })

        # Get the sending peer's public key
        sender = self.get_peer(federation.from_did)
        if not sender:
            logger.warning(f"Unknown federation sender: {federation.from_did}")
            return False

        if not self.verify(message, federation.signature, sender.public_key):
            logger.warning(f"Invalid federation signature from {federation.from_did}")
            return False

        # Update the target peer's federated scores
        target = self.get_peer(federation.for_did)
        if not target:
            logger.info(f"Federation target not found locally: {federation.for_did}")
            return False

        target.federated_scores[federation.from_did] = federation.score

        # Recalculate trust score using weighted average
        self._recalculate_trust_score(target)

        # Log federation
        self._log_trust_event(federation)

        self.save_peer(target)
        return True

    def create_trust_federation(self, for_did: str, score: int, reason: Optional[str] = None) -> TrustFederation:
        """Create a signed trust federation message to share with peers."""
        identity = self.get_or_create_identity()
        timestamp = datetime.utcnow().isoformat() + "Z"

        message = json.dumps({
            "from_did": identity.did,
            "for_did": for_did,
            "score": score,
            "timestamp": timestamp
        })

        signature = self.sign(message)

        return TrustFederation(
            from_did=identity.did,
            for_did=for_did,
            score=score,
            reason=reason,
            timestamp=timestamp,
            signature=signature
        )

    def _recalculate_trust_score(self, peer: PeerIdentity):
        """Recalculate trust score using local and federated scores."""
        if not peer.federated_scores:
            return

        # Weight: local score is 60%, federated is 40%
        local_weight = 0.6
        federated_weight = 0.4

        # Average federated scores, weighted by sender trust
        federated_total = 0
        federated_count = 0

        for sender_did, score in peer.federated_scores.items():
            sender = self.get_peer(sender_did)
            if sender and sender.trust_level in [TrustLevel.VERIFIED, TrustLevel.TRUSTED]:
                # Trusted senders get full weight
                federated_total += score
                federated_count += 1
            elif sender and sender.trust_level == TrustLevel.NEUTRAL:
                # Neutral senders get half weight
                federated_total += score * 0.5
                federated_count += 0.5

        if federated_count > 0:
            federated_avg = federated_total / federated_count
            peer.trust_score = int(peer.trust_score * local_weight + federated_avg * federated_weight)

    def _log_trust_event(self, federation: TrustFederation):
        """Log trust federation event."""
        try:
            with open(self.trust_history_file, "a") as f:
                f.write(json.dumps({
                    "type": "federation",
                    "from": federation.from_did,
                    "for": federation.for_did,
                    "score": federation.score,
                    "timestamp": federation.timestamp
                }) + "\n")
        except Exception as e:
            logger.warning(f"Failed to log trust event: {e}")

    def get_trust_history(self, limit: int = 100) -> List[Dict]:
        """Get recent trust history events."""
        events = []
        if not self.trust_history_file.exists():
            return events

        try:
            with open(self.trust_history_file) as f:
                lines = f.readlines()
            for line in lines[-limit:]:
                try:
                    events.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            logger.warning(f"Failed to read trust history: {e}")

        return events

    def get_trust_summary(self) -> Dict[str, Any]:
        """Get summary of trust relationships."""
        peers = self.list_peers()

        summary = {
            "total_peers": len(peers),
            "by_trust_level": {
                "verified": 0,
                "trusted": 0,
                "neutral": 0,
                "suspicious": 0,
                "untrusted": 0
            },
            "avg_trust_score": 0,
            "with_federated_scores": 0
        }

        total_score = 0
        for peer in peers:
            summary["by_trust_level"][peer.trust_level.value] += 1
            total_score += peer.trust_score
            if peer.federated_scores:
                summary["with_federated_scores"] += 1

        if peers:
            summary["avg_trust_score"] = round(total_score / len(peers), 1)

        return summary


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
async def export_identity_public():
    """Export identity for backup/migration (public key only)."""
    identity = identity_manager.get_or_create_identity()

    return {
        "identity": identity,
        "peers": identity_manager.list_peers(),
        "exported_at": datetime.utcnow().isoformat() + "Z"
    }


@app.post("/export/encrypted", dependencies=[Depends(require_jwt)])
async def export_identity_encrypted(passphrase: str):
    """Export identity with encrypted private key for full backup."""
    if len(passphrase) < 8:
        raise HTTPException(status_code=400, detail="Passphrase must be at least 8 characters")

    export_data = identity_manager.export_identity(passphrase)
    return export_data


@app.post("/import", dependencies=[Depends(require_jwt)])
async def import_identity(key_import: KeyImport):
    """Import identity from backup."""
    try:
        identity = identity_manager.import_identity(key_import)
        return {"status": "imported", "identity": identity}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/expiry", dependencies=[Depends(require_jwt)])
async def check_key_expiry():
    """Check key expiration status."""
    identity = identity_manager.get_or_create_identity()
    expired = identity_manager.is_key_expired(identity)
    days_remaining = identity_manager.get_key_expiry_days(identity)

    return {
        "did": identity.did,
        "created_at": identity.created_at,
        "expires_at": identity.expires_at,
        "expired": expired,
        "days_remaining": days_remaining,
        "needs_rotation": days_remaining >= 0 and days_remaining < 30
    }


# Trust Federation Endpoints
@app.post("/federation/receive", dependencies=[Depends(require_jwt)])
async def receive_federation(federation: TrustFederation):
    """Receive trust federation from another peer."""
    success = identity_manager.receive_trust_federation(federation)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to process federation")
    return {"status": "accepted"}


class CreateFederationRequest(BaseModel):
    for_did: str
    score: int = Field(ge=0, le=100)
    reason: Optional[str] = None


@app.post("/federation/create", dependencies=[Depends(require_jwt)])
async def create_federation(request: CreateFederationRequest):
    """Create a signed trust federation to share with peers."""
    federation = identity_manager.create_trust_federation(
        request.for_did, request.score, request.reason
    )
    return federation


@app.get("/trust/summary", dependencies=[Depends(require_jwt)])
async def trust_summary():
    """Get trust relationship summary."""
    return identity_manager.get_trust_summary()


@app.get("/trust/history", dependencies=[Depends(require_jwt)])
async def trust_history(limit: int = 100):
    """Get trust federation history."""
    events = identity_manager.get_trust_history(limit)
    return {"events": events, "count": len(events)}


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    PEERS_DIR.mkdir(parents=True, exist_ok=True)

    # Pre-generate identity if needed
    identity = identity_manager.get_or_create_identity()

    # Check for key expiration warning
    days = identity_manager.get_key_expiry_days(identity)
    if days >= 0 and days < 30:
        logger.warning(f"Identity key expires in {days} days - rotation recommended")
    elif days == 0:
        logger.error("Identity key has EXPIRED - rotation required")

    logger.info(f"Identity service started: {identity.did}")
