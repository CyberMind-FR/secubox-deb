# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: crypto
Real Ed25519 signing/verification + DID derivation + canonical serialization.

Mirrors the approach used in packages/secubox-identity/api/main.py:
  - did:plc:<sha256(pubkey_raw)[:32]>
  - cryptography.hazmat.primitives.asymmetric.ed25519 for keys
  - Raw (32-byte) key format for portability

NIZK interface
--------------
MembershipProver and verify_nizk provide a PLUGGABLE interface for zero-knowledge
non-revoked membership proofs.

v0 implementation (log-state membership):
  - Returns membership = "in members set AND NOT in revoked set"
  - Clearly marked TODO for binding to GK·HAM ZKP-HAM-v1
    (packages/zkp-hamiltonian) once the C-to-Python cffi/socket bridge exists.

PSI interface:
  - psi_intersection_exists() is a stub returning set-intersection truth
  - TODO: bind to a CSPN-acceptable PSI scheme (ECDH-DH or OPRF-based)
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional, Set

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair.

    Returns:
        (priv_bytes_raw, pub_bytes_raw) — each 32 bytes.
    """
    priv_key = _ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    priv_raw = priv_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_raw, pub_raw


# ---------------------------------------------------------------------------
# Signing and verification
# ---------------------------------------------------------------------------

def sign(priv_bytes: bytes, msg: bytes) -> str:
    """Sign *msg* with the given raw Ed25519 private key bytes.

    Args:
        priv_bytes: 32-byte raw private key.
        msg: arbitrary bytes to sign.

    Returns:
        128-char lowercase hex string (64-byte Ed25519 signature).
    """
    priv_key = _ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    sig_bytes = priv_key.sign(msg)
    return sig_bytes.hex()


def public_from_private(priv_bytes: bytes) -> bytes:
    """Derive the raw 32-byte Ed25519 public key from a raw private key.

    Used by node bootstrap (genesis) where only the persisted private key is
    held: the DID and the offer-signing pubkey are both derived from it, so the
    node never needs to store its public key separately.

    Args:
        priv_bytes: 32-byte raw private key.

    Returns:
        32-byte raw public key.
    """
    priv_key = _ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    return priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def verify(pub_hex: str, msg: bytes, sig_hex: str) -> bool:
    """Verify an Ed25519 signature.

    Args:
        pub_hex: hex-encoded raw 32-byte Ed25519 public key.
        msg: the original message bytes.
        sig_hex: hex-encoded 64-byte signature.

    Returns:
        True if valid, False on any failure (wrong key, tampered sig/msg).
    """
    try:
        pub_bytes = bytes.fromhex(pub_hex)
        sig_bytes = bytes.fromhex(sig_hex)
        pub_key = _ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, msg)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# DID derivation — mirrors secubox-identity exactly
# ---------------------------------------------------------------------------

def did_from_pubkey(pub_bytes: bytes) -> str:
    """Derive a self-certifying DID from a raw Ed25519 public key.

    Formula (from packages/secubox-identity/api/main.py::generate_did):
        did:plc:<sha256(pub_bytes).hexdigest()[:32]>

    The name IS the hash of the key — no directory is needed to bind name
    to key.  This is the intrinsic self-certification property.

    Args:
        pub_bytes: 32-byte raw Ed25519 public key.

    Returns:
        String of the form "did:plc:<32 lowercase hex chars>".
    """
    fingerprint = hashlib.sha256(pub_bytes).hexdigest()[:32]
    return f"did:plc:{fingerprint}"


# ---------------------------------------------------------------------------
# Canonical serialization (for signing and hashing)
# ---------------------------------------------------------------------------

def canonical_bytes(obj: Dict[str, Any]) -> bytes:
    """Deterministic JSON serialization of a dict.

    Rules:
      - Keys sorted lexicographically (sort_keys=True)
      - No extra whitespace (separators=(",", ":"))
      - UTF-8 encoded

    This is used for both signing (producing the bytes to sign) and hashing
    (producing the bytes for compute_entry_hash).  Any dict with the same
    logical content yields the same bytes regardless of insertion order.

    Args:
        obj: a JSON-serializable dict.

    Returns:
        UTF-8 bytes of the canonical JSON string.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# NIZK interface — PLUGGABLE membership proof
# ---------------------------------------------------------------------------

class MembershipProver:
    """Interface for a zero-knowledge non-revoked membership prover.

    v0 default: log-state membership (non-revoked = in members AND NOT in revoked).

    # TODO: bind to GK·HAM ZKP-HAM-v1 (packages/zkp-hamiltonian/include/zkp_hamiltonian.h)
    #       via cffi or a thin Unix-socket verifier daemon.
    #       The revocation structure must be mapped to the public graph G so that
    #       revoking a member destroys their provable Hamiltonian cycle (they can
    #       no longer produce a valid proof).
    #       Soundness target: ≥ 1 − 2⁻¹²⁸ (GK-HAM-2025 Fiat-Shamir, SHA3-256).
    """

    def prove(self, subject_did: str, domain: str, log_state: Dict) -> Optional[bytes]:
        """Produce a membership proof (v0: always None — proof IS the log state)."""
        # v0: proof is implicit in the log state; no bytes needed
        return None

    def verify(
        self,
        proof: Optional[bytes],
        domain: str,
        subject_did: str,
        log_state: Dict,
    ) -> bool:
        """Verify a membership proof.

        v0: checks log_state["members"] and ["revoked"] sets directly.
        ZKP-HAM-v1: would verify a Hamiltonian NIZK without revealing the key.
        """
        return verify_nizk(proof, domain, subject_did, log_state)


def verify_nizk(
    proof: Optional[bytes],
    domain: str,
    subject_did: str,
    log_state: Dict,
) -> bool:
    """Verify non-revoked membership for *subject_did* in *domain*.

    v0 implementation — log-state membership:
      Returns True iff subject_did is in log_state["members"] AND NOT in
      log_state["revoked"].

    # TODO: bind to GK·HAM ZKP-HAM-v1 (packages/zkp-hamiltonian) — v0 = log-state
    #       membership.  The ZKP proves "I am a non-revoked member of the trust graph"
    #       WITHOUT revealing which key.  Map the revocation structure → public graph G;
    #       revoking a member removes the cycle so they can no longer prove.

    Args:
        proof: opaque proof bytes (v0: ignored).
        domain: isolation_domain string.
        subject_did: the DID to check membership for.
        log_state: dict with keys "members" (Set[str]) and "revoked" (Set[str]).

    Returns:
        True if non-revoked member, False otherwise.
    """
    members: Set[str] = log_state.get("members", set())
    revoked: Set[str] = log_state.get("revoked", set())
    return (subject_did in members) and (subject_did not in revoked)


# ---------------------------------------------------------------------------
# PSI interface stub — Private Set Intersection for proximity-as-trust
# ---------------------------------------------------------------------------

def psi_intersection_exists(
    my_domains: Set[str],
    their_domains: Set[str],
) -> bool:
    """Stub: does an intersection exist between two sets of isolation_domains?

    v0: plain set intersection (no privacy — reveals both sets).

    # TODO: replace with a CSPN-acceptable PSI scheme (ECDH-DH or OPRF-based)
    #       that reveals only "yes/no" — never the actual positions or full sets.
    #       See spec §5.2: "Same zone? yes/no — never 'where.'"
    #       Implementation choice (ECDH-DH vs OPRF) is a human governance decision
    #       (spec §8, open item 1).

    Args:
        my_domains: set of isolation_domain strings for this node.
        their_domains: set of isolation_domain strings for the peer.

    Returns:
        True if at least one domain is shared.
    """
    return bool(my_domains & their_domains)
