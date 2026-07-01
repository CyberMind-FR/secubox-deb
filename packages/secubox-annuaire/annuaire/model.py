# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: model
Annuaire·Miroir — the trust substrate's ontology-lite object set.

Every object is:
  - signed (Ed25519 sig + signer_did),
  - timestamped (RFC 3339, CSPN requirement),
  - chainable (each LogEntry carries prev_hash + entry_hash, BLAKE2b-256).

Access is resolved exclusively by can() in annuaire.resolver.
No object grants rights by its mere existence.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# RFC 3339 timestamp helper (CSPN logging requirement)
# ---------------------------------------------------------------------------

def now_rfc3339() -> str:
    """Return the current UTC time as an RFC 3339 string."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# ENUMS — explicit, closed vocabularies
# ---------------------------------------------------------------------------

class MemberState(str, Enum):
    """The membership state machine.

    AUTO-ADD lands in OBSERVED; an accepted Invitation promotes to MEMBER;
    any RevocationNotice drives to REVOKED.  There is no silent upgrade from
    OBSERVED to MEMBER — only an accepted Invitation does it.
    """
    OBSERVED = "observed"   # seen via gossip; quarantined; NO standing
    MEMBER   = "member"     # invited & grafted; has standing under a domain
    REVOKED  = "revoked"    # membership withdrawn; detectable, never deleted


class Op(str, Enum):
    """Log operation types — the four verbs plus bookkeeping."""
    GENESIS        = "genesis"      # founder self-attests MEMBER (root of trust)
    AUTO_ADD       = "auto_add"
    INVITE_ISSUE   = "invite_issue"
    INVITE_ACCEPT  = "invite_accept"
    ATTEST         = "attest"
    REVOKE         = "revoke"
    PROPOSAL_OPEN  = "proposal_open"
    PROPOSAL_VOTE  = "proposal_vote"
    PROPOSAL_CLOSE = "proposal_close"
    EMANCIPATE     = "emancipate"
    WITNESS        = "witness"
    NAME_BIND      = "name_bind"    # Gondwana human name → did:plc binding
    NAME_REVOKE    = "name_revoke"
    SERVICE_OFFER        = "service_offer"
    SERVICE_REVOKE_OFFER = "service_revoke_offer"
    SERVICE_SUBSCRIBE    = "service_subscribe"
    SERVICE_APPROVE      = "service_approve"
    SERVICE_REJECT       = "service_reject"
    SERVICE_REVOKE_SUB   = "service_revoke_sub"
    # Gondwana P1 directory (#768): the annuaire is the distributed directory.
    NODE_PUBLISH         = "node_publish"     # signed mesh peer registry entry
    CONFIG_PUBLISH       = "config_publish"   # signed, versioned config distribution
    CONFIG_REVOKE        = "config_revoke"


class ProposalType(str, Enum):
    CHANGE_PROTOCOL  = "change_protocol"
    QUORUM_REVISION  = "quorum_revision"
    ADD_ANCHOR       = "add_anchor"
    REMOVE_ANCHOR    = "remove_anchor"
    EMANCIPATION     = "emancipation"
    ADD_WITNESS      = "add_witness"
    REMOVE_WITNESS   = "remove_witness"


class QuorumRule(str, Enum):
    """ANTI-PLUTOCRACY.  Default is one-voice-per-attested-node.
    Attestation-depth weighting is a DOCUMENTED OPTION, never the silent default.
    """
    ONE_NODE_ONE_VOICE = "one_node_one_voice"   # DEFAULT
    ATTESTATION_DEPTH  = "attestation_depth"    # opt-in via QUORUM_REVISION proposal


class RevocationScope(str, Enum):
    SELF      = "self"       # revoke only this subject
    CASCADE   = "cascade"    # revoke subject + entities it grafted (bounded)
    NAME_ONLY = "name_only"  # revoke a Gondwana name binding, leave the key alone


class ApprovalMode(str, Enum):
    """Whether a service subscription is approved automatically or requires provider action."""
    AUTO    = "auto"
    PENDING = "pending"


class SubscriptionState(str, Enum):
    """Derived state of a Subscription (computed from the log, never stored)."""
    PENDING  = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED  = "revoked"


# ---------------------------------------------------------------------------
# JuridictionTag — the geo primitive, made SAFE
# ---------------------------------------------------------------------------

class JuridictionTag(BaseModel):
    """COARSE, CONSENTED jurisdiction label — SCION Isolation-Domain style.

    Sovereignty: YES.  Precise tracking: NEVER.  There is deliberately NO
    coordinate field, and there can never be one (see §5.2 of the spec).
    Proximity, when needed, is proven by PSI without revealing position.
    """
    model_config = ConfigDict(extra="forbid")

    isolation_domain: str = Field(
        ...,
        description="SCION-style ISD id, e.g. 'fr-chambery' — a zone, not a point",
    )
    legal_regime: str = Field(
        ...,
        description="Coarse legal label, e.g. 'FR' (data stays under French law)",
    )
    consented: bool = Field(
        ...,
        description="The subject explicitly consented to this label being published",
    )

    @field_validator("isolation_domain", "legal_regime")
    @classmethod
    def no_coordinates(cls, v: str) -> str:
        """Defensive guard: reject anything that looks like lat/long.
        Geo is a zone label, never a coordinate point.
        The *real* guarantee is structural (no coordinate field exists).
        """
        if any(c.isdigit() for c in v) and ("." in v or "," in v):
            raise ValueError("jurisdiction tags are zones, not coordinates")
        return v


# ---------------------------------------------------------------------------
# Identity — builds directly on did:plc (secubox-identity)
# ---------------------------------------------------------------------------

class Identity(BaseModel):
    """A self-certifying identity.

    did is the hash of the key — the binding is intrinsic, so the directory
    never has to be trusted to assert name→key.  The directory only tracks
    STATE, contextual attestations, and jurisdiction.

    The self_cert_digest validator enforces this: the digest MUST equal the
    did suffix.  Any identity that cannot pass this check is not self-certifying
    and must be rejected.
    """
    model_config = ConfigDict(extra="forbid")

    did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    pubkey: str = Field(..., description="Ed25519 public key, hex (raw 32 bytes)")
    self_cert_digest: str = Field(
        ...,
        description="sha256(pubkey)[:32] — MUST equal the did suffix; "
                    "proves the name IS the key",
    )
    state: MemberState = MemberState.OBSERVED
    jurisdiction: List[JuridictionTag] = Field(default_factory=list)
    hardware_attest: Optional[str] = Field(
        default=None,
        description="Opaque BYOH/SecuBox hardware-anchor attestation blob "
                    "(raises Sybil cost, §5.1)",
    )
    invited_by: Optional[str] = Field(
        default=None,
        description="did of the inviter who grafted standing "
                    "(None for OBSERVED/founder)",
    )
    created_at: str = Field(default_factory=now_rfc3339)
    sig: Optional[str] = Field(
        default=None,
        description="Ed25519 self-signature over canonical JSON (sig field excluded)",
    )
    signer_did: Optional[str] = Field(
        default=None,
        description="did of the key that produced sig (usually == did for self-sig)",
    )

    @field_validator("self_cert_digest")
    @classmethod
    def digest_matches_did(cls, v: str, info) -> str:
        did = info.data.get("did", "")
        if did and did != f"did:plc:{v}":
            raise ValueError(
                "self_cert_digest does not match did — identity is NOT self-certifying"
            )
        return v


# ---------------------------------------------------------------------------
# Attestation — CONTEXTUAL, dated, revocable. NOT PGP-WoT transitivity.
# ---------------------------------------------------------------------------

class Attestation(BaseModel):
    """A CONTEXTUAL trust edge: 'I (attester) trust you (subject) ON context X,
    not globally.'

    Typed, dated, REVOCABLE.  This is explicitly NOT PGP web-of-trust
    transitivity: trust does not flow blindly through this edge.  can()
    decides whether an edge applies to a given action; depth is bounded
    and never silently transitive (spec §6.4).
    """
    model_config = ConfigDict(extra="forbid")

    attester: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    subject: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    context: str = Field(
        ...,
        description="The SCOPE of trust, e.g. 'mesh.route', 'threat.report', 'name.gondwana'",
    )
    weight: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Strength within context (not a global score)",
    )
    domain: str = Field(..., description="isolation_domain this attestation is valid within")
    valid_from: str = Field(default_factory=now_rfc3339)
    valid_until: Optional[str] = Field(
        default=None,
        description="None = open-ended, but always revocable",
    )
    revoked: bool = False
    created_at: str = Field(default_factory=now_rfc3339)
    sig: Optional[str] = None
    signer_did: Optional[str] = None


# ---------------------------------------------------------------------------
# Invitation — a scoped, offline-verifiable capability that confers STANDING
# ---------------------------------------------------------------------------

class Invitation(BaseModel):
    """Capability-based invitation.

    Signed by the inviter, SCOPED (domain, rights, duration), LIMITED-USE,
    OFFLINE-VERIFIABLE.  Accepting it places a directed edge in the trust
    graph and promotes OBSERVED→MEMBER.  The inviter CO-STAKES reputation:
    revoking an inviter can CASCADE (bounded, parameterized — never blindly
    transitive).
    """
    model_config = ConfigDict(extra="forbid")

    invite_id: str = Field(..., description="random 256-bit hex id")
    inviter: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    domain: str = Field(..., description="isolation_domain the invite admits into")
    rights: List[str] = Field(
        default_factory=list,
        description="capability scope granted on accept",
    )
    max_uses: int = Field(default=1, ge=1)
    uses: int = Field(default=0, ge=0)
    expires_at: str = Field(..., description="RFC 3339; offline-verifiable expiry")
    co_stake: bool = Field(
        default=True,
        description="inviter's reputation is bonded to invitee conduct",
    )
    created_at: str = Field(default_factory=now_rfc3339)
    sig: Optional[str] = Field(
        default=None,
        description="inviter Ed25519 sig — verifiable WITHOUT the log",
    )
    signer_did: Optional[str] = None


# ---------------------------------------------------------------------------
# Proposal — network governance. Default quorum = one voice per attested node.
# ---------------------------------------------------------------------------

class Proposal(BaseModel):
    """A signed, typed governance proposal posted on the log with a bounded voting window.

    ANTI-PLUTOCRACY by default.  META-GOVERNANCE: a QUORUM_REVISION proposal
    can change the quorum rule itself — the rule is an object, not a constant.
    """
    model_config = ConfigDict(extra="forbid")

    proposal_id: str = Field(..., description="random 256-bit hex id")
    proposer: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    ptype: ProposalType
    domain: str
    body: Dict[str, Any] = Field(default_factory=dict, description="type-specific payload")
    quorum_rule: QuorumRule = QuorumRule.ONE_NODE_ONE_VOICE
    quorum_threshold: float = Field(
        default=0.6,
        gt=0.5,
        le=1.0,
        description="fraction of eligible voters required",
    )
    opens_at: str = Field(default_factory=now_rfc3339)
    closes_at: str = Field(..., description="bounded voting window — RFC 3339")
    tally_for: int = 0
    tally_against: int = 0
    resolved: Optional[Literal["passed", "failed", "void"]] = None
    created_at: str = Field(default_factory=now_rfc3339)
    sig: Optional[str] = None
    signer_did: Optional[str] = None


# ---------------------------------------------------------------------------
# RevocationNotice — bounded cascade, never blind transitivity
# ---------------------------------------------------------------------------

class RevocationNotice(BaseModel):
    """Withdraws standing or a name binding.

    The cascade is BOUNDED and PARAMETERIZED (cascade_depth), never blindly
    transitive.  Revocation is APPEND-ONLY: nothing is deleted, the withdrawal
    is itself logged and detectable forever.
    """
    model_config = ConfigDict(extra="forbid")

    revocation_id: str = Field(..., description="random 256-bit hex id")
    revoker: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    target: str = Field(
        ...,
        description="did, invite_id, attestation sig, or gondwana name",
    )
    scope: RevocationScope = RevocationScope.SELF
    cascade_depth: int = Field(
        default=0,
        ge=0,
        le=8,
        description="0 = self only; bounded graft cascade (max 8)",
    )
    reason: str
    created_at: str = Field(default_factory=now_rfc3339)
    sig: Optional[str] = None
    signer_did: Optional[str] = None


# ---------------------------------------------------------------------------
# WitnessAttest — auditor co-signature of the log (anti-equivocation)
# ---------------------------------------------------------------------------

class WitnessAttest(BaseModel):
    """An auditor/witness co-signs an observed Merkle root at a given log height.

    Redundant witnesses make equivocation detectable (CONIKS) and provide the
    witness-redundancy milestone that unlocks EMANCIPATE (§3.4).
    """
    model_config = ConfigDict(extra="forbid")

    witness: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    domain: str
    log_height: int = Field(..., ge=0)
    merkle_root: str = Field(
        ...,
        description="BLAKE2b-256 Merkle root the witness observed at this height",
    )
    observed_at: str = Field(default_factory=now_rfc3339)
    sig: Optional[str] = Field(
        default=None,
        description="witness Ed25519 sig over (domain, height, root)",
    )
    signer_did: Optional[str] = None


# ---------------------------------------------------------------------------
# MacroDescriptor — optional access macro for a ServiceOffer
# ---------------------------------------------------------------------------

class MacroDescriptor(BaseModel):
    """An access macro descriptor that can be federated as part of a ServiceOffer.

    The macro describes a reusable access pattern (e.g., tor-exit, cache-config).
    The kind field follows the pattern ^[a-z][a-z0-9-]{1,31}$ to ensure portable,
    federated kind names across nodes.
    """
    model_config = ConfigDict(extra="forbid")

    kind: str = Field(..., pattern=r"^[a-z][a-z0-9-]{1,31}$")
    params: Dict[str, Union[str, int, bool]] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# ServiceOffer — a provider advertising a service to the trust graph
# ---------------------------------------------------------------------------

class ServiceOffer(BaseModel):
    """A signed offer of a service by a provider node.

    Self-certifying: authored by the provider (entry.author == provider).
    The sig covers canonical_bytes(payload_without_sig).
    approval_mode=AUTO: subscription is APPROVED immediately (derived).
    approval_mode=PENDING: requires an explicit SERVICE_APPROVE from the provider.
    """
    model_config = ConfigDict(extra="forbid")

    service_id:    str = Field(..., description="random hex id")
    provider:      str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    name:          str
    kind:          str = Field(..., description="e.g. 'module', 'api', 'mirror'")
    endpoint:      str = Field(..., description="mesh URL or local path")
    scope:         Dict[str, Any] = Field(default_factory=dict)
    approval_mode: ApprovalMode = ApprovalMode.AUTO
    description:   str = ""
    macro:         Optional[MacroDescriptor] = None
    created_at:    str = Field(default_factory=now_rfc3339)
    sig:           Optional[str] = Field(
        default=None,
        description="Ed25519 sig over canonical_bytes(payload_without_sig)",
    )
    signer_did:    Optional[str] = None


# ---------------------------------------------------------------------------
# Subscription — a subscriber requesting access to a ServiceOffer
# ---------------------------------------------------------------------------

class Subscription(BaseModel):
    """A signed subscription request from a subscriber node.

    Self-certifying: authored by the subscriber (entry.author == subscriber).
    State is DERIVED from the log — see subscription_state() in verbs.py.
    """
    model_config = ConfigDict(extra="forbid")

    subscription_id: str = Field(..., description="random hex id")
    subscriber:      str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    service_id:      str
    requested_at:    str = Field(default_factory=now_rfc3339)
    sig:             Optional[str] = None
    signer_did:      Optional[str] = None


# ---------------------------------------------------------------------------
# NodeRecord — the signed mesh peer registry entry (gondwana P1, #768)
# ---------------------------------------------------------------------------

class NodeRecord(BaseModel):
    """A signed record of one mesh node, published into the directory.

    Self-certifying: authored by the node itself (entry.author == did). This is
    the replicated form of secubox-p2p's local wg_mesh.json/peers.json — the
    Phase-1 identity (pubkey_wg, node_id, boxname, DDNS) becomes a ledger
    record (gondwana §8 "distributed directory"). NO secret material here: only
    the WireGuard PUBLIC key. The sig covers canonical_bytes(payload_without_sig).
    """
    model_config = ConfigDict(extra="forbid")

    did:       str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    node_id:   str = Field(..., description="stable node id, e.g. 'sb-<mac12>'")
    boxname:   str = Field(..., description="human node name, e.g. 'gk2'")
    pubkey_wg: str = Field(..., description="WireGuard PUBLIC key (base64) — never the private key")
    mesh_ip:   str = Field(..., description="assigned mesh address, e.g. '10.10.0.1'")
    ddns:      str = Field(..., description="name-based reachability, e.g. '<boxname>.secubox.in'")
    endpoint:  Optional[str] = Field(
        default=None,
        description="public host:port if this node is reachable (rendezvous); None for NAT'd satellites",
    )
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = Field(
        default=None,
        description="Ed25519 sig over canonical_bytes(payload_without_sig)",
    )
    signer_did: Optional[str] = None


# ---------------------------------------------------------------------------
# ConfigBlob — signed, versioned config distribution entry (gondwana P1, #768)
# ---------------------------------------------------------------------------

class ConfigBlob(BaseModel):
    """A signed, versioned configuration blob published by a service's home node.

    Self-certifying: authored by the publisher (entry.author == publisher).
    `version` is a monotonic integer driving last-writer-wins ordering across
    the mesh (single-writer per scope by design). Small configs travel inline
    in `payload`; large ones are referenced by `payload_uri` + `content_hash`
    (BLAKE2b-256 hex). Secrets are NEVER carried — config only. The sig covers
    canonical_bytes(payload_without_sig).
    """
    model_config = ConfigDict(extra="forbid")

    config_id:    str = Field(..., description="stable id for this config stream, e.g. 'cfg-<scope>'")
    publisher:    str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    scope:        str = Field(..., description="what this configures, e.g. a module name 'yacy'")
    version:      int = Field(..., ge=0, description="monotonic; higher wins (last-writer-wins)")
    content_hash: str = Field(..., description="BLAKE2b-256 hex of the canonical config content")
    payload:      Optional[Dict[str, Any]] = Field(
        default=None, description="inline config (small blobs); mutually exclusive with payload_uri"
    )
    payload_uri:  Optional[str] = Field(
        default=None, description="fetch location for large blobs; content verified against content_hash"
    )
    valid_from:   str = Field(default_factory=now_rfc3339)
    valid_until:  Optional[str] = None
    sig:          Optional[str] = Field(
        default=None,
        description="Ed25519 sig over canonical_bytes(payload_without_sig)",
    )
    signer_did:   Optional[str] = None


# ---------------------------------------------------------------------------
# LogEntry — the BLAKE2b-chained journal link
# ---------------------------------------------------------------------------

class LogEntry(BaseModel):
    """One link in the append-only, BLAKE2b-chained journal.

    entry_hash = BLAKE2b-256(prev_hash || canonical_payload_bytes || sig).
    A published Merkle tree over entry_hash values gives clients an auditable root.
    Tamper with any entry and every subsequent entry_hash is broken — detectable.
    """
    model_config = ConfigDict(extra="forbid")

    height: int = Field(..., ge=0)
    op: Op
    prev_hash: str = Field(
        ...,
        description="BLAKE2b-256 hex of the previous entry; genesis = 64*'0'",
    )
    payload_type: str = Field(..., description="class name of the embedded object")
    payload: Dict[str, Any] = Field(..., description="the signed object as canonical dict")
    author: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    sig: str = Field(..., description="author Ed25519 sig over the canonical payload bytes")
    entry_hash: str = Field(
        ...,
        description="BLAKE2b-256 hex chain link (computed by compute_entry_hash)",
    )
    created_at: str = Field(default_factory=now_rfc3339)


# ---------------------------------------------------------------------------
# Chain constants and the hash function
# ---------------------------------------------------------------------------

GENESIS_HASH: str = "0" * 64


def compute_entry_hash(prev_hash: str, payload_canonical: bytes, sig: str) -> str:
    """The chain link: BLAKE2b-256 over prev_hash || payload_bytes || sig.

    Tampering with any historical entry breaks every subsequent entry_hash,
    making the tamper detectable by any auditing client (verify_chain).

    Args:
        prev_hash: hex string of the previous entry's hash (64 chars).
        payload_canonical: deterministic JSON bytes of the payload.
        sig: hex Ed25519 signature string.

    Returns:
        64-char lowercase hex string (BLAKE2b-256, digest_size=32).
    """
    h = hashlib.blake2b(digest_size=32)
    h.update(bytes.fromhex(prev_hash))
    h.update(payload_canonical)
    h.update(sig.encode())
    return h.hexdigest()
