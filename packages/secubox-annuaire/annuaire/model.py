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
    GRANT_ISSUE          = "grant_issue"      # a center is granted delegated config authority
    GRANT_REVOKE         = "grant_revoke"     # a delegated grant is withdrawn
    # Gondwana threatmesh (#768): bidirectional WAF/threat ban federation.
    BAN_PUBLISH          = "ban_publish"      # a node signs an IP ban → federates
    BAN_REVOKE           = "ban_revoke"       # the publisher lifts its own ban
    # Support / assistance request (sous-projet 2) — signed control-plane
    ASSIST_REQUEST        = "assist_request"        # box asks a center for help
    ASSIST_ACCEPT         = "assist_accept"         # center accepts the request
    ASSIST_SESSION_OPEN   = "assist_session_open"   # box consents → live session
    ASSIST_SESSION_CLOSE  = "assist_session_close"  # session ends (op or auto-expiry)
    ASSIST_CONSOLE_GRANT  = "assist_console_grant"  # 2nd consent → console escalation
    ASSIST_CONSOLE_REVOKE = "assist_console_revoke" # console withdrawn
    # Assist marketplace (dual offer/request rendezvous)
    ASSIST_OFFER          = "assist_offer"          # advertise availability to help
    ASSIST_OFFER_REVOKE   = "assist_offer_revoke"
    ASSIST_REQUEST_OPEN   = "assist_request_open"   # open (untargeted) request for help
    ASSIST_MATCH_ACCEPT   = "assist_match_accept"   # one side accepts a proposed match


# ---------------------------------------------------------------------------
# Centers/grants — layered config delegation (feat/centers-grants-remote-config)
# ---------------------------------------------------------------------------

LAYER_ORDER = ["baseline", "override", "local"]
NON_DELEGATABLE = {"auth", "secrets"}


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
# PacDescriptor — optional PAC routing hint for a ServiceOffer
# ---------------------------------------------------------------------------

class PacDescriptor(BaseModel):
    """Optional PAC routing hint federated with a ServiceOffer (#784).

    Declares which hosts this service handles and how a client proxies them.
    Absent pac ⇒ the service contributes no client routing rule.
    """
    model_config = ConfigDict(extra="forbid")

    match: List[str] = Field(..., min_length=1, description="host globs, e.g. ['*.onion']")
    proxy: Literal["socks5", "http", "gateway", "direct"] = Field(...)


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
    pac:           Optional[PacDescriptor] = None
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
    scope:        str = Field(
        ...,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
        description="what this configures, e.g. a module name 'yacy' — becomes a bare "
                    "filename component on disk (config_apply.py), so no '/' or '..'",
    )
    version:      int = Field(..., ge=0, description="monotonic; higher wins (last-writer-wins)")
    content_hash: str = Field(..., description="BLAKE2b-256 hex of the canonical config content")
    layer:        str = Field(default="baseline", description="config layer; local is box-only")
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
# Grant — delegated config authority to a center (feat/centers-grants-remote-config)
# ---------------------------------------------------------------------------

class Grant(BaseModel):
    """A signed grant of delegated config authority to a center.

    Self-certifying: authored by the issuer (entry.author == issued_by).
    A center holding a Grant may publish ConfigBlob entries within `scope` at
    `layer` (never above `layer` in LAYER_ORDER, never for a scope in
    NON_DELEGATABLE). The sig covers canonical_bytes(payload_without_sig).
    """
    model_config = ConfigDict(extra="forbid")

    grant_id:   str = Field(..., description="stable id for this grant")
    center_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    capability: str = Field(default="config", description="what is delegated, e.g. 'config'")
    scope:      str = Field(
        ...,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
        description="what this grant covers, e.g. a module name 'firewall' — becomes a "
                    "bare filename component on disk (config_apply.py), so no '/' or '..'",
    )
    layer:      str = Field(..., description="config layer this grant is confined to")
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = Field(
        default=None,
        description="Ed25519 sig over canonical_bytes(payload_without_sig)",
    )
    signer_did: Optional[str] = None


# ---------------------------------------------------------------------------
# Support / assistance request (sous-projet 2) — real-time help sessions
# ---------------------------------------------------------------------------

ASSIST_MODES = {"per-incident", "standing"}


class AssistRequest(BaseModel):
    """A box's signed request for assistance from a center.

    Self-certifying: authored by the box (entry.author == issued_by). In
    'per-incident' mode this request IS the ephemeral authority (no standing
    grant needed); in 'standing' mode an active capability="assist" Grant is
    required for the center to initiate. sig covers canonical_bytes(payload
    without sig/signer_did).
    """
    model_config = ConfigDict(extra="forbid")

    req_id:     str = Field(..., description="stable id for this request")
    center_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    mode:       str = Field(..., description="'per-incident' or 'standing'")
    scope:      str = Field(..., pattern=r"^[a-z0-9][a-z0-9._-]*$",
                            description="incident scope hint; bare filename component")
    duration_s: int = Field(..., ge=60, le=86400, description="requested max session seconds")
    reason:     str = Field(..., min_length=1, max_length=512)
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None

    @field_validator("mode")
    @classmethod
    def _mode_known(cls, v: str) -> str:
        if v not in ASSIST_MODES:
            raise ValueError(f"mode must be one of {sorted(ASSIST_MODES)}")
        return v


class AssistSession(BaseModel):
    """A box-consented live assistance session. token_hash is BLAKE2b-hex of
    the single-use session token; the token secret itself is NEVER journaled.
    """
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(..., description="stable id for this session")
    req_id:     str = Field(..., description="the AssistRequest this opens")
    center_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    token_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$",
                            description="BLAKE2b-hex of the single-use session token")
    expires_ts: str = Field(..., description="RFC3339 hard-cap; fail-closed past this")
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None


# ---------------------------------------------------------------------------
# Assist marketplace — offer/request rendezvous (assist-dual)
# ---------------------------------------------------------------------------

ASSIST_MATCH_SIDES = {"offer", "request"}


class AssistOffer(BaseModel):
    """A signed advertisement of availability to help (marketplace OFFER)."""
    model_config = ConfigDict(extra="forbid")
    offer_id:   str = Field(..., description="stable id for this offer")
    tags:       list[str] = Field(..., min_length=1, description="free-form capability tags")
    scope:      Optional[str] = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    ttl_s:      int = Field(..., ge=60, le=86400)
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None


class AssistOpenRequest(BaseModel):
    """A signed open (untargeted) request for help (marketplace REQUEST)."""
    model_config = ConfigDict(extra="forbid")
    req_id:     str = Field(..., description="stable id for this open request")
    tags:       list[str] = Field(..., min_length=1)
    scope:      Optional[str] = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    ttl_s:      int = Field(..., ge=60, le=86400)
    reason:     str = Field(..., min_length=1, max_length=512)
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None


class AssistMatchAccept(BaseModel):
    """One side's signed acceptance of a proposed offer↔request match."""
    model_config = ConfigDict(extra="forbid")
    match_id:   str = Field(..., pattern=r"^[0-9a-f]{64}$")
    offer_id:   str = Field(...)
    req_id:     str = Field(...)
    side:       str = Field(..., description="'offer' or 'request'")
    issued_by:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    created_at: str = Field(default_factory=now_rfc3339)
    sig:        Optional[str] = None
    signer_did: Optional[str] = None

    @field_validator("side")
    @classmethod
    def _side_known(cls, v: str) -> str:
        if v not in ASSIST_MATCH_SIDES:
            raise ValueError(f"side must be one of {sorted(ASSIST_MATCH_SIDES)}")
        return v


# ---------------------------------------------------------------------------
# BanRecord — a signed WAF/threat ban (gondwana threatmesh, #768)
# ---------------------------------------------------------------------------

class BanRecord(BaseModel):
    """A signed IP ban published by a node, federated to the whole mesh.

    Self-certifying: authored by the node that observed the threat
    (entry.author == publisher). Bans gossip over the same convergent log as
    node/config records, so a ban on ANY node reaches ALL nodes (bidirectional,
    no master). The enforcement view is the UNION of active bans; a node lifts
    only its own ban (BAN_REVOKE). `expires_at` gives each ban a TTL so stale
    bans fall out of the set automatically. No secrets, just an address + reason.
    """
    model_config = ConfigDict(extra="forbid")

    ban_id:     str = Field(..., description="stable id per (publisher, ip), e.g. 'ban-<ip>'")
    publisher:  str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    ip:         str = Field(..., description="the banned IPv4/IPv6 address")
    reason:     str = ""
    severity:   str = Field(default="medium", description="low|medium|high|critical")
    created_at: str = Field(default_factory=now_rfc3339)
    expires_at: Optional[str] = Field(default=None, description="RFC3339 TTL; None = no expiry")
    sig:        Optional[str] = Field(
        default=None, description="Ed25519 sig over canonical_bytes(payload_without_sig)")
    signer_did: Optional[str] = None


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
