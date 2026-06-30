<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->

# Annuaire·Miroir — A Federated, Self-Certifying Trust Substrate

**Design spec · 2026-06-30 · SecuBox-DEB**
**Status:** design — *not built, not deployed.* This document is a specification.
**Jurisdiction:** Chambéry (FR) · **License:** CMSD-1.0 (source-available) · **Builds:** reproducible (mandatory)
**Author:** Gérald Kerma <devel@cybermind.fr> — CyberMind

---

## 0. Thesis — honesty over purity

The Annuaire·Miroir ("Mirror Directory") is the **trust directory** that sits between
two existing layers of the SecuBox-DEB platform:

- **Below — MirrorNet (L3 P2P):** WireGuard/Noise transport, `did:plc` identities,
  HamCoin token, the *ALERTE·DÉPÔT* signal. MirrorNet carries **bytes and
  reachability**.
- **Above — Gondwana (public face):** the human-readable, branded, mythological
  namespace. Gondwana is the **public reflection** of the cryptographic substrate.

The directory carries the third thing neither of those carries: **MEANING** — *who is
who, and who attests to whom.* It is **not a blockchain.** It is an **honest
cryptographic substrate** with one governing rule:

> **Crypto makes betrayal *detectable*, not *impossible*. Assume this everywhere.**

The directory does **not** claim to be simultaneously 100 % open, 100 % safe, and
100 % respectful of privacy. Those three pull against each other. What the directory
does instead is make every trade-off **explicit, auditable, and user-chosen**: the
user can *see* their trust roots and *choose* them. Where a property cannot be
guaranteed, the spec **says so** and makes its violation **detectable**.

> *"The legibility of trust is the deepest form of respect."*

### Document map

| § | Deliverable |
|---|-------------|
| 1 | **Architecture** — the two mirrored faces + the third; placement; data flow; ASCII diagram |
| 2 | **Data model** — runnable Pydantic v2 for every object, with BLAKE2b chaining + signatures |
| 3 | **The four protocols** — AUTO-ADD / INVITE / PROPOSAL / EMANCIPATE, as signed-log events with state machines |
| 4 | **Reference code** — FastAPI + SQLite-WAL BLAKE2b-chained log, Merkle root, `can()` resolver |
| 5 | **Sybil, geo, metadata privacy** — invitation-grafting + hardware-anchoring; coarse jurisdiction + PSI; NIZK + CONIKS + onion |
| 6 | **Trade-offs & anti-goals** — the explicit honest list; for each ungranted guarantee, the detection mechanism |
| 7 | **The social layer** — the named actors and the path to credible neutrality |

### What the directory plugs into (it does NOT reinvent these)

| Concern | Existing component | Where |
|---------|--------------------|-------|
| Self-certifying identity | `did:plc:<sha256(pubkey)[:32]>`, Ed25519, signed `IdentityDocument`, key rotation | `packages/secubox-identity/api/main.py` |
| Membership join / token / approve | master-link: `/master-link/token`, `/master-link/join`, `/master-link/approve`, wg-mesh `10.10.0.0/24` | `packages/secubox-p2p/api/main.py` + `api/mesh.py` |
| Non-revoked-membership ZKP | `ZKP-HAM-v1` — Blum + Fiat-Shamir, SHA3-256, soundness ≥ 1 − 2⁻¹²⁸, `zkp_prove`/`zkp_verify` | `packages/zkp-hamiltonian/include/zkp_hamiltonian.h` |
| Config safety doctrine | OPAD invariants INV-01..INV-08, observe/enforce, double-buffer/4R | `common/secubox_core/opad/`, `docs/.../opad-doctrine-design.md` |
| The ledger this fulfils | Gondwana §8 "Distributed directory (DNS-structured ledger)" | `docs/.../2026-06-29-gondwana-phase1-mesh-substrate-design.md` |

The directory **consumes** these guarantees; it never bypasses them. Notably it never
violates an OPAD invariant — AUTO-ADD maps onto OPAD's *observe* posture (quarantine by
default), and config-sensitive changes ride the double-buffer/4R swap.

---

## 1. Architecture — the doubling, and the third face

### 1.1 The two mirrored faces

```
                        ┌──────────────────────────────────────┐
                        │            GONDWANA  (public)         │   ← readable layer
                        │   human / branded / mythological      │     (capturable, legible)
                        │   names  ──mapped-via-audited-log──▶  │
                        └───────────────▲──────────────────────┘
                                        │  AUDITED RECONCILIATION
                                        │  (this is what is authoritative)
                        ┌───────────────▼──────────────────────┐
                        │            MIRROR   (substrate)       │   ← truth layer
                        │   THE NAME IS THE HASH OF THE KEY     │     (illegible, intrinsic)
                        │   did:plc:<sha256(pubkey)[:32]>       │
                        │   CONIKS-style key-transparency log   │
                        └───────────────▲──────────────────────┘
                                        │ consumes bytes + reachability
                        ┌───────────────▼──────────────────────┐
                        │         MIRRORNET  (L3 P2P)           │
                        │   WireGuard/Noise · onion · HamCoin   │
                        └──────────────────────────────────────┘
```

**Face 1 — MIRROR (substrate, internal / CyberMind): the truth layer.**
Identity is **self-certifying**: *the name is the hash of the key.* The directory
inherits this verbatim from `secubox-identity`:

```python
# packages/secubox-identity/api/main.py
def generate_did(self, public_key_bytes: bytes) -> str:
    """Generate DID from public key: did:plc:<sha256_fingerprint>"""
    fingerprint = hashlib.sha256(public_key_bytes).hexdigest()[:32]
    return f"did:plc:{fingerprint}"
```

Because `did → key` is **intrinsic** (the onion/nostr/IPNS/DID pattern), *no directory
is needed to bind name to key.* That dissolves **half the trust problem** before it
starts. What remains is **key transparency**: a CONIKS-style append-only,
privacy-preserving Merkle tree that clients **audit**. Equivocation — the directory
showing key K to Alice and key K′ to Bob for the same `did` — becomes **detectable** by
any auditing client comparing signed Merkle roots (§4.3, §5.3).

**Face 2 — GONDWANA (public, external): the readable layer.**
Human / branded / mythological names (`vortex.gondwana`, `gk2.secubox.in`) mapped to
keys **via the audited transparency log**. The **Zooko triangle** (secure ∧ decentralized
∧ human-meaningful — pick two) appears **only here**, at the human-naming boundary. We do
**not** answer it with a name-blockchain by default. We answer it with:

1. **Transparency** — the name→key binding is published in the auditable CONIKS log.
2. **A deliberate, auditable anchor** — DNS/DANE for the `secubox.in` / `gondwana` zones,
   exactly as Gondwana §8 already sketches (gk2 authoritative or registrar API), plus a
   **DHT fallback** so a censored or failed anchor is survivable.
3. **Revocability** — any name binding can be revoked by a `RevocationNotice` and the
   revocation is itself logged.

A name-blockchain (Namecoin / ENS / Handshake) is a **documented option** (§6.7),
**never imposed**. The default is "transparency + assumed anchor + revocability."

**Face 3 — THE THIRD FACE: the device itself.**
(ref *CM-2026-0410-MIRROR*, "bilateral hallucination".) The protocol holding the two
faces in tension **IS** the trust object. Neither the raw key (illegible to humans) nor
the Gondwana name (capturable by whoever controls the anchor) is authoritative **alone**.
**Their *audited reconciliation* is what is authoritative.** Concretely, a trust
decision is valid only when:

```
   (a) the Gondwana name resolves, via the log, to a did:plc,   AND
   (b) that did:plc's key is consistent across audited Merkle roots
       (no equivocation),                                       AND
   (c) the did:plc is a non-REVOKED member (NIZK GK·HAM-HASH),  AND
   (d) the relevant Attestation is contextual, dated, non-revoked, and
       in-scope for the action being authorized (can(), §4.4).
```

If any of (a)–(d) is absent, the answer is **not "trusted"** — it is **"unreconciled,"**
which is a *visible* state, never silently upgraded to trust.

### 1.2 Placement & data flow

The Annuaire·Miroir ships as a SecuBox module, **`secubox-annuaire`**, served
in-process by the aggregator (like every other module) under
`/api/v1/annuaire/*`, on the Unix socket `/run/secubox/annuaire.sock`, JWT-gated via
`Depends(require_jwt)`, running as user `secubox-annuaire`. It owns one SQLite-WAL
database, `/var/lib/secubox/annuaire/log.db`, and one append-only audit mirror,
`/var/log/secubox/annuaire/audit.log`.

It does **not** replace `secubox-p2p` or `secubox-identity`. It **federates over** them:

```
 ┌─────────────────────────── ONE SOVEREIGN ISLAND (a domain) ───────────────────────────┐
 │                                                                                        │
 │   Gondwana web UI  ──(reads)──▶  secubox-annuaire  ──(reads)──▶  secubox-identity      │
 │   (human names)                  │  log.db (WAL)                  (did:plc, Ed25519)    │
 │                                  │  BLAKE2b chain                                       │
 │                                  │  Merkle roots                  zkp-hamiltonian       │
 │                                  │  can() resolver  ◀──(verifies)── (NIZK membership)   │
 │                                  ▼                                                      │
 │                          WitnessAttest co-signatures                                   │
 │                          (auditors / witnesses)                                        │
 │                                  ▲                                                      │
 │   secubox-p2p (master-link) ─────┘  AUTO-ADD/INVITE/PROPOSAL/EMANCIPATE ride this flow  │
 │   wg-mesh 10.10.0.0/24                                                                  │
 └────────────────────────────────────┬───────────────────────────────────────────────────┘
                                       │  shared protocol (signed log entries + Merkle roots)
       ┌───────────────────────────────┼───────────────────────────────┐
       ▼                               ▼                               ▼
  another island                  another island                  another island
  (own anchor, own witnesses)     (own anchor)                    (own anchor)
       └──── federation: email/Matrix/ActivityPub model — NO global monolith ────┘
```

Each **domain** (= one sovereign island, SCION-Isolation-Domain style, §5.2) holds its
**own** log, its **own** anchor(s), and its **own** witnesses. Islands interoperate by
exchanging **signed log entries and published Merkle roots** — never by submitting to a
single global chain. This is the email / Matrix / ActivityPub federation model;
MirrorNet is already this sketch (`/announcers`, `/discover/bridge`, master-link depth).

### 1.3 Mapping the four verbs onto the live master-link flow

The directory **extends** the existing master-link endpoints rather than replacing
them. Each existing call gains a **signed, typed, dated, revocable `LogEntry`** so the
membership graph becomes auditable:

| Verb | Existing master-link endpoint (extended) | New log effect |
|------|------------------------------------------|----------------|
| AUTO-ADD | `POST /api/v1/p2p/discover` (gossip/mDNS aggregate) | `LogEntry{op=AUTO_ADD}` → `Identity.state = OBSERVED` |
| INVITE | `POST /api/v1/p2p/master-link/token` + `/master-link/join` + `/master-link/approve` | `Invitation` capability + `LogEntry{op=INVITE_ACCEPT}` → `OBSERVED→MEMBER`, directed `Attestation` edge |
| PROPOSAL | *new:* `POST /api/v1/annuaire/proposal` | `Proposal` + tallied `Attestation`-votes |
| EMANCIPATE | *new:* `POST /api/v1/annuaire/proposal` (type=`Emancipation`) gated by milestones | `LogEntry{op=EMANCIPATE}` removes/relaxes an anchor, monotone |

---

## 2. Data model (Pydantic v2)

Design rules, uniform across every object:

- **Everything is signed.** `sig` = Ed25519 signature (hex) over the object's
  canonical JSON (`model_dump_json()` with sorted keys, `sig` field excluded).
- **Everything is timestamped** in RFC 3339 (`created_at`), to satisfy CSPN immutable,
  RFC-3339-timestamped logging.
- **Everything is chained.** When committed, each object becomes a `LogEntry` whose
  `prev_hash` links to the previous entry, BLAKE2b-256.
- `model_config = ConfigDict(extra="forbid")` everywhere (matches the OPAD models'
  house style — reject unknown fields).
- Access to anything is resolved by `can()` (§4.4). No object grants rights by mere
  existence — an `Attestation` is a *claim*, `can()` is the *adjudicator*.

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: models
Annuaire·Miroir — the trust substrate's ontology-lite object set.
Every object is signed (Ed25519), timestamped (RFC 3339), and chained (BLAKE2b)
in the journal. Access is resolved exclusively by can().
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any, Literal

from pydantic import BaseModel, Field, ConfigDict, field_validator


def now_rfc3339() -> str:
    """RFC 3339 UTC timestamp (CSPN logging requirement)."""
    return datetime.now(timezone.utc).isoformat()


# ============================================================================
# ENUMS — explicit, closed vocabularies
# ============================================================================

class MemberState(str, Enum):
    """The membership state machine. AUTO-ADD lands in OBSERVED; INVITE-accept
    promotes to MEMBER; any RevocationNotice drives to REVOKED. There is no
    silent upgrade from OBSERVED to MEMBER — only an accepted Invitation does it."""
    OBSERVED = "observed"   # seen via gossip; quarantined; minimal rights; NO standing
    MEMBER   = "member"     # invited & grafted; has standing under a domain
    REVOKED  = "revoked"    # membership withdrawn; detectable, never deleted from log


class Op(str, Enum):
    """Log operation types — the four verbs plus their bookkeeping."""
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
    NAME_BIND      = "name_bind"   # Gondwana human name -> did:plc binding
    NAME_REVOKE    = "name_revoke"


class ProposalType(str, Enum):
    CHANGE_PROTOCOL  = "change_protocol"
    QUORUM_REVISION  = "quorum_revision"   # META-GOVERNANCE: the quorum rule is itself an object
    ADD_ANCHOR       = "add_anchor"
    REMOVE_ANCHOR    = "remove_anchor"
    EMANCIPATION     = "emancipation"
    ADD_WITNESS      = "add_witness"
    REMOVE_WITNESS   = "remove_witness"


class QuorumRule(str, Enum):
    """ANTI-PLUTOCRACY. Default is one-voice-per-attested-node. Attestation-depth
    weighting is a DOCUMENTED OPTION, never the silent default."""
    ONE_NODE_ONE_VOICE   = "one_node_one_voice"     # DEFAULT
    ATTESTATION_DEPTH    = "attestation_depth"      # opt-in, must be set by a QuorumRevision proposal


class RevocationScope(str, Enum):
    SELF        = "self"          # revoke only this subject
    CASCADE     = "cascade"       # revoke subject + entities it grafted (bounded, parameterized)
    NAME_ONLY   = "name_only"     # revoke a Gondwana name binding, leave the key alone


# ============================================================================
# JuridictionTag — the geo primitive, made SAFE
# ============================================================================

class JuridictionTag(BaseModel):
    """COARSE, CONSENTED jurisdiction label — SCION Isolation-Domain style.
    Sovereignty: YES. Precise tracking: NEVER. There is deliberately NO
    coordinate field, and there can never be one (see §5.2). Proximity, when
    needed, is proven by PSI without revealing position."""
    model_config = ConfigDict(extra="forbid")

    isolation_domain: str = Field(
        ..., description="SCION-style ISD id, e.g. 'fr-chambery' — a zone, not a point"
    )
    legal_regime: str = Field(
        ..., description="Coarse legal label, e.g. 'FR' (data stays under French law)"
    )
    consented: bool = Field(
        ..., description="The subject explicitly consented to this label being published"
    )

    @field_validator("isolation_domain", "legal_regime")
    @classmethod
    def no_coordinates(cls, v: str) -> str:
        # Defensive: reject anything that looks like lat/long. Geo is a zone, never a point.
        if any(c.isdigit() for c in v) and ("." in v or "," in v):
            raise ValueError("jurisdiction tags are zones, not coordinates")
        return v


# ============================================================================
# Identity — builds directly on did:plc (secubox-identity)
# ============================================================================

class Identity(BaseModel):
    """A self-certifying identity. did is the hash of the key — the binding is
    intrinsic, so the directory never has to be trusted to assert name->key.
    The directory only tracks STATE, contextual attestations, and jurisdiction."""
    model_config = ConfigDict(extra="forbid")

    did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    pubkey: str = Field(..., description="Ed25519 public key, hex (raw)")
    self_cert_digest: str = Field(
        ..., description="sha256(pubkey)[:32] — MUST equal the did suffix; the proof the name IS the key"
    )
    state: MemberState = MemberState.OBSERVED
    jurisdiction: List[JuridictionTag] = Field(default_factory=list)
    hardware_attest: Optional[str] = Field(
        default=None,
        description="Opaque BYOH/SecuBox hardware-anchor attestation blob (raises Sybil cost, §5.1)"
    )
    invited_by: Optional[str] = Field(
        default=None, description="did of the inviter who grafted standing (None for OBSERVED/founder)"
    )
    created_at: str = Field(default_factory=now_rfc3339)
    sig: Optional[str] = Field(default=None, description="Ed25519 self-signature over canonical JSON")

    @field_validator("self_cert_digest")
    @classmethod
    def digest_matches_did(cls, v: str, info) -> str:
        did = info.data.get("did", "")
        if did and did != f"did:plc:{v}":
            raise ValueError("self_cert_digest does not match did — identity is NOT self-certifying")
        return v


# ============================================================================
# Claim / Attestation — CONTEXTUAL, dated, revocable. NOT PGP-WoT transitivity.
# ============================================================================

class Attestation(BaseModel):
    """A CONTEXTUAL trust edge: 'I (attester) trust you (subject) ON context X,
    not globally.' Typed, dated, REVOCABLE. This is explicitly NOT confused PGP
    web-of-trust transitivity: trust does not flow blindly through this edge.
    can() decides whether an edge applies to a given action; depth is bounded
    and never silently transitive."""
    model_config = ConfigDict(extra="forbid")

    attester: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    subject: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    context: str = Field(
        ..., description="The SCOPE of the trust, e.g. 'mesh.route', 'threat.report', 'name.gondwana'"
    )
    weight: float = Field(default=1.0, ge=0.0, le=1.0, description="strength within context (not a global score)")
    domain: str = Field(..., description="isolation_domain this attestation is valid within")
    valid_from: str = Field(default_factory=now_rfc3339)
    valid_until: Optional[str] = Field(default=None, description="None = open-ended, but always revocable")
    revoked: bool = False
    created_at: str = Field(default_factory=now_rfc3339)
    sig: Optional[str] = None


# ============================================================================
# Invitation — a scoped, offline-verifiable capability that confers STANDING
# ============================================================================

class Invitation(BaseModel):
    """Capability-based invitation. Signed by the inviter, SCOPED (domain, rights,
    duration), LIMITED-USE, OFFLINE-VERIFIABLE. Accepting it places a directed
    edge in the trust graph and promotes OBSERVED->MEMBER. The inviter CO-STAKES
    reputation: revoking an inviter can CASCADE (bounded, parameterized — never
    blindly transitive)."""
    model_config = ConfigDict(extra="forbid")

    invite_id: str = Field(..., description="random 256-bit hex id")
    inviter: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    domain: str = Field(..., description="isolation_domain the invite admits into")
    rights: List[str] = Field(default_factory=list, description="capability scope granted on accept")
    max_uses: int = Field(default=1, ge=1)
    uses: int = Field(default=0, ge=0)
    expires_at: str = Field(..., description="RFC 3339; offline-verifiable expiry")
    co_stake: bool = Field(default=True, description="inviter's reputation is bonded to invitee conduct")
    created_at: str = Field(default_factory=now_rfc3339)
    sig: Optional[str] = Field(default=None, description="inviter Ed25519 sig — verifiable WITHOUT the log")


# ============================================================================
# Proposal — network governance. Default quorum = one voice per attested node.
# ============================================================================

class Proposal(BaseModel):
    """A signed, typed governance proposal posted on the log with a bounded voting
    window. ANTI-PLUTOCRACY by default. META-GOVERNANCE: a QUORUM_REVISION proposal
    can change the quorum rule itself — the rule is an object, not a constant."""
    model_config = ConfigDict(extra="forbid")

    proposal_id: str = Field(..., description="random 256-bit hex id")
    proposer: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    ptype: ProposalType
    domain: str
    body: Dict[str, Any] = Field(default_factory=dict, description="type-specific payload")
    quorum_rule: QuorumRule = QuorumRule.ONE_NODE_ONE_VOICE
    quorum_threshold: float = Field(default=0.6, gt=0.5, le=1.0, description="fraction of eligible voters")
    opens_at: str = Field(default_factory=now_rfc3339)
    closes_at: str = Field(..., description="bounded voting window — RFC 3339")
    tally_for: int = 0
    tally_against: int = 0
    resolved: Optional[Literal["passed", "failed", "void"]] = None
    created_at: str = Field(default_factory=now_rfc3339)
    sig: Optional[str] = None


# ============================================================================
# RevocationNotice — bounded cascade, never blind transitivity
# ============================================================================

class RevocationNotice(BaseModel):
    """Withdraws standing or a name binding. The cascade is BOUNDED and
    PARAMETERIZED (cascade_depth), never blindly transitive. Revocation is
    APPEND-ONLY: nothing is deleted, the withdrawal is itself logged and
    detectable forever."""
    model_config = ConfigDict(extra="forbid")

    revocation_id: str = Field(..., description="random 256-bit hex id")
    revoker: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    target: str = Field(..., description="did, invite_id, attestation sig, or gondwana name")
    scope: RevocationScope = RevocationScope.SELF
    cascade_depth: int = Field(default=0, ge=0, le=8, description="0 = self only; bounded graft cascade")
    reason: str
    created_at: str = Field(default_factory=now_rfc3339)
    sig: Optional[str] = None


# ============================================================================
# WitnessAttest — auditor co-signature of the log (anti-equivocation)
# ============================================================================

class WitnessAttest(BaseModel):
    """An auditor/witness co-signs an observed Merkle root at a given log height.
    Redundant witnesses make equivocation detectable (CONIKS) and provide the
    witness-redundancy milestone that unlocks EMANCIPATE (§3.4)."""
    model_config = ConfigDict(extra="forbid")

    witness: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    domain: str
    log_height: int = Field(..., ge=0)
    merkle_root: str = Field(..., description="BLAKE2b-256 Merkle root the witness observed at this height")
    observed_at: str = Field(default_factory=now_rfc3339)
    sig: Optional[str] = Field(default=None, description="witness Ed25519 sig over (domain,height,root)")


# ============================================================================
# LogEntry — the BLAKE2b-chained journal link
# ============================================================================

class LogEntry(BaseModel):
    """One link in the append-only, BLAKE2b-chained journal. The payload is one of
    the objects above, serialized. entry_hash = BLAKE2b(prev_hash || payload || sig).
    A published Merkle tree over entry_hash values gives clients an auditable root."""
    model_config = ConfigDict(extra="forbid")

    height: int = Field(..., ge=0)
    op: Op
    prev_hash: str = Field(..., description="BLAKE2b-256 hex of the previous entry; genesis = 64*'0'")
    payload_type: str = Field(..., description="class name of the embedded object")
    payload: Dict[str, Any] = Field(..., description="the signed object as canonical dict")
    author: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    sig: str = Field(..., description="author Ed25519 sig over the canonical payload")
    entry_hash: str = Field(..., description="BLAKE2b-256 hex chain link (computed, see compute_entry_hash)")
    created_at: str = Field(default_factory=now_rfc3339)


GENESIS_HASH = "0" * 64


def compute_entry_hash(prev_hash: str, payload_canonical: bytes, sig: str) -> str:
    """The chain link: BLAKE2b-256 over prev_hash || payload || sig.
    Tampering with any historical entry breaks every subsequent entry_hash."""
    h = hashlib.blake2b(digest_size=32)
    h.update(bytes.fromhex(prev_hash))
    h.update(payload_canonical)
    h.update(sig.encode())
    return h.hexdigest()
```

> **Note on the `JuridictionTag` validator:** the `no_coordinates` check is a defensive
> guard, not a security boundary — the *real* guarantee is structural (there is no
> coordinate field, and the spec forbids ever adding one). It exists so that an operator
> who tries to smuggle a lat/long into a label gets a hard error.

---

## 3. The four protocols

All four are **signed, typed, dated `LogEntry` events**, each **revocable**. The
membership state machine is shared:

```
                 gossip / mDNS                 accept Invitation
   (nothing) ───────────────▶ OBSERVED ─────────────────────────▶ MEMBER
                              │  quarantined,                       │
                              │  minimal rights,                    │
                              │  NO standing                        │
                              │                                     │
                              └──────────────┬──────────────────────┘
                                             │  RevocationNotice (any time)
                                             ▼
                                          REVOKED  (append-only; detectable forever;
                                                    re-entry requires a NEW Invitation)
```

**The hard rule:** AUTO-ADD lands an identity in **OBSERVED only.** OBSERVED **never**
auto-promotes. The *only* edge from OBSERVED→MEMBER is an **accepted Invitation.**
*Invitation-grafting IS the Sybil resistance* (§5.1) — so this edge is the security
boundary and is guarded accordingly.

### 3.1 AUTO-ADD — provisional, observed membership

**Intent:** make an unknown peer **visible/observable**, nothing more. Permissionless
*discovery*, not permissionless *standing*.

**Trigger:** MirrorNet gossip / mDNS / `POST /api/v1/p2p/discover` surfaces an unknown
`did:plc`.

**Flow:**
1. The discovering node verifies the peer's signed `IdentityDocument`
   (`secubox-identity` already does this in `register_peer`).
2. It writes `LogEntry{op=AUTO_ADD, payload=Identity(state=OBSERVED)}`.
3. The new identity gets **`MemberState.OBSERVED`**, **low trust**, **minimal rights**,
   under the domain's policy. By default it is **quarantined** — directly consistent
   with the OPAD *observe* posture (off-path, INV-01..INV-08 untouched: AUTO-ADD changes
   *visibility*, not *enforcement*).
4. No standing is conferred. `can()` returns the OBSERVED right-set only.

**Revocable:** a `RevocationNotice{scope=SELF}` removes the observed entry (still logged).

### 3.2 INVITE — the capability that confers standing

**Intent:** confer **standing**. You enter the trust graph because an already-trusted
node **invited** you.

**Flow:**
1. **Issue.** An inviter (MEMBER, with the `invite` right) calls
   `POST /api/v1/p2p/master-link/token` (the live endpoint) which the directory wraps
   into an `Invitation` capability: signed by the inviter, **scoped** (`domain`,
   `rights`, `expires_at`), **limited-use** (`max_uses`). The token is
   **offline-verifiable** — a recipient can check the inviter's signature and expiry
   *without contacting the log*. `LogEntry{op=INVITE_ISSUE}`.
2. **Accept.** The invitee presents the capability to
   `POST /api/v1/p2p/master-link/join`. The directory:
   - verifies the Invitation signature, domain, scope, expiry, and `uses < max_uses`;
   - places a **directed `Attestation` edge** `inviter --(context=domain)--> invitee`;
   - promotes the invitee **OBSERVED→MEMBER**;
   - writes `LogEntry{op=INVITE_ACCEPT}`.
   This maps onto the existing `/master-link/approve` (`action="approve"`) path, which
   already allocates a mesh IP and adds the peer — the directory adds the **signed,
   logged, contextual edge** on top.
3. **Co-staking.** Because `Invitation.co_stake = True` by default, the inviter's
   reputation is **bonded** to the invitee's conduct. Revoking an inviter can therefore
   **cascade** to invitees — but **only** via `RevocationNotice{scope=CASCADE,
   cascade_depth=k}`, **bounded** by `k ≤ 8` and **parameterized**, *never* blindly
   transitive (the explicit anti-goal — the PGP-WoT ergonomic failure, §6.4).

**Tension resolved — auto-add vs. invite.** AUTO-ADD gives **permissionless growth of
*visibility*** (the network sees you); INVITE gives **controlled growth of *standing***
(the network *trusts* you, contextually). The two never collapse into one: there is no
code path from OBSERVED to MEMBER except an accepted Invitation.

### 3.3 PROPOSAL — network governance

**Intent:** change the network's own rules, anti-plutocratically.

**Flow:**
1. **Open.** A MEMBER posts `POST /api/v1/annuaire/proposal` →
   `Proposal{ptype, domain, body, quorum_rule, closes_at}` →
   `LogEntry{op=PROPOSAL_OPEN}`. The voting window is **bounded** (`closes_at`).
2. **Vote.** Each eligible voter posts a signed vote → `LogEntry{op=PROPOSAL_VOTE}`.
   **Default eligibility & weight: ONE VOICE PER ATTESTED NODE within the domain**
   (`QuorumRule.ONE_NODE_ONE_VOICE`) — **not** stake-weighted. Attestation-depth
   weighting (`ATTESTATION_DEPTH`) exists but is **opt-in** and can only be selected by a
   prior, passed `QUORUM_REVISION` proposal — it is **never the silent default** (§6.5).
3. **Close.** At `closes_at`, the tally is computed and
   `LogEntry{op=PROPOSAL_CLOSE, resolved=passed|failed}` is written. Passing a
   `CHANGE_PROTOCOL` / `QUORUM_REVISION` / `ADD_ANCHOR` / `REMOVE_ANCHOR` /
   `ADD_WITNESS` / `REMOVE_WITNESS` / `EMANCIPATION` proposal applies its effect.

**Meta-governance.** The quorum rule is itself a `Proposal`-modifiable object: a
`QUORUM_REVISION` proposal can change `quorum_rule`/`quorum_threshold` for the domain.
The rule that governs change is itself subject to change — under the *current* rule.

### 3.4 EMANCIPATE — the weaning of anchors

**The philosophically heavy deliverable.** The network **starts anchored**: a founding
key, a DNS/DANE root (`secubox.in` / Gondwana zone), and seed nodes (gk2 as the active
rendezvous, per Gondwana Phase 1). **Emancipation is the defined, staged path by which
the network cuts its umbilical cord and becomes uncapturable — including by its
founder.**

**Staged milestones.** Each milestone, once *provably* met, **unlocks** an Emancipation
`Proposal`. Milestones are evaluated from the log itself (no operator assertion):

| Milestone | Predicate (computed from the log) | Unlocks |
|-----------|-----------------------------------|---------|
| **M1 — domain plurality** | ≥ N independent `isolation_domain`s each with ≥ 1 MEMBER not grafted by the founder | `Proposal(ADD_ANCHOR)` for a second anchor |
| **M2 — auditor plurality** | ≥ M distinct `WitnessAttest` witnesses co-signing consistent roots over a rolling window | `Proposal(REMOVE_ANCHOR)` for the DNS/DANE root → DHT fallback becomes primary |
| **M3 — witness redundancy** | ≥ R witnesses with no single operator controlling > ⌊R/3⌋ | `Proposal(EMANCIPATION)` to **remove the founding anchor key** |

**Founder revocation, made POSSIBLE and SAFE.** At M3, an `EMANCIPATION` proposal can
`REMOVE_ANCHOR(founder_key)`. The protocol **must** make this removal *possible* (the
founder cannot veto it once M3 is met — credible-neutrality / exit-to-community test)
*and* *safe*:

- **Safety predicate (enforced before the EMANCIPATE LogEntry is accepted):**
  removing the anchor must **not** (a) open a Sybil window — i.e. invitation-grafting +
  hardware-anchoring must remain the sole standing path with no founder-only bypass left;
  nor (b) break auditability — i.e. ≥ M witnesses must remain after removal.
- **Monotone weaning (INVARIANT EM-MONOTONE):** emancipation is **one-way**. The log
  records a monotonic `emancipation_level`; an `EMANCIPATE` entry may only *increase* it.
  **No quiet re-anchoring** — re-introducing an anchor requires a *public* `ADD_ANCHOR`
  proposal that itself appears in the log and lowers nothing. A regression is therefore
  **detectable** by any auditor diffing `emancipation_level` across roots.

**Emancipation state machine:**

```
  ANCHORED ──M1──▶ MULTI-ANCHOR ──M2──▶ ANCHOR-OPTIONAL ──M3+EMANCIPATION──▶ SOVEREIGN
     │                  │                     │                                  │
     └──────────────────┴─────────────────────┴───── emancipation_level only ───┘
                                  rises (monotone, EM-MONOTONE);
                          any drop without a logged ADD_ANCHOR = DETECTABLE BREACH
```

---

## 4. Reference code — log, Merkle root, `can()`

A FastAPI + SQLite-WAL sketch. **Implementable, not a full build.** No `can()` resolver
or BLAKE2b-chained audit log exists in the repo today (grep confirmed) — this is the
canonical one the rest of the platform can adopt.

### 4.1 SQLite-WAL schema & append (BLAKE2b chain)

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# secubox-annuaire :: log — append-only BLAKE2b-chained journal on SQLite WAL.
import json
import sqlite3
import hashlib
import threading
from pathlib import Path
from typing import Optional

DB_PATH = Path("/var/lib/secubox/annuaire/log.db")
AUDIT_PATH = Path("/var/log/secubox/annuaire/audit.log")  # append-only mirror (CSPN)
GENESIS_HASH = "0" * 64
_LOCK = threading.Lock()  # serialize appends; the chain is strictly ordered


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, isolation_level=None)  # autocommit; we manage txns
    con.execute("PRAGMA journal_mode=WAL;")        # concurrent readers + one writer
    con.execute("PRAGMA synchronous=NORMAL;")      # WAL-safe durability
    con.execute("PRAGMA foreign_keys=ON;")
    con.execute("""
        CREATE TABLE IF NOT EXISTS log (
            height       INTEGER PRIMARY KEY,
            op           TEXT NOT NULL,
            prev_hash    TEXT NOT NULL,
            payload_type TEXT NOT NULL,
            payload      TEXT NOT NULL,   -- canonical JSON
            author       TEXT NOT NULL,
            sig          TEXT NOT NULL,
            entry_hash   TEXT NOT NULL UNIQUE,
            created_at   TEXT NOT NULL
        );
    """)
    con.execute("CREATE INDEX IF NOT EXISTS idx_author ON log(author);")
    return con


def _canonical(payload: dict) -> bytes:
    """Deterministic serialization: sorted keys, no whitespace, UTF-8."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def compute_entry_hash(prev_hash: str, payload_canonical: bytes, sig: str) -> str:
    h = hashlib.blake2b(digest_size=32)
    h.update(bytes.fromhex(prev_hash))
    h.update(payload_canonical)
    h.update(sig.encode())
    return h.hexdigest()


def head(con: sqlite3.Connection) -> tuple[int, str]:
    """Return (height, entry_hash) of the chain head, or (-1, GENESIS_HASH)."""
    row = con.execute("SELECT height, entry_hash FROM log ORDER BY height DESC LIMIT 1").fetchone()
    return (row[0], row[1]) if row else (-1, GENESIS_HASH)


def append(op: str, payload_type: str, payload: dict, author: str, sig: str,
           created_at: str, verify_sig) -> dict:
    """Append a signed object as the next chain link. verify_sig(canonical, sig,
    author_pubkey) -> bool is injected (uses secubox-identity's Ed25519 verify).
    Returns the committed LogEntry as a dict. Raises on a bad signature."""
    canonical = _canonical(payload)
    with _LOCK:                                     # one writer; chain is total-ordered
        con = _connect()
        try:
            prev_height, prev_hash = head(con)
            if not verify_sig(canonical, sig, author):
                raise ValueError("signature verification failed — refusing to chain")
            entry_hash = compute_entry_hash(prev_hash, canonical, sig)
            height = prev_height + 1
            con.execute("BEGIN IMMEDIATE;")
            con.execute(
                "INSERT INTO log VALUES (?,?,?,?,?,?,?,?,?)",
                (height, op, prev_hash, payload_type, canonical.decode(),
                 author, sig, entry_hash, created_at),
            )
            con.execute("COMMIT;")
            _audit_mirror(height, op, author, entry_hash, created_at)
            return {"height": height, "op": op, "prev_hash": prev_hash,
                    "payload_type": payload_type, "payload": payload,
                    "author": author, "sig": sig, "entry_hash": entry_hash,
                    "created_at": created_at}
        finally:
            con.close()


def _audit_mirror(height: int, op: str, author: str, entry_hash: str, created_at: str) -> None:
    """Append-only audit mirror (CSPN immutable log; rotation without truncate)."""
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"height": height, "op": op, "author": author,
                       "entry_hash": entry_hash, "ts": created_at}, sort_keys=True)
    with open(AUDIT_PATH, "a") as fh:
        fh.write(line + "\n")


def verify_chain(con: Optional[sqlite3.Connection] = None) -> dict:
    """Walk the chain; recompute every entry_hash. Any break is a tamper signal.
    This is what an auditing client runs — equivocation/tampering is DETECTABLE."""
    own = con is None
    con = con or _connect()
    try:
        prev = GENESIS_HASH
        n = 0
        for (height, op, prev_hash, payload, sig, entry_hash) in con.execute(
            "SELECT height, op, prev_hash, payload, sig, entry_hash FROM log ORDER BY height"
        ):
            if prev_hash != prev:
                return {"ok": False, "broken_at": height, "reason": "prev_hash mismatch"}
            recomputed = compute_entry_hash(prev_hash, payload.encode(), sig)
            if recomputed != entry_hash:
                return {"ok": False, "broken_at": height, "reason": "entry_hash mismatch"}
            prev = entry_hash
            n += 1
        return {"ok": True, "entries": n, "head": prev}
    finally:
        if own:
            con.close()
```

### 4.2 Merkle root publication

```python
def merkle_root(con: Optional[sqlite3.Connection] = None) -> dict:
    """BLAKE2b Merkle root over all entry_hash leaves, at the current height.
    Witnesses co-sign THIS root (WitnessAttest); clients compare published roots
    across witnesses to detect equivocation (CONIKS)."""
    own = con is None
    con = con or _connect()
    try:
        leaves = [bytes.fromhex(r[0]) for r in
                  con.execute("SELECT entry_hash FROM log ORDER BY height")]
        height = len(leaves) - 1
        if not leaves:
            return {"height": -1, "root": GENESIS_HASH}
        level = leaves
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left  # duplicate odd leaf
                nxt.append(hashlib.blake2b(left + right, digest_size=32).digest())
            level = nxt
        return {"height": height, "root": level[0].hex()}
    finally:
        if own:
            con.close()
```

### 4.3 FastAPI surface (the directory's own endpoints)

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# secubox-annuaire :: api/main.py (sketch)
from fastapi import FastAPI, Depends, HTTPException
from secubox_core.auth import require_jwt           # JWT on every mutating endpoint
from . import log as journal
from .models import (Identity, Attestation, Invitation, Proposal,
                     RevocationNotice, WitnessAttest, Op, now_rfc3339)
from .identity_bridge import verify_sig, did_pubkey  # thin shim over secubox-identity

app = FastAPI(title="SecuBox Annuaire-Miroir", version="0.1.0")


@app.get("/status")                                  # public
async def status():
    return {"module": "annuaire", "merkle": journal.merkle_root(),
            "chain": journal.verify_chain()}

@app.get("/log/verify")                              # public — anyone can audit
async def log_verify():
    return journal.verify_chain()

@app.get("/log/root")                                # public — published root for witnesses
async def log_root():
    return journal.merkle_root()

@app.post("/attest", dependencies=[Depends(require_jwt)])
async def attest(a: Attestation):
    if not a.sig:
        raise HTTPException(400, "unsigned attestation")
    journal.append(Op.ATTEST, "Attestation", a.model_dump(exclude={"sig"}),
                   a.attester, a.sig, a.created_at, verify_sig)
    return {"status": "logged"}

@app.post("/proposal", dependencies=[Depends(require_jwt)])
async def proposal(p: Proposal):
    journal.append(Op.PROPOSAL_OPEN, "Proposal", p.model_dump(exclude={"sig"}),
                   p.proposer, p.sig, p.created_at, verify_sig)
    return {"status": "open", "proposal_id": p.proposal_id, "closes_at": p.closes_at}

@app.post("/revoke", dependencies=[Depends(require_jwt)])
async def revoke(r: RevocationNotice):
    journal.append(Op.REVOKE, "RevocationNotice", r.model_dump(exclude={"sig"}),
                   r.revoker, r.sig, r.created_at, verify_sig)
    return {"status": "revoked", "target": r.target}

@app.post("/witness", dependencies=[Depends(require_jwt)])
async def witness(w: WitnessAttest):
    journal.append(Op.WITNESS, "WitnessAttest", w.model_dump(exclude={"sig"}),
                   w.witness, w.sig, w.observed_at, verify_sig)
    return {"status": "co-signed", "height": w.log_height}
```

### 4.4 The `can()` resolver — the centralized adjudicator

`can()` is the **single point** that turns the graph + log into a yes/no on a concrete
action. It implements the §1.1 *audited reconciliation* test. It is **the** place to
audit authority decisions, and it never trusts an `Attestation` blindly.

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# secubox-annuaire :: can — the centralized access resolver.
from typing import Optional
from . import log as journal
from .models import MemberState

# Minimal right-sets per state. OBSERVED is deliberately near-powerless.
RIGHTS = {
    MemberState.OBSERVED: {"read.public"},
    MemberState.MEMBER:   {"read.public", "attest", "vote", "invite", "report.threat",
                           "name.bind", "service.publish"},
    MemberState.REVOKED:  set(),
}


def can(actor_did: str, action: str, *, context: str, domain: str,
        require_nizk: bool = True, nizk_proof: Optional[bytes] = None,
        verify_nizk=None, store=None) -> dict:
    """Decide whether actor_did may perform `action` on `context` within `domain`.

    Returns {"allow": bool, "reason": str, "reconciled": bool}. The decision is the
    AUDITED RECONCILIATION of §1.1 — name<->key<->membership<->attestation. A missing
    leg yields allow=False with reconciled=False ("unreconciled", NOT trusted)."""
    ident = store.get_identity(actor_did)
    if ident is None:
        return {"allow": False, "reason": "unknown identity", "reconciled": False}

    # (b) self-certification: the name IS the key, intrinsically.
    if ident.self_cert_digest != actor_did.removeprefix("did:plc:"):
        return {"allow": False, "reason": "identity not self-certifying", "reconciled": False}

    # state gate
    if ident.state == MemberState.REVOKED:
        return {"allow": False, "reason": "revoked", "reconciled": True}
    if action not in RIGHTS.get(ident.state, set()):
        return {"allow": False, "reason": f"{ident.state} lacks {action}", "reconciled": True}

    # (c) non-revoked MEMBERSHIP proven by NIZK GK-HAM-HASH, WITHOUT revealing the key.
    #     The proof attests "I am a non-revoked member of the trust graph" — which key
    #     is never disclosed (metadata privacy, §5.3).
    if require_nizk and action != "read.public":
        if not nizk_proof or verify_nizk is None or not verify_nizk(nizk_proof, domain):
            return {"allow": False, "reason": "membership NIZK absent/invalid",
                    "reconciled": False}

    # (d) CONTEXTUAL attestation in-scope — NOT blind transitivity.
    #     We require a direct, non-revoked, in-context, in-domain, unexpired edge,
    #     OR a BOUNDED graft-chain of depth <= max_depth. Trust never flows blindly.
    if action in {"attest", "vote", "invite", "name.bind", "service.publish",
                  "report.threat"}:
        if not store.has_attestation(subject=actor_did, context=context, domain=domain,
                                     max_depth=2):  # bounded; never unbounded WoT
            return {"allow": False, "reason": f"no in-scope attestation for {context}",
                    "reconciled": True}

    return {"allow": True, "reason": "reconciled", "reconciled": True}
```

> **Why `can()` is centralized but the trust is not.** Centralizing the *resolver* gives
> one auditable adjudication path (good for CSPN). It does **not** centralize *trust*:
> the inputs (identities, attestations, NIZK membership, witnesses) are produced
> independently across federated islands. The resolver is a referee, not a sovereign.

---

## 5. Sybil, geo, metadata privacy

### 5.1 Sybil resistance — invitation-grafting + hardware-anchoring

**What makes an identity rare?** We **choose** two mechanisms and **document the
alternatives we reject:**

- **Invitation-grafting (the primary).** You acquire **standing** only because an
  already-trusted node **invited** you (§3.2). The directed `Attestation` edge an invite
  places *is* the scarce thing. Manufacturing identities is cheap (anyone can mint a
  keypair → a `did:plc`), but manufacturing *standing* requires an existing member to
  spend an `Invitation` and **co-stake** their reputation. **Invitation-grafting IS the
  Sybil resistance.**
- **Hardware-anchoring (the multiplier).** **One SecuBox = one node** (BYOH / SecuBox
  model). `Identity.hardware_attest` carries an opaque hardware-anchor attestation that
  raises the **cost of identity manufacturing**: a thousand fake `did`s still need a
  thousand boxes to be hardware-attested members.

**Rejected, and why (named explicitly):**

| Rejected | Reason |
|----------|--------|
| **PoW** | wasteful — burns energy to prove nothing about trustworthiness |
| **PoS** | plutocratic — money buys standing (the anti-goal of §6.5) |
| **Proof-of-personhood** | intrusive — biometrics/ID scanning violates the respect doctrine |

### 5.2 Geo — the dangerous primitive, kept coarse

Geo is a **coarse, consented attribute, NEVER a coordinate.**

- **Jurisdiction label = yes.** `JuridictionTag(isolation_domain, legal_regime,
  consented)` says "this node's data stays under French law / lives in ISD
  `fr-chambery`." Sovereignty, expressed as a **zone**. SCION **Isolation Domains** map
  *directly* onto this — an ISD is a sovereignty boundary, and routing can be confined to
  it, which is exactly the jurisdiction constraint ("data stays under French law").
- **Precise coordinates = never.** There is **no** coordinate field, and the spec
  forbids adding one. The `no_coordinates` validator is the belt; the absent field is the
  braces.
- **Proximity-as-trust only via PSI.** When two nodes need to prove "we are in the same
  domain/zone" *without revealing where*, they run a **Private Set Intersection**: each
  inputs its set of `isolation_domain` memberships; the protocol reveals only the
  *intersection's existence*, not the positions. "Same zone? yes/no" — never "where."

### 5.3 Metadata privacy — the social graph is more sensitive than content

The **metadata** (who attests to whom) is often **more sensitive than content.** Three
mechanisms, layered:

1. **NIZK membership (GK·HAM-HASH).** Membership is proven with the `ZKP-HAM-v1`
   Hamiltonian NIZK (`zkp_prove`/`zkp_verify`, Fiat-Shamir, SHA3-256, soundness
   ≥ 1 − 2⁻¹²⁸). It proves **non-revoked membership in the trust graph WITHOUT revealing
   WHICH key.** `can()` consumes this at step (c). The graph's revocation structure is
   encoded as the public graph `G`; the prover's secret Hamiltonian cycle `H` witnesses
   membership; revoking a member removes the cycle, so a revoked key can no longer prove.
2. **CONIKS privacy-preserving log.** The transparency log is auditable for
   **consistency** (no equivocation) **without exposing the graph in clear** — entries
   commit to bindings via hashes, and clients verify roots and their own entries without
   reading everyone else's social edges.
3. **Onion transport over MirrorNet.** Directory traffic rides metadata-resistant onion
   routing over MirrorNet (the existing transport already targets this), so **who queries
   whom** is not exposed on the wire. **No location disclosure by default.**

---

## 6. Trade-offs & anti-goals — the honest list

For each guarantee the substrate **cannot** make, we **say so** and define how a
violation is **detected.** This section is the heart of the honesty doctrine.

### 6.1 We do NOT guarantee non-equivocation. We make it DETECTABLE.
A malicious log operator *can* show different bindings to different clients. **Detection:**
multiple **`WitnessAttest`** co-signatures over the same `(domain, height)` must agree on
`merkle_root`; a client comparing witness roots sees the fork. CONIKS consistency proofs
flag a client's own entry being silently changed. *Crypto makes betrayal detectable, not
impossible.*

### 6.2 We do NOT guarantee anchors won't betray. We make removal POSSIBLE and the path AUDITABLE.
The founding key / DNS-DANE anchor is trusted **at first**. **Detection & remedy:** the
staged **EMANCIPATE** path (§3.4) lets the community *remove* the founder once milestones
are met; `emancipation_level` is monotone, so a **quiet re-anchoring is a detectable
breach** (any auditor diffing roots sees the level drop without a logged `ADD_ANCHOR`).

### 6.3 NO global-consensus blockchain for trust.
A minimal **append-only log** (did:plc / Rekor-Sigstore / Certificate-Transparency style)
**suffices.** `did:plc` — already in the stack — is **not** a chain. The heavy global
chain is **almost never needed**; at most it is an *option* for human naming (§6.7),
never imposed. Anti-goal: paying global-consensus cost to solve a problem an audited
append-only log already solves.

### 6.4 NO blind trust transitivity (the PGP-WoT failure).
Attestations are **contextual** ("I trust you ON X") and **never** flow blindly. `can()`
requires a **direct or bounded-depth** (`max_depth ≤ 2`) in-context edge. **Detection of
attempted over-reach:** a request that would need unbounded transitivity simply returns
`allow=False, reason="no in-scope attestation"` — there is no silent transitive grant to
detect because there is no silent transitive grant.

### 6.5 NO plutocratic governance by default.
Default quorum is **one voice per attested node** (§3.3). Stake/attestation-depth
weighting is **opt-in** via a logged `QUORUM_REVISION` proposal. **Detection:** if a
domain is running weighted voting, the `Proposal.quorum_rule` field says so *in the log*
— it cannot be applied silently.

### 6.6 NO precise geolocation, ever.
Structural: no coordinate field exists (§5.2). **Detection:** the `no_coordinates`
validator rejects smuggled lat/long at write time; a reviewer auditing the schema sees
there is no field to abuse.

### 6.7 NO global monolith — federation of sovereign islands.
Islands interoperate via the **shared protocol** (signed entries + roots), email/Matrix/
ActivityPub style. A name-blockchain (Namecoin/ENS/Handshake) for human naming is a
**documented option**, selectable per-domain by proposal, **never** the default. The
default Zooko answer is **transparency + assumed auditable anchor + revocability**.

### 6.8 We do NOT claim purity. We claim HONESTY.
Trade-offs are **visible**, roots are **user-chosen**, disclosure is **controlled**. The
user can inspect their trust roots (anchors, witnesses, inviters) and *choose* them. If
the substrate ever pretends to be simultaneously fully open, fully safe, and fully
private, **that itself is the bug** — and the published trade-off table is how a reviewer
catches it.

### 6.9 Honest residual risks (stated, not hidden).
- A **colluding majority of witnesses** can sustain an equivocation an isolated client
  can't disprove → mitigated by witness-redundancy diversity (M3: no operator > ⌊R/3⌋),
  not eliminated.
- **Hardware attestation** depends on a manufacturer root → if BYOH attestation is
  forged at scale, Sybil cost drops to invitation-grafting alone (still non-trivial). This
  dependence is **documented**, not assumed away.
- **PSI / NIZK** are only as private as their implementations; side channels are possible
  → CSPN review + reproducible builds are the mitigation, not a proof of perfection.

---

## 7. The social layer — who, and the path to credible neutrality

"Open" and "safe" ultimately rest on the **social**, not the cryptography. We **name the
actors** and the path.

### 7.1 The named actors

| Actor | Who | Power | Accountability |
|-------|-----|-------|----------------|
| **Protocol maintainers** | CyberMind (Gérald Kerma) + contributors, under CMSD-1.0 | Evolve the protocol & schema | Source-available; changes land via PR + reproducible builds; `CHANGE_PROTOCOL` proposals on-log |
| **Log witnesses / auditors** | Independent operators co-signing roots (`WitnessAttest`) | Make equivocation detectable | Diversity enforced at M3 (no operator > ⌊R/3⌋); their co-signatures are public |
| **Anchor operators** | gk2 today (DNS/DANE for `secubox.in`, founding key, seed rendezvous) | Bootstrap trust | **Removable** via EMANCIPATE once M1–M3 met; monotone weaning makes re-capture detectable |
| **Domain operators** | Each sovereign island's admins | Set local policy, quorum, invites | Bounded to their `isolation_domain`; cannot reach across federation |
| **Members** | Hardware-anchored, invitation-grafted nodes | Attest, vote, invite, publish | Co-stake reputation; revocable; one-voice-per-node by default |

### 7.2 The path to credible neutrality

1. **Open source** — CMSD-1.0 source-available; the protocol, schema, and `can()` resolver
   are inspectable by anyone whose trust they ask for.
2. **Reproducible builds (mandatory)** — *legal/social scaffolding is part of security.* A
   bit-identical rebuild from source is the only credible defence against a backdoored
   binary anchor. This is non-negotiable for the directory just as for every SecuBox
   package.
3. **Chambéry jurisdiction** — a *named, real* legal venue. `JuridictionTag(legal_regime=
   "FR")` is not decoration: it states which law the data lives under, auditable and
   consented.
4. **Staged emancipation** — the founder's privilege is **designed to be removed** (§3.4).
   Credible neutrality is not a promise; it is a **mechanism with milestones**, monotone,
   and detectable on regression.

> The cryptography makes betrayal *detectable*. The social layer — open source +
> reproducible builds + a named jurisdiction + a staged, irreversible weaning of the
> founder — is what makes the *promise not to betray* **credible** rather than merely
> asserted. Where even that cannot be guaranteed, §6 says so and points at the detector.

---

## 8. Open items for the human (TODO)

1. **PSI primitive choice.** §5.2 specifies PSI for proximity-as-trust but does not pin a
   scheme (e.g. ECDH-based DH-PSI vs. OPRF-based). Needs a CSPN-acceptable, reproducible
   implementation decision.
2. **Bridging the C ZKP to Python `can()`.** `zkp-hamiltonian` is C (`ZKP-HAM-v1`). The
   `verify_nizk` hook in `can()` needs a binding (cffi/cython or a thin Unix-socket
   verifier daemon). Mapping the **revocation structure → public graph `G`** (so revoking a
   member destroys their provable cycle) is the substantive design task, deferred here.
3. **Milestone parameters N, M, R.** §3.4 leaves the emancipation thresholds symbolic.
   Choosing concrete N (domains), M (auditors), R (witnesses, with the ⌊R/3⌋ cap) is a
   governance decision, not an engineering one — for the human.
4. **Hardware-attestation root.** §5.1 / §6.9 depend on a BYOH/SecuBox attestation root
   whose trust model is out of scope here; needs its own spec.
5. **Witness recruitment.** Credible neutrality (M2/M3) needs *real, independent* witness
   operators. That is a social/operational recruitment problem, flagged for the human.
6. **Cascade-depth policy.** `RevocationNotice.cascade_depth ≤ 8` is a placeholder bound;
   the per-domain default and whether co-staking cascades are opt-in deserve a policy call.

---

*End of spec. This is a design document — nothing here is built or deployed.*
