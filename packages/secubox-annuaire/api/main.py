# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: api/main.py
FastAPI app for the Annuaire·Miroir trust substrate.

Root path: /api/v1/annuaire
Socket:    /run/secubox/annuaire.sock (Unix socket, no TCP)
DB:        /var/lib/secubox/annuaire/journal.db (override via ANNUAIRE_DB_PATH env)

Read endpoints: public (no JWT required).
Mutating endpoints: require JWT via Depends(require_jwt).
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Optional JWT dependency — gracefully degrade when secubox_core is not installed
# (allows off-box smoke-test: python3 -c "from api import main; print(main.app.root_path)")
# ---------------------------------------------------------------------------
try:
    from secubox_core.auth import require_jwt as _require_jwt  # type: ignore
    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False

    async def _require_jwt():  # type: ignore[misc]
        """No-op JWT guard when secubox_core is not installed (dev / off-box)."""
        return None


def require_jwt():
    """Return the real or stub JWT dependency."""
    return Depends(_require_jwt)


# ---------------------------------------------------------------------------
# Journal path
# ---------------------------------------------------------------------------

_DB_PATH = os.environ.get(
    "ANNUAIRE_DB_PATH",
    "/var/lib/secubox/annuaire/journal.db",
)

# Lazy singleton journal — created on first use so import itself doesn't create files
_journal = None


def get_journal():
    global _journal
    if _journal is None:
        # Import here so the module can be imported without touching the FS
        from annuaire.log import Journal  # noqa: PLC0415
        _journal = Journal(_DB_PATH)
    return _journal


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SecuBox Annuaire-Miroir",
    version="0.1.0",
    root_path="/api/v1/annuaire",
    description=(
        "The Annuaire·Miroir trust substrate — federated, self-certifying, "
        "BLAKE2b-chained, JWT-gated. §3 AUTO-ADD / INVITE / PROPOSAL / EMANCIPATE."
    ),
)

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class AutoAddRequest(BaseModel):
    did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    pubkey: str
    self_cert_digest: str
    sig: str
    signer_did: Optional[str] = None
    hardware_attest: Optional[str] = None
    jurisdiction: List[Dict[str, Any]] = Field(default_factory=list)


class InviteRequest(BaseModel):
    inviter_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    # priv key NOT transmitted over the wire — the API is meant to be called
    # by the inviter's own process that holds the key; this endpoint accepts
    # the already-signed invitation for logging.
    # For server-side signing (trusted node), provide inviter_priv_hex.
    inviter_priv_hex: Optional[str] = Field(
        default=None,
        description="Inviter's raw Ed25519 private key hex (32 bytes, 64 hex chars). "
                    "Only send to a trusted endpoint.",
    )
    domain: str
    rights: List[str] = Field(default_factory=list)
    ttl_s: int = 86400
    max_uses: int = 1


class JoinRequest(BaseModel):
    """Accept an invitation (mirrors master-link/join)."""
    invitee_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    invitee_priv_hex: str = Field(
        ...,
        description="Invitee's raw Ed25519 private key hex (32 bytes, 64 hex chars).",
    )
    invitation: Dict[str, Any] = Field(..., description="The full Invitation object as JSON.")


class ProposalRequest(BaseModel):
    proposer_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    proposer_priv_hex: str
    ptype: str
    body: Dict[str, Any] = Field(default_factory=dict)
    window_s: int = 604800
    quorum_rule: str = "one_node_one_voice"
    quorum_threshold: float = 0.6


class VoteRequest(BaseModel):
    voter_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    voter_priv_hex: str
    choice: str  # "for" or "against"


class RevokeRequest(BaseModel):
    revoker_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    revoker_priv_hex: str
    target_did: str
    reason: str
    cascade_depth: int = 0


class EmancipateRequest(BaseModel):
    proposer_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    proposer_priv_hex: str
    milestone_evidence: Dict[str, Any]
    founder_did: Optional[str] = None


class CanRequest(BaseModel):
    subject: str
    action: str
    target: str
    domain: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _priv_from_hex(priv_hex: str) -> bytes:
    try:
        b = bytes.fromhex(priv_hex)
    except ValueError:
        raise HTTPException(400, "invalid private key hex")
    if len(b) != 32:
        raise HTTPException(400, f"private key must be 32 bytes, got {len(b)}")
    return b


# ---------------------------------------------------------------------------
# Health / public read endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    """Liveness probe — always returns 200 if the process is up."""
    return {"status": "ok", "module": "annuaire"}


@app.get("/status")
async def status():
    """Global status: merkle root + chain integrity."""
    j = get_journal()
    ok, broken_at = j.verify_chain()
    root = j.merkle_root()
    tip = j.tip()
    return {
        "module": "annuaire",
        "chain_ok": ok,
        "chain_broken_at": broken_at,
        "merkle_root": root,
        "tip_height": tip.height if tip else -1,
    }


@app.get("/log")
async def log_recent(limit: int = 20):
    """Return recent log entries (oldest-first, up to *limit*)."""
    j = get_journal()
    entries = list(j.iter_entries())
    recent = entries[-limit:] if len(entries) > limit else entries
    return [e.model_dump() for e in recent]


@app.get("/verify-chain")
async def verify_chain():
    """Walk the BLAKE2b chain; detect tampering. Public — anyone may audit."""
    j = get_journal()
    ok, broken_at = j.verify_chain()
    return {"ok": ok, "broken_at": broken_at}


@app.get("/merkle-root")
async def merkle_root():
    """Current BLAKE2b Merkle root over all entry_hash leaves."""
    j = get_journal()
    root = j.merkle_root()
    tip = j.tip()
    return {"root": root, "height": tip.height if tip else -1}


@app.get("/can")
async def can_query(subject: str, action: str, target: str, domain: str):
    """Ask the can() resolver whether *subject* may *action* on *target* in *domain*."""
    from annuaire.resolver import can  # noqa: PLC0415
    j = get_journal()
    decision = can(j, subject_did=subject, action=action, target=target, domain=domain)
    return {"allowed": decision.allowed, "reasons": decision.reasons}


@app.get("/proposal/{proposal_id}")
async def get_proposal_tally(proposal_id: str):
    """Tally the votes on a proposal and return the computed outcome."""
    from annuaire.verbs import tally  # noqa: PLC0415
    j = get_journal()
    try:
        result = tally(j, proposal_id)
    except ValueError as e:
        raise HTTPException(404, str(e))
    return result


# ---------------------------------------------------------------------------
# Mutating endpoints — require JWT
# ---------------------------------------------------------------------------


@app.post("/auto-add", dependencies=[Depends(_require_jwt)])
async def auto_add(req: AutoAddRequest):
    """AUTO-ADD: make a peer visible as OBSERVED (never confers MEMBER standing)."""
    from annuaire.model import Identity  # noqa: PLC0415
    from annuaire.verbs import auto_add as _auto_add  # noqa: PLC0415
    j = get_journal()
    try:
        ident = Identity(
            did=req.did,
            pubkey=req.pubkey,
            self_cert_digest=req.self_cert_digest,
            sig=req.sig,
            signer_did=req.signer_did,
            hardware_attest=req.hardware_attest,
            jurisdiction=req.jurisdiction,
        )
        result = _auto_add(j, ident)
    except Exception as e:
        raise HTTPException(400, str(e))
    return {"status": "observed", "did": result.did, "state": result.state.value}


@app.post("/invite", dependencies=[Depends(_require_jwt)])
async def invite(req: InviteRequest):
    """INVITE: issue a signed, scoped Invitation capability."""
    from annuaire.verbs import invite as _invite  # noqa: PLC0415
    if not req.inviter_priv_hex:
        raise HTTPException(400, "inviter_priv_hex required for server-side signing")
    priv = _priv_from_hex(req.inviter_priv_hex)
    j = get_journal()
    try:
        inv = _invite(
            j,
            priv,
            req.inviter_did,
            domain=req.domain,
            rights=req.rights,
            ttl_s=req.ttl_s,
            max_uses=req.max_uses,
        )
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except Exception as e:
        raise HTTPException(400, str(e))
    return inv.model_dump()


@app.post("/join", dependencies=[Depends(_require_jwt)])
async def join(req: JoinRequest):
    """JOIN (accept invite): verify capability → OBSERVED→MEMBER transition."""
    from annuaire.model import Invitation  # noqa: PLC0415
    from annuaire.verbs import accept_invite  # noqa: PLC0415
    priv = _priv_from_hex(req.invitee_priv_hex)
    j = get_journal()
    try:
        inv = Invitation(**req.invitation)
        result = accept_invite(j, priv, req.invitee_did, inv)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except Exception as e:
        raise HTTPException(400, str(e))
    return {"status": "member", "did": result.did, "state": result.state.value}


@app.post("/proposal", dependencies=[Depends(_require_jwt)])
async def proposal(req: ProposalRequest):
    """PROPOSAL: open a governance proposal."""
    from annuaire.model import ProposalType, QuorumRule  # noqa: PLC0415
    from annuaire.verbs import propose  # noqa: PLC0415
    priv = _priv_from_hex(req.proposer_priv_hex)
    j = get_journal()
    try:
        ptype = ProposalType(req.ptype)
        qrule = QuorumRule(req.quorum_rule)
        p = propose(
            j,
            priv,
            req.proposer_did,
            ptype=ptype,
            body=req.body,
            window_s=req.window_s,
            quorum_rule=qrule,
            quorum_threshold=req.quorum_threshold,
        )
    except (ValueError, PermissionError) as e:
        raise HTTPException(400, str(e))
    return p.model_dump()


@app.post("/proposal/{proposal_id}/vote", dependencies=[Depends(_require_jwt)])
async def vote(proposal_id: str, req: VoteRequest):
    """VOTE: cast a signed vote on a proposal (one-voice-per-node enforced)."""
    from annuaire.verbs import vote as _vote  # noqa: PLC0415
    priv = _priv_from_hex(req.voter_priv_hex)
    j = get_journal()
    try:
        result = _vote(j, priv, req.voter_did, proposal_id, req.choice)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return result


@app.post("/revoke", dependencies=[Depends(_require_jwt)])
async def revoke(req: RevokeRequest):
    """REVOKE: withdraw standing (bounded cascade, never blind-transitive)."""
    from annuaire.verbs import revoke as _revoke  # noqa: PLC0415
    priv = _priv_from_hex(req.revoker_priv_hex)
    j = get_journal()
    try:
        notice = _revoke(
            j,
            priv,
            req.revoker_did,
            req.target_did,
            req.reason,
            cascade_depth=req.cascade_depth,
        )
    except Exception as e:
        raise HTTPException(400, str(e))
    return notice.model_dump()


@app.post("/emancipate", dependencies=[Depends(_require_jwt)])
async def emancipate(req: EmancipateRequest):
    """EMANCIPATE: post an Emancipation proposal (EM-MONOTONE + milestone-gated)."""
    from annuaire.verbs import emancipate as _emancipate  # noqa: PLC0415
    priv = _priv_from_hex(req.proposer_priv_hex)
    j = get_journal()
    try:
        result = _emancipate(
            j,
            priv,
            req.proposer_did,
            milestone_evidence=req.milestone_evidence,
            founder_did=req.founder_did,
        )
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return result
