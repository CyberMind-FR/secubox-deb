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


# ---------------------------------------------------------------------------
# Service offer + subscription request/response models
# ---------------------------------------------------------------------------


class ServiceOfferRequest(BaseModel):
    provider_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    provider_priv_hex: str
    name: str
    kind: str
    endpoint: str
    scope: Optional[Dict[str, Any]] = None
    approval_mode: str = "auto"
    description: str = ""


class RevokeOfferRequest(BaseModel):
    provider_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    provider_priv_hex: str


class SubscribeRequest(BaseModel):
    subscriber_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    subscriber_priv_hex: str


class SubscriptionActionRequest(BaseModel):
    actor_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    actor_priv_hex: str


class PullServicesRequest(BaseModel):
    base_url: str


# ---------------------------------------------------------------------------
# Service offer + subscription endpoints
# ---------------------------------------------------------------------------


@app.get("/services")
async def list_services():
    """List all non-revoked service offers (public)."""
    from annuaire.verbs import _get_offers  # noqa: PLC0415
    j = get_journal()
    return {"services": _get_offers(j)}


@app.post("/service/offer", dependencies=[Depends(_require_jwt)])
async def post_service_offer(req: ServiceOfferRequest):
    """SERVICE_OFFER: publish a signed service offer."""
    from annuaire.verbs import offer_service  # noqa: PLC0415
    priv = _priv_from_hex(req.provider_priv_hex)
    j = get_journal()
    try:
        offer = offer_service(
            j,
            priv,
            req.provider_did,
            name=req.name,
            kind=req.kind,
            endpoint=req.endpoint,
            scope=req.scope,
            approval_mode=req.approval_mode,
            description=req.description,
        )
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except Exception as e:
        raise HTTPException(400, str(e))
    return offer.model_dump()


@app.post("/service/{service_id}/revoke", dependencies=[Depends(_require_jwt)])
async def revoke_service_offer(service_id: str, req: RevokeOfferRequest):
    """SERVICE_REVOKE_OFFER: withdraw a service offer (provider only)."""
    from annuaire.verbs import revoke_offer  # noqa: PLC0415
    priv = _priv_from_hex(req.provider_priv_hex)
    j = get_journal()
    try:
        result = revoke_offer(j, priv, req.provider_did, service_id)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))
    return result


@app.post("/service/{service_id}/subscribe", dependencies=[Depends(_require_jwt)])
async def subscribe_to_service(service_id: str, req: SubscribeRequest):
    """SERVICE_SUBSCRIBE: subscribe to a service offer (MEMBER only)."""
    from annuaire.verbs import subscribe, subscription_state  # noqa: PLC0415
    priv = _priv_from_hex(req.subscriber_priv_hex)
    j = get_journal()
    try:
        sub = subscribe(j, priv, req.subscriber_did, service_id)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))
    state = subscription_state(j, sub.subscription_id)
    result = sub.model_dump()
    result["state"] = state.value
    return result


@app.get("/subscriptions")
async def list_subscriptions(mine: Optional[str] = None, pending_for: Optional[str] = None):
    """List subscriptions with derived state (public read).

    Optional filters:
      ?mine=<subscriber_did>       — subscriptions by this subscriber
      ?pending_for=<provider_did>  — pending subscriptions for this provider
    """
    from annuaire.verbs import subscription_state, _find_any_offer  # noqa: PLC0415
    from annuaire.model import Op as _Op, SubscriptionState as _SS  # noqa: PLC0415
    j = get_journal()

    # Collect all subscription entries
    subs = []
    for entry in j.iter_entries():
        if entry.op == _Op.SERVICE_SUBSCRIBE and entry.payload_type == "Subscription":
            sub_id = entry.payload.get("subscription_id")
            if sub_id is None:
                continue
            try:
                state = subscription_state(j, sub_id)
            except ValueError:
                continue
            record = dict(entry.payload)
            record["state"] = state.value
            # Resolve provider for this subscription
            offer = _find_any_offer(j, entry.payload.get("service_id", ""))
            record["provider"] = offer.get("provider") if offer else None
            subs.append(record)

    # Apply filters
    if mine:
        subs = [s for s in subs if s.get("subscriber") == mine]
    if pending_for:
        subs = [s for s in subs
                if s.get("provider") == pending_for
                and s.get("state") == _SS.PENDING.value]

    return {"subscriptions": subs}


@app.post("/subscription/{subscription_id}/approve", dependencies=[Depends(_require_jwt)])
async def approve_sub(subscription_id: str, req: SubscriptionActionRequest):
    """SERVICE_APPROVE: approve a subscription (provider only)."""
    from annuaire.verbs import approve_subscription  # noqa: PLC0415
    priv = _priv_from_hex(req.actor_priv_hex)
    j = get_journal()
    try:
        result = approve_subscription(j, priv, req.actor_did, subscription_id)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))
    return result


@app.post("/subscription/{subscription_id}/reject", dependencies=[Depends(_require_jwt)])
async def reject_sub(subscription_id: str, req: SubscriptionActionRequest):
    """SERVICE_REJECT: reject a subscription (provider only)."""
    from annuaire.verbs import reject_subscription  # noqa: PLC0415
    priv = _priv_from_hex(req.actor_priv_hex)
    j = get_journal()
    try:
        result = reject_subscription(j, priv, req.actor_did, subscription_id)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))
    return result


@app.post("/services/pull", dependencies=[Depends(_require_jwt)])
async def pull_services(req: PullServicesRequest):
    """Federation pull: fetch /services from a remote node and ingest valid offers.

    Fetches <base_url>/api/v1/annuaire/services with a 5s timeout.
    For each offer, verifies the signature and ingests into the local journal.
    Never crashes on offline targets — returns partial results with errors.
    """
    import urllib.request  # noqa: PLC0415
    import urllib.error   # noqa: PLC0415
    from annuaire.model import ServiceOffer as _ServiceOffer  # noqa: PLC0415
    from annuaire.verbs import ingest_offer  # noqa: PLC0415
    from annuaire.verbs import _get_offers  # noqa: PLC0415

    j = get_journal()
    ingested = 0
    rejected = 0
    error_msg: Optional[str] = None

    try:
        url = req.base_url.rstrip("/") + "/api/v1/annuaire/services"
        req_http = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req_http, timeout=5) as resp:
            import json as _json  # noqa: PLC0415
            data = _json.loads(resp.read())
        remote_offers: List[Dict[str, Any]] = data.get("services", [])
    except Exception as e:
        return {"ingested": 0, "rejected": 0, "error": str(e)}

    # Skip offers we already have (by service_id) to avoid duplicate key errors
    known_sids = {o.get("service_id") for o in _get_offers(j)}

    for raw in remote_offers:
        sid = raw.get("service_id")
        if sid in known_sids:
            continue  # already ingested
        try:
            provider_pubkey_hex = raw.get("pubkey") or raw.get("provider_pubkey")
            # The offer payload carries no pubkey directly — we need to resolve it.
            # For now, try to find the pubkey from the local identity store.
            # If the provider is unknown locally, we cannot verify — skip safely.
            if not provider_pubkey_hex:
                # Try resolving from local log
                from annuaire.verbs import _get_inviter_pubkey  # noqa: PLC0415
                provider_pubkey_hex = _get_inviter_pubkey(j, raw.get("provider", ""))
            if not provider_pubkey_hex:
                rejected += 1
                continue
            # Reconstruct ServiceOffer (sig must be present)
            offer_obj = _ServiceOffer(**raw)
            ingest_offer(j, offer_obj, provider_pubkey_hex)
            ingested += 1
            known_sids.add(sid)
        except Exception as exc:
            rejected += 1

    result: Dict[str, Any] = {"ingested": ingested, "rejected": rejected}
    if error_msg:
        result["error"] = error_msg
    return result


# ---------------------------------------------------------------------------
# Directory endpoints — NodeRecord + ConfigBlob + log federation (gondwana P1, #768)
# ---------------------------------------------------------------------------


class PublishNodeRequest(BaseModel):
    node_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    node_priv_hex: str
    node_id: str
    boxname: str
    pubkey_wg: str
    mesh_ip: str
    ddns: str
    endpoint: Optional[str] = None


class PublishConfigRequest(BaseModel):
    publisher_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    publisher_priv_hex: str
    scope: str
    version: int = Field(..., ge=0)
    content_hash: str
    payload: Optional[Dict[str, Any]] = None
    payload_uri: Optional[str] = None
    valid_until: Optional[str] = None
    config_id: Optional[str] = None


class RevokeConfigRequest(BaseModel):
    publisher_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    publisher_priv_hex: str


class PullLogRequest(BaseModel):
    base_url: str


@app.get("/nodes")
async def list_nodes():
    """List the latest self-authored NodeRecord per node (public — the peer registry)."""
    from annuaire.verbs import _get_nodes  # noqa: PLC0415
    return {"nodes": _get_nodes(get_journal())}


@app.get("/config")
async def list_config(scope: Optional[str] = None):
    """List current (non-revoked) config blobs, optionally filtered by scope (public)."""
    from annuaire.verbs import _get_configs  # noqa: PLC0415
    configs = _get_configs(get_journal())
    if scope is not None:
        configs = [c for c in configs if c.get("scope") == scope]
    return {"configs": configs}


@app.get("/log/export")
async def export_log():
    """Export the full signed log for a peer to pull (public).

    Distinct from GET /log (a truncated recent view): this returns every entry
    with its author_pubkey so a consumer can verify and re-append.
    """
    from annuaire.verbs import export_entries  # noqa: PLC0415
    return {"entries": export_entries(get_journal())}


@app.post("/node/publish", dependencies=[Depends(_require_jwt)])
async def post_node_publish(req: PublishNodeRequest):
    """NODE_PUBLISH: publish this node's signed registry record into the directory."""
    from annuaire.verbs import publish_node  # noqa: PLC0415
    priv = _priv_from_hex(req.node_priv_hex)
    try:
        rec = publish_node(
            get_journal(), priv, req.node_did,
            node_id=req.node_id, boxname=req.boxname, pubkey_wg=req.pubkey_wg,
            mesh_ip=req.mesh_ip, ddns=req.ddns, endpoint=req.endpoint,
        )
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except Exception as e:
        raise HTTPException(400, str(e))
    return rec.model_dump()


@app.post("/config/publish", dependencies=[Depends(_require_jwt)])
async def post_config_publish(req: PublishConfigRequest):
    """CONFIG_PUBLISH: publish a signed, versioned config blob."""
    from annuaire.verbs import publish_config  # noqa: PLC0415
    priv = _priv_from_hex(req.publisher_priv_hex)
    try:
        blob = publish_config(
            get_journal(), priv, req.publisher_did,
            scope=req.scope, version=req.version, content_hash=req.content_hash,
            payload=req.payload, payload_uri=req.payload_uri,
            valid_until=req.valid_until, config_id=req.config_id,
        )
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except Exception as e:
        raise HTTPException(400, str(e))
    return blob.model_dump()


@app.post("/config/revoke", dependencies=[Depends(_require_jwt)])
async def post_config_revoke(req: RevokeConfigRequest, config_id: str):
    """CONFIG_REVOKE: withdraw a config blob (publisher only). config_id is a query param."""
    from annuaire.verbs import revoke_config  # noqa: PLC0415
    priv = _priv_from_hex(req.publisher_priv_hex)
    try:
        result = revoke_config(get_journal(), priv, req.publisher_did, config_id)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(404, str(e))
    return result


@app.post("/log/pull", dependencies=[Depends(_require_jwt)])
async def pull_log(req: PullLogRequest):
    """Federation pull: fetch /log/export from a peer and merge valid entries.

    Mirrors /services/pull but for the whole directory. Never crashes on an
    offline peer — returns {ingested, skipped, rejected, error?}.
    """
    import json as _json          # noqa: PLC0415
    import urllib.request         # noqa: PLC0415
    from annuaire.verbs import import_entries  # noqa: PLC0415

    try:
        url = req.base_url.rstrip("/") + "/api/v1/annuaire/log/export"
        http_req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(http_req, timeout=5) as resp:
            data = _json.loads(resp.read())
        entries = data.get("entries", [])
    except Exception as e:
        return {"ingested": 0, "skipped": 0, "rejected": 0, "error": str(e)}

    return import_entries(get_journal(), entries)


# ---------------------------------------------------------------------------
# Directory replication background loop (gondwana P1, #768)
#
# Runs IN-PROCESS (this service owns the journal → no JWT, no second writer).
# secubox-p2p owns the peer list (wg_mesh.json); we only read it. Disabled via
# ANNUAIRE_DIR_SYNC=0 (tests / off-box). The blocking fetch+merge runs in a
# worker thread so it never stalls the event loop.
# ---------------------------------------------------------------------------


@app.on_event("startup")
async def _start_dir_sync():
    import asyncio  # noqa: PLC0415
    if os.environ.get("ANNUAIRE_DIR_SYNC", "1") != "1":
        return
    asyncio.create_task(_dir_sync_loop())


async def _dir_sync_loop():
    import asyncio  # noqa: PLC0415
    from annuaire.mesh_sync import read_mesh_peers, sync_once  # noqa: PLC0415

    interval = int(os.environ.get("ANNUAIRE_DIR_SYNC_INTERVAL", "120"))
    peers_path = os.environ.get("ANNUAIRE_PEERS_PATH", "/var/lib/secubox/p2p/wg_mesh.json")
    while True:
        try:
            peers = read_mesh_peers(peers_path)
            if peers:
                await asyncio.to_thread(sync_once, get_journal(), peers)
        except Exception:
            pass
        await asyncio.sleep(interval)
