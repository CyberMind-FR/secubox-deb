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

import asyncio
import concurrent.futures
import json
import time
from datetime import datetime, timezone
import urllib.error
import urllib.request
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from secubox_core.auth import require_lecture
from secubox_core import auth as _auth


async def lecture_ou_pair(request: Request) -> Dict[str, Any]:
    """Lecture gardée (#1256) SAUF pour un pair du maillage (#1530).

    /services, /log/export et /fleet/self sont PUBLICS par conception : ce sont
    des enregistrements signés que le pair vérifie. Depuis #1256 ils exigeaient
    un jeton, et plus aucune box ne lisait celles des autres : la Flotte ne
    montrait que soi, la réplication du journal s'était arrêtée. La marque
    X-SecuBox-Maillage n'est posée que par l'écouteur wg-mesh (:8799,
    10.10.0.0/24) et vidée par secubox-proxy.conf partout ailleurs."""
    if request.headers.get("X-SecuBox-Maillage", "").strip() == "1":
        return {"sub": None, "pair_maillage": True}
    creds = await _auth._bearer(request)
    return await require_lecture(request, creds)
from pydantic import BaseModel, Field, field_validator

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
# Fleet metrics (feat/fleet-metrics, Task 4) — pure modules, no FS/DB touched
# on import, safe to bind at module scope (and lets tests monkeypatch
# apimain.fleet_store / apimain.mesh_sync directly, mirroring apimain._centers_ctl).
# ---------------------------------------------------------------------------
from annuaire import fleet, fleet_store, mesh_sync  # noqa: E402


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


@app.get("/status", dependencies=[Depends(require_lecture)])
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


@app.get("/log", dependencies=[Depends(require_lecture)])
async def log_recent(limit: int = 20):
    """Return recent log entries (oldest-first, up to *limit*)."""
    j = get_journal()
    entries = list(j.iter_entries())
    recent = entries[-limit:] if len(entries) > limit else entries
    return [e.model_dump() for e in recent]


@app.get("/verify-chain", dependencies=[Depends(require_lecture)])
async def verify_chain():
    """Walk the BLAKE2b chain; detect tampering. Public — anyone may audit."""
    j = get_journal()
    ok, broken_at = j.verify_chain()
    return {"ok": ok, "broken_at": broken_at}


@app.get("/merkle-root", dependencies=[Depends(require_lecture)])
async def merkle_root():
    """Current BLAKE2b Merkle root over all entry_hash leaves."""
    j = get_journal()
    root = j.merkle_root()
    tip = j.tip()
    return {"root": root, "height": tip.height if tip else -1}


@app.get("/can", dependencies=[Depends(require_lecture)])
async def can_query(subject: str, action: str, target: str, domain: str):
    """Ask the can() resolver whether *subject* may *action* on *target* in *domain*."""
    from annuaire.resolver import can  # noqa: PLC0415
    j = get_journal()
    decision = can(j, subject_did=subject, action=action, target=target, domain=domain)
    return {"allowed": decision.allowed, "reasons": decision.reasons}


@app.get("/proposal/{proposal_id}", dependencies=[Depends(require_lecture)])
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


AUDIT_DROITS = Path("/var/log/secubox/audit.log")


def _ip_pair(request: Request) -> str:
    """Adresse source vue par l'écouteur wg-mesh (secubox-proxy.conf pose X-Real-IP = $remote_addr)."""
    return request.headers.get("X-Real-IP", "").strip()[:45]


def _auditer_refus(ip: str, service: str, raison: str) -> None:
    """Refus d'un service du maillage (#3305) dans le journal d'audit (ajout seul) ; un échec d'écriture ne rend pas le service."""
    ligne = json.dumps({"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "module": "annuaire",
                        "action": "droit_maillage_refus", "pair": ip, "service": service, "raison": raison}, ensure_ascii=False)
    try:
        with open(AUDIT_DROITS, "a", encoding="utf-8") as f:
            f.write(ligne + "\n")
    except OSError:
        pass


async def exiger_droit(request: Request, ident: Dict[str, Any], service: str) -> None:
    """Pair du maillage (marque posée par l'écouteur :8799) : 403 si son abonnement n'inclut pas `service` (#3305).
    Un administrateur (jeton) n'est jamais concerné."""
    if not ident.get("pair_maillage"):
        return
    from annuaire import droits as D  # noqa: PLC0415
    ip = _ip_pair(request)
    ok, raison = await asyncio.to_thread(D.decider, ip, service, D.DROITS_DEFAUT, D.PAIRS_DEFAUT)
    if not ok:
        _auditer_refus(ip, service, raison)
        raise HTTPException(403, f"service du maillage non inclus dans l'abonnement ({raison})")


@app.get("/droits/self", dependencies=[Depends(lecture_ou_pair)])
async def droits_self(request: Request):
    """Droits du pair appelant (#3305), lus par la box pour couper ses synchros quand son abonnement ne les inclut plus."""
    from annuaire import droits as D  # noqa: PLC0415
    return await asyncio.to_thread(D.droits_de, _ip_pair(request), D.DROITS_DEFAUT, D.PAIRS_DEFAUT)


@app.get("/services")
async def list_services(request: Request, ident: Dict[str, Any] = Depends(lecture_ou_pair)):
    """List all non-revoked service offers (public)."""
    from annuaire.verbs import _get_offers  # noqa: PLC0415
    await exiger_droit(request, ident, "annuaire-offres")
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


@app.get("/subscriptions", dependencies=[Depends(require_lecture)])
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
            # The remote /services response carries the provider's pubkey as
            # transport metadata (see verbs._enrich_offer). This is what makes
            # trustless federation between strangers possible: ingest_offer
            # checks did_from_pubkey(pubkey) == provider, so a carried pubkey
            # cannot lie about whose offer this is.
            provider_pubkey_hex = raw.get("provider_pubkey") or raw.get("pubkey")
            if not provider_pubkey_hex:
                # Fallback: a provider we already host locally (re-export).
                # A stranger with no carried pubkey cannot be verified → skip.
                from annuaire.verbs import _get_inviter_pubkey  # noqa: PLC0415
                provider_pubkey_hex = _get_inviter_pubkey(j, raw.get("provider", ""))
            if not provider_pubkey_hex:
                rejected += 1
                continue
            # Reconstruct the ServiceOffer from model fields only — provider_pubkey
            # is transport metadata (not a model field, not in the signed bytes)
            # and would trip the model's extra=forbid.
            allowed = set(_ServiceOffer.model_fields)
            offer_obj = _ServiceOffer(**{k: v for k, v in raw.items() if k in allowed})
            ingest_offer(j, offer_obj, provider_pubkey_hex)  # self-certifies + verifies sig
            ingested += 1
            known_sids.add(sid)
        except Exception:
            rejected += 1

    result: Dict[str, Any] = {"ingested": ingested, "rejected": rejected}
    if error_msg:
        result["error"] = error_msg
    return result


# ---------------------------------------------------------------------------
# MirrorNet v1 (#3647) — gestes signés PAR CE NŒUD, et export pour secubox-mirrornet
# ---------------------------------------------------------------------------
# Les routes /service/... historiques reçoivent la clé privée dans la requête. MirrorNet tourne sous un compte dédié
# qui ne doit JAMAIS lire node.key : ces routes /self/... signent ici, dans le processus propriétaire de la clé
# (compte secubox), comme _publish_self_node. Garde : administrateur réel (require_jwt) ; MirrorNet relaie le jeton de
# l'administrateur qui l'appelle. Chaque geste est écrit dans audit.log puis l'export est rafraîchi.

MIRRORNET_EXPORT = Path(os.environ.get("ANNUAIRE_MIRRORNET_EXPORT", "/var/lib/secubox/annuaire/mirrornet-export.json"))
_JOIGNABILITE: Dict[str, Dict[str, Any]] = {}     # mesh_ip -> {"ok_le", "echec_depuis"}
_EXPORT_CACHE: Dict[str, Any] = {"hauteur": None, "donnees": None}


def _cle_du_noeud():
    """(clé privée, did) de CE nœud ; 503 tant que `annuairectl init` n'a pas créé la clé, ou si la garde
    d'administrateur est indisponible (secubox_core absent : la garde de repli laisserait tout passer)."""
    if not _JWT_AVAILABLE:
        raise HTTPException(503, "garde d'administrateur indisponible : gestes signés refusés")
    key_path = os.environ.get("ANNUAIRE_KEY_PATH", "/etc/secubox/secrets/annuaire/node.key")
    try:
        from annuaire.crypto import did_from_pubkey, public_from_private  # noqa: PLC0415
        with open(key_path, "r", encoding="ascii") as fh:
            priv = bytes.fromhex(fh.read().strip())
        if len(priv) != 32:
            raise ValueError
        return priv, did_from_pubkey(public_from_private(priv))
    except (OSError, ValueError):
        raise HTTPException(503, "identité du nœud absente (annuairectl init)") from None


def _auditer_mirrornet(action: str, ident: Any, **details: Any) -> None:
    """Le journal d'audit commun appartient à `secubox` : l'annuaire y écrit les gestes MirrorNet, avec l'administrateur
    qui les a ordonnés (le compte de secubox-mirrornet n'a, lui, aucun droit d'écriture sur ce journal)."""
    par = ident.get("sub") if isinstance(ident, dict) else None
    ligne = json.dumps({"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "module": "annuaire",
                        "action": action, "par": par, **details}, ensure_ascii=False)
    try:
        with open(AUDIT_DROITS, "a", encoding="utf-8") as f:
            f.write(ligne + "\n")
    except OSError:
        logging.getLogger("secubox.annuaire").warning("audit.log non écrit : %s", ligne)


JOIGNABILITE_ETAT = Path(os.environ.get("ANNUAIRE_JOIGNABILITE", "/var/lib/secubox/annuaire/joignabilite.json"))
_VERROU_JOIGN = threading.Lock()


def _charger_joignabilite() -> None:
    """Au démarrage : `echec_depuis` survit à un redémarrage (sinon la période de grâce repartirait de zéro)."""
    try:
        d = json.loads(JOIGNABILITE_ETAT.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if isinstance(d, dict):
        with _VERROU_JOIGN:
            for ip, v in d.items():
                if isinstance(ip, str) and isinstance(v, dict):
                    _JOIGNABILITE[ip] = {"ok_le": v.get("ok_le"), "echec_depuis": v.get("echec_depuis")}


def _noter_joignabilite(suivi: Dict[str, bool]) -> None:
    """Seules les TRANSITIONS sont notées (`ok_le` = retour à la joignabilité, `echec_depuis` = premier échec) : l'export
    ne change pas à chaque passe de 20 s, et l'état est persisté pour survivre à un redémarrage."""
    maintenant = datetime.now(timezone.utc).isoformat()
    change = False
    with _VERROU_JOIGN:
        for ip, joint in suivi.items():
            e = _JOIGNABILITE.setdefault(ip, {"ok_le": None, "echec_depuis": None})
            if joint and (e.get("echec_depuis") or not e.get("ok_le")):
                e["ok_le"], e["echec_depuis"], change = maintenant, None, True
            elif not joint and not e.get("echec_depuis"):
                e["echec_depuis"], change = maintenant, True
        copie = json.dumps(_JOIGNABILITE)
    if change:
        try:
            tmp = JOIGNABILITE_ETAT.with_name(".joignabilite.json.tmp")
            tmp.write_text(copie, encoding="utf-8")
            os.replace(tmp, JOIGNABILITE_ETAT)
        except OSError as e:
            logging.getLogger("secubox.annuaire.sync").warning("joignabilité non persistée : %s", e)


def _exporter_mirrornet() -> None:
    """Dépose l'export MirrorNet ; la partie journal n'est recalculée que si la hauteur PERTINENTE (service_*,
    identités, nœuds, révocations) a changé. Jamais d'exception vers l'appelant (synchronisation, route)."""
    try:
        from annuaire import mirrornet_export as MX  # noqa: PLC0415
        j = get_journal()
        hauteur = MX.hauteur_pertinente(j)
        if _EXPORT_CACHE["hauteur"] != hauteur or _EXPORT_CACHE["donnees"] is None:
            _EXPORT_CACHE["donnees"] = MX.construire(j, _self_did_best_effort(), {})
            _EXPORT_CACHE["hauteur"] = hauteur
        ip_vers_did = _EXPORT_CACHE["donnees"].get("_ip_vers_did", {})
        with _VERROU_JOIGN:
            joign = {ip_vers_did[ip]: dict(v) for ip, v in _JOIGNABILITE.items() if ip in ip_vers_did}
        MX.ecrire(dict(_EXPORT_CACHE["donnees"], hauteur=hauteur, joignabilite=joign), MIRRORNET_EXPORT)
    except Exception as e:  # noqa: BLE001
        logging.getLogger("secubox.annuaire.sync").warning("export MirrorNet non écrit : %s", e)


def _abonnement_en_cours(j, abonne: str, service_id: str) -> Optional[str]:
    """Identifiant d'un abonnement de `abonne` à `service_id` encore en cours (en attente ou approuvé, non échu), ou
    None : l'annuaire refuse un second abonnement, même sans clé d'idempotence (deux requêtes simultanées)."""
    from annuaire.model import Op as _Op, SubscriptionState as _SS  # noqa: PLC0415
    from annuaire.verbs import _instant, echeance_abonnement, subscription_state  # noqa: PLC0415
    maintenant = datetime.now(timezone.utc)
    for e in j.iter_entries(ops=("service_subscribe",)):
        p = e.payload
        if e.op != _Op.SERVICE_SUBSCRIBE or p.get("subscriber") != abonne or p.get("service_id") != service_id:
            continue
        sid = p.get("subscription_id")
        if subscription_state(j, sid) not in (_SS.PENDING, _SS.APPROVED):
            continue
        ech = _instant(echeance_abonnement(j, sid, maintenant))
        if ech is None or ech > maintenant:
            return sid
    return None


class SelfOfferRequest(BaseModel):
    model_config = {"extra": "forbid"}
    name: str = Field(..., min_length=1, max_length=80)
    kind: str = Field(..., pattern=r"^[a-z][a-z0-9_-]{1,23}$")
    endpoint: str = Field(..., min_length=1, max_length=256)
    approval_mode: str = Field("pending", pattern=r"^(auto|pending)$")
    description: str = Field("", max_length=500)
    version: Optional[str] = Field(None, max_length=64)
    compat: Optional[Dict[str, Any]] = None
    tarif: Optional[Dict[str, Any]] = None
    quotas: Optional[Dict[str, int]] = None
    classe: Optional[str] = Field(None, pattern=r"^(public|communaute|prive)$")
    duree_s: Optional[int] = Field(None, gt=0, le=10 * 365 * 86400)
    grace_s: Optional[int] = Field(None, ge=0, le=90 * 86400)
    sonde: Optional[str] = Field(None, max_length=256, pattern=r"^/[A-Za-z0-9._/~-]*$")

    @field_validator("quotas")
    @classmethod
    def _quotas(cls, v):
        if v is not None and (len(v) > 8 or any(len(k) > 32 or x < 0 or x > 10 ** 15 for k, x in v.items())):
            raise ValueError("quotas : 8 clés au plus, entiers de 0 à 10^15")
        return v

    @field_validator("compat")
    @classmethod
    def _compat(cls, v):
        if v is not None and len(json.dumps(v)) > 1024:
            raise ValueError("compat : 1 Kio au plus")
        return v


class SelfSubscribeRequest(BaseModel):
    model_config = {"extra": "forbid"}
    version: Optional[str] = Field(None, max_length=64)
    # Fournisseur évalué par MirrorNet : l'abonnement le porte, signé ; s'il diffère de celui de l'offre, refus.
    provider: Optional[str] = Field(None, pattern=r"^did:plc:[0-9a-f]{32}$")


class SelfCancelRequest(BaseModel):
    model_config = {"extra": "forbid"}
    motif: str = Field("", max_length=200)


def _geste(fn, *args, **kwargs):
    """Exécute un verbe signé ; PermissionError → 403, ValueError → 409 (état incompatible) ou 422 (entrée)."""
    try:
        return fn(*args, **kwargs)
    except PermissionError as e:
        raise HTTPException(403, str(e)) from None
    except ValueError as e:
        raise HTTPException(409, str(e)) from None


@app.post("/self/service/offer")
async def self_offer(req: SelfOfferRequest, ident: Dict[str, Any] = Depends(_require_jwt)):
    """Publie une offre de CE nœud (champs MirrorNet facultatifs), signée par node.key."""
    from annuaire.verbs import offer_service  # noqa: PLC0415
    priv, did = _cle_du_noeud()
    champs = req.model_dump(exclude={"name", "kind", "endpoint", "approval_mode", "description"})
    try:
        offre = await asyncio.to_thread(offer_service, get_journal(), priv, did, name=req.name, kind=req.kind,
                                        endpoint=req.endpoint, approval_mode=req.approval_mode,
                                        description=req.description, **champs)
    except PermissionError as e:
        raise HTTPException(403, str(e)) from None
    except ValueError as e:                      # pydantic.ValidationError en hérite : tarif, classe…
        raise HTTPException(422, str(e)) from None
    _auditer_mirrornet("mirrornet_offre_publiee", ident, service_id=offre.service_id, nom=req.name, kind=req.kind)
    await asyncio.to_thread(_exporter_mirrornet)
    return offre.model_dump()


@app.post("/self/service/{service_id}/subscribe")
async def self_subscribe(service_id: str, req: SelfSubscribeRequest, ident: Dict[str, Any] = Depends(_require_jwt)):
    """Abonnement de CE nœud : tarif de l'offre accepté tel quel, échéance = maintenant + duree_s de l'offre."""
    from datetime import timedelta  # noqa: PLC0415
    from annuaire.verbs import _get_offer, subscribe, subscription_state  # noqa: PLC0415
    priv, did = _cle_du_noeud()
    j = get_journal()
    offre = await asyncio.to_thread(_get_offer, j, service_id)
    if offre is None:
        raise HTTPException(404, "offre inconnue ou retirée")
    if offre.get("provider") == did:
        raise HTTPException(409, "un nœud ne s'abonne pas à sa propre offre")
    if req.provider and req.provider != offre.get("provider"):
        raise HTTPException(409, "le fournisseur de l'offre n'est pas celui évalué")
    from annuaire import confiance  # noqa: PLC0415
    niveau, _cause = await asyncio.to_thread(confiance.niveau, j, offre.get("provider"))
    if niveau in ("OBSERVER", "REVOKED") or offre.get("classe") == "prive":
        raise HTTPException(409, f"offre non ouverte à l'abonnement (fournisseur {niveau}, classe "
                                 f"{offre.get('classe') or 'public'})")
    en_cours = await asyncio.to_thread(_abonnement_en_cours, j, did, service_id)
    if en_cours:
        raise HTTPException(409, f"abonnement déjà en cours : {en_cours}")
    duree = offre.get("duree_s")
    expire = ((datetime.now(timezone.utc) + timedelta(seconds=duree)).isoformat()
              if isinstance(duree, int) and duree > 0 else None)
    try:
        sub = await asyncio.to_thread(subscribe, j, priv, did, service_id, version=req.version,
                                      tarif_accepte=offre.get("tarif"), expire_le=expire,
                                      provider=offre.get("provider"))
    except PermissionError as e:
        raise HTTPException(403, str(e)) from None
    except ValueError as e:
        raise HTTPException(404, str(e)) from None
    etat = await asyncio.to_thread(subscription_state, j, sub.subscription_id)
    _auditer_mirrornet("mirrornet_abonnement", ident, subscription_id=sub.subscription_id, service_id=service_id,
                       fournisseur=offre.get("provider"), etat=etat.value)
    await asyncio.to_thread(_exporter_mirrornet)
    return dict(sub.model_dump(), state=etat.value)


@app.post("/self/subscription/{subscription_id}/renew")
async def self_renew(subscription_id: str, ident: Dict[str, Any] = Depends(_require_jwt)):
    from annuaire.verbs import renew_subscription  # noqa: PLC0415
    priv, did = _cle_du_noeud()
    res = await asyncio.to_thread(_geste, renew_subscription, get_journal(), priv, did, subscription_id)
    _auditer_mirrornet("mirrornet_renouvellement", ident, subscription_id=subscription_id, expire_le=res.get("expire_le"))
    await asyncio.to_thread(_exporter_mirrornet)
    return res


@app.post("/self/subscription/{subscription_id}/cancel")
async def self_cancel(subscription_id: str, req: SelfCancelRequest, ident: Dict[str, Any] = Depends(_require_jwt)):
    """Résiliation par l'abonné, ou révocation de l'abonné par le fournisseur : le rôle de CE nœud décide."""
    from annuaire.verbs import _get_subscription_payload, cancel_subscription, revoke_subscriber  # noqa: PLC0415
    priv, did = _cle_du_noeud()
    j = get_journal()
    sub = await asyncio.to_thread(_get_subscription_payload, j, subscription_id)
    if sub is None:
        raise HTTPException(404, "abonnement inconnu")
    fn = cancel_subscription if sub.get("subscriber") == did else revoke_subscriber
    res = await asyncio.to_thread(_geste, fn, j, priv, did, subscription_id, req.motif)
    _auditer_mirrornet("mirrornet_resiliation", ident, subscription_id=subscription_id, role=res.get("role"),
                       motif=req.motif)
    await asyncio.to_thread(_exporter_mirrornet)
    return res


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
    layer: str = "baseline"


class RevokeConfigRequest(BaseModel):
    publisher_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    publisher_priv_hex: str


class PullLogRequest(BaseModel):
    base_url: str


@app.get("/nodes", dependencies=[Depends(require_lecture)])
async def list_nodes():
    """List the latest self-authored NodeRecord per node (public — the peer registry)."""
    from annuaire.verbs import _get_nodes  # noqa: PLC0415
    return {"nodes": _get_nodes(get_journal())}


@app.get("/config", dependencies=[Depends(require_lecture)])
async def list_config(scope: Optional[str] = None):
    """List current (non-revoked) config blobs, optionally filtered by scope (public)."""
    from annuaire.verbs import _get_configs  # noqa: PLC0415
    configs = _get_configs(get_journal())
    if scope is not None:
        configs = [c for c in configs if c.get("scope") == scope]
    return {"configs": configs}


@app.get("/bans", dependencies=[Depends(require_lecture)])
async def list_bans():
    """The federated ban union (public read) — every node's active bans (#768)."""
    from annuaire.verbs import _get_bans, banned_ips  # noqa: PLC0415
    j = get_journal()
    return {"banned_ips": banned_ips(j), "bans": _get_bans(j)}


@app.get("/log/export")
async def export_log(request: Request, ops: Optional[str] = None, ident: Dict[str, Any] = Depends(lecture_ou_pair)):
    """Export the full signed log for a peer to pull (public).

    Distinct from GET /log (a truncated recent view): this returns every entry
    with its author_pubkey so a consumer can verify and re-append.
    """
    from annuaire.verbs import export_entries  # noqa: PLC0415
    # Hors de la boucle d'événements (#1530) : servi par un seul worker, un
    # export long gelait TOUTES les routes de l'annuaire.
    # ?ops=assist_ (#2540) : la voie rapide ne tire que l'assistance (quelques Ko) au lieu du journal entier (3 Mo).
    prefixes = tuple(x for x in (ops or "").split(",") if x.strip()) or None
    entrees = await asyncio.to_thread(export_entries, get_journal(), prefixes)
    if ident.get("pair_maillage"):                               # #3305 : bans et offres seulement si l'abonnement du pair les inclut
        from annuaire import droits as D  # noqa: PLC0415
        exclues = await asyncio.to_thread(D.operations_exclues, _ip_pair(request), D.DROITS_DEFAUT, D.PAIRS_DEFAUT)
        entrees = D.filtrer(entrees, exclues)
    return {"entries": entrees}


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
            valid_until=req.valid_until, config_id=req.config_id, layer=req.layer,
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
# Fleet metrics (feat/fleet-metrics, Task 4)
#
# /fleet/self mirrors /log/export: public, no JWT — it serves this node's own
# SIGNED MetricSnapshot verbatim, exactly what a peer pulls on :8799 (safe to
# expose: the record is signed, a reader must still verify_snapshot() it).
#
# /fleet is the JWT-gated aggregate view: self + every mesh peer's snapshot,
# pulled live and verified, annotated with health/stale. Read-only and must
# NEVER 500 — an unreachable, timing-out, or malicious peer is dropped, not
# fatal to the endpoint.
# ---------------------------------------------------------------------------

_FLEET_TTL_S = 5 * 60  # 5x the publish interval (sbx-fleetctl publish timer)


@app.get("/fleet/self", dependencies=[Depends(lecture_ou_pair)])
async def get_fleet_self():
    """This node's own signed MetricSnapshot, or {} if not yet published (public)."""
    return fleet_store.read() or {}


def _fetch_fleet_peer(url: str, timeout: int = 2) -> Optional[Dict[str, Any]]:
    """Pull a peer's /fleet/self record (production fetcher, injectable for tests).

    Returns the parsed record dict, or None on ANY error (unreachable peer,
    timeout, non-200, malformed JSON, non-dict body) — the caller treats None
    as "skip this peer", never as fatal.
    """
    import json as _json          # noqa: PLC0415
    import urllib.request         # noqa: PLC0415

    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with _OUVREUR_MAILLAGE.open(req, timeout=timeout) as resp:  # sans proxy ni redirection (revue #3212)
            data = _json.loads(resp.read(4 * 1024 * 1024))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


@app.get("/fleet", dependencies=[Depends(_require_jwt)])
async def get_fleet():
    """Aggregate fleet view: self + verified mesh peers, with health/stale.

    Never raises — any unexpected failure (corrupt local store, peer list
    unreadable, etc.) degrades to {"nodes": []} rather than a 500.
    """
    try:
        self_rec = fleet_store.read()
        peers = mesh_sync.read_mesh_peers()

        urls = [
            f"http://{peer['mesh_ip']}:{mesh_sync.DEFAULT_MESH_PORT}/api/v1/annuaire/fleet/self"
            for peer in peers
            if peer.get("mesh_ip")
        ]
        peer_recs: List[Dict[str, Any]] = []
        if urls:
            # Offload each blocking urllib call to a thread and run them
            # concurrently — this API is served in-process by the aggregator
            # (a shared event loop across ~110 modules), so a serial loop of
            # synchronous fetches would block it for up to timeout*len(urls).
            # return_exceptions=True turns a raising peer into a value instead
            # of aborting the gather; non-dict results (None or Exception) are
            # dropped below.
            results = await asyncio.gather(
                *[asyncio.to_thread(_fetch_fleet_peer, u) for u in urls],
                return_exceptions=True,
            )
            peer_recs = [r for r in results if isinstance(r, dict)]

        snaps = fleet.fleet_snapshots(self_rec, peer_recs)

        from annuaire.model import now_rfc3339  # noqa: PLC0415
        now = now_rfc3339()
        nodes = [
            {**snap, "health": fleet.health(snap), "stale": fleet.is_stale(snap, now, _FLEET_TTL_S)}
            for snap in snaps.values()
        ]
        return {"nodes": nodes}
    except Exception:
        # Ne lève jamais (500 évité), mais ne se fait PAS passer pour une flotte vide : `erreur: true` (#2487). Une lecture en échec
        # affichée « aucun nœud » faisait croire que le maillage était vide.
        return {"nodes": [], "erreur": True}


# ---------------------------------------------------------------------------
# Relevé de validation des modules (#3212) — comparateur des profils, toutes les box du maillage.
#
# /fleet/modules/self : le relevé SIGNÉ de cette box (sbx-fleetctl publish-modules), servi aux pairs sur :8799 comme
# /fleet/self. /fleet/modules (JWT) : soi + chaque pair de wg_mesh.json, vérifiés (signature ET forme), et les box sans
# relevé lisible NOMMÉES avec leur raison — une colonne « relevé indisponible », jamais une box qui disparaît.
# ---------------------------------------------------------------------------

_MODULES_TTL_S = 15 * 60  # 3 relevés (secubox-profiles-releve.timer, 5 min)
_DELAI_PARC_S = 12.0      # au-delà, les pairs encore en lecture sont « délai dépassé » (la page ne reste pas pendue)
_log_parc = logging.getLogger("secubox.annuaire.parc")


class _SansRedirection(urllib.request.HTTPRedirectHandler):
    """Revue #3212 : un pair ne redirige pas l'agrégateur vers 127.0.0.1 ou le LAN — toute redirection est une erreur."""

    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None


# Lectures des pairs du maillage : jamais de proxy (http_proxy de l'environnement), jamais de redirection.
_OUVREUR_MAILLAGE = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SansRedirection())
# Pool DÉDIÉ et petit : l'exécuteur par défaut est partagé par tous les modules de l'agrégateur.
_POOL_MAILLAGE = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="annuaire-parc")


@app.get("/fleet/modules/self", dependencies=[Depends(lecture_ou_pair)])
async def get_fleet_modules_self():
    """Le relevé de validation signé de cette box, ou {} s'il n'est pas encore publié."""
    return await asyncio.to_thread(fleet_store.read, fleet_store.MODULES_PATH) or {}


@app.get("/fleet/status/self", dependencies=[Depends(lecture_ou_pair)])
async def get_fleet_status_self():
    """Le relevé Status Live signé de cette box (#3626, sbx-fleetctl publish-status), ou {} s'il n'est pas publié."""
    return await asyncio.to_thread(fleet_store.read, fleet_store.STATUS_PATH) or {}


def _fetch_modules_peer(url: str, timeout: float = 3, echeance_s: float = 5.0,
                        limite: int = 4 * 1024 * 1024) -> "tuple[Optional[Dict[str, Any]], Optional[str]]":
    """(relevé brut, None) ou (None, raison) — raison affichée dans la colonne de la box (injectable en test).

    `timeout` borne chaque lecture ; `echeance_s` borne l'échange ENTIER (un pair qui distille un octet à la fois ne
    tient pas un thread des heures) ; `limite` borne la taille."""
    debut = time.monotonic()
    morceaux: List[bytes] = []
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with _OUVREUR_MAILLAGE.open(req, timeout=timeout) as resp:
            taille = 0
            while True:
                if time.monotonic() - debut > echeance_s:
                    return None, "délai dépassé"
                morceau = resp.read(65536)
                if not morceau:
                    break
                taille += len(morceau)
                if taille > limite:
                    return None, "réponse trop volumineuse"
                morceaux.append(morceau)
    except urllib.error.HTTPError as e:
        return None, "version trop ancienne" if e.code == 404 else f"réponse HTTP {e.code}"
    except (urllib.error.URLError, OSError, ValueError):
        return None, "injoignable"
    try:
        data = fleet.charger_json(b"".join(morceaux))
    except ValueError:
        return None, "réponse illisible"
    return (data, None) if isinstance(data, dict) else (None, "réponse illisible")


def _releve_pair(url: str) -> "tuple[Optional[Dict[str, Any]], Optional[str]]":
    """Lecture ET vérification (signature, forme) dans le pool : rien de coûteux sur la boucle partagée."""
    data, raison = _fetch_modules_peer(url)
    if raison:
        return None, raison
    if not data:
        return None, "relevé non publié"
    norm = fleet.normaliser_modules(data)
    return (norm, None) if norm else (None, "signature invalide")


def _contexte_parc() -> "tuple[Optional[Dict[str, Any]], List[Dict[str, str]], Dict[str, str], str]":
    """Relevé local vérifié, pairs (WireGuard + répertoire, sans soi), lien adresse → did des fiches signées, réseau."""
    from collections import Counter  # noqa: PLC0415
    brut = fleet_store.read(fleet_store.MODULES_PATH)
    soi = fleet.normaliser_modules(brut) if brut else None
    meta = mesh_sync.read_self_meta() or {}
    reseau = mesh_sync.reseau_maillage()
    noeuds = mesh_sync.noeuds_du_repertoire(get_journal())
    ici = meta.get("mesh_ip", "")
    pairs = [p for p in mesh_sync.completer_pairs(mesh_sync.read_mesh_peers(), noeuds, soi=ici, reseau=reseau)
             if p.get("mesh_ip") and p.get("mesh_ip") != ici]
    revendiquees = Counter(str(n.get("mesh_ip") or "") for n in noeuds)
    attendus = {str(n["mesh_ip"]): str(n["did"]) for n in noeuds
                if n.get("mesh_ip") and n.get("did") and revendiquees[str(n["mesh_ip"])] == 1}
    return soi, pairs, attendus, reseau


@app.get("/fleet/modules", dependencies=[Depends(_require_jwt)])
async def get_fleet_modules():
    """Les relevés vérifiés de toutes les box ({noeuds}), et les box sans relevé lisible ({indisponibles}). Ne lève jamais."""
    try:
        import ipaddress  # noqa: PLC0415
        from annuaire.model import now_rfc3339  # noqa: PLC0415
        maintenant = now_rfc3339()
        soi, pairs, attendus, reseau = await asyncio.to_thread(_contexte_parc)
        net = ipaddress.ip_network(reseau, strict=False)
        valides, resultats = [], []
        for p in pairs:
            try:
                dedans = ipaddress.ip_address(p["mesh_ip"]) in net
            except ValueError:
                dedans = False
            if dedans:
                valides.append(p)
            else:
                resultats.append((p, None, "adresse hors du maillage"))
        boucle = asyncio.get_running_loop()
        taches = [boucle.run_in_executor(
            _POOL_MAILLAGE, _releve_pair,
            f"http://{p['mesh_ip']}:{mesh_sync.DEFAULT_MESH_PORT}/api/v1/annuaire/fleet/modules/self") for p in valides]
        if taches:
            _fait, reste = await asyncio.wait(taches, timeout=_DELAI_PARC_S)
            for t in reste:
                t.cancel()
        for p, t in zip(valides, taches):
            if not t.done() or t.cancelled():
                resultats.append((p, None, "délai dépassé"))
            elif t.exception() is not None:
                resultats.append((p, None, "injoignable"))
            else:
                rec, raison = t.result()
                resultats.append((p, rec, raison))
        noeuds, indisponibles = fleet.resoudre_releves(soi, resultats, attendus, maintenant, _MODULES_TTL_S)
        return {"noeuds": noeuds, "indisponibles": indisponibles}
    except Exception:
        _log_parc.exception("relevés de validation du parc illisibles")
        return {"noeuds": [], "indisponibles": [], "erreur": True}


# ---------------------------------------------------------------------------
# Centers — delegated config-property ownership (feat/centers-grants-remote-config, Task 8)
#
# Read endpoints (GET) resolve entirely in-process from the journal
# (annuaire.grants / annuaire.config_router) — no privileged action, no JWT.
#
# Mutating endpoints (POST) NEVER hold or touch the box's signing key
# in-process: they delegate to `sbx-centersctl` (a root-confined, audited
# CLI — see sbin/sbx-centersctl) via subprocess with a fixed argv list (no
# shell=True, no string interpolation into a shell command line, so no
# argument can smuggle a second command). The box key that actually signs
# GRANT_ISSUE/GRANT_REVOKE journal entries is loaded server-side by that CLI
# from ANNUAIRE_KEY_PATH (the same node identity key as annuairectl and
# _publish_self_node below — one box, one sovereign identity) — it is never
# accepted as a request field here.
# ---------------------------------------------------------------------------

CONFIG_TARGET_DIR = os.environ.get("CONFIG_TARGET_DIR", "/etc/secubox")
CONFIG_LOCAL_DIR = os.environ.get("CONFIG_LOCAL_DIR", "/etc/secubox/config-local")


class CenterGrantRequest(BaseModel):
    center_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    scope: str = Field(..., pattern=r"^[a-z0-9][a-z0-9._:-]*$")      # « : » admis (mitm-exclusion:gk2, #2776)
    layer: str


class CenterRevokeRequest(BaseModel):
    grant_id: str


class CenterProposalAcceptRequest(BaseModel):
    center_did: str = Field(..., pattern=r"^did:plc:[0-9a-f]{32}$")
    scope: str = Field(..., pattern=r"^[a-z0-9][a-z0-9._:-]*$")      # « : » admis (mitm-exclusion:gk2, #2776)
    layer: str


def _centers_ctl(args: List[str], timeout: int = 25):
    """Run sbx-centersctl with a fixed argv list; never raises.

    Path is overridable via SBX_CENTERSCTL (tests / non-standard installs);
    defaults to the packaged location. Returns (returncode, stdout, stderr) —
    a subprocess/OS failure (binary missing, timeout, ...) is folded into
    (1, "", "<exception message>") rather than propagating, so callers have
    one uniform failure shape to check (rc != 0).
    """
    ctl_path = os.environ.get("SBX_CENTERSCTL", "/usr/sbin/sbx-centersctl")
    try:
        p = subprocess.run(
            [ctl_path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.SubprocessError) as e:
        return 1, "", str(e)


def _ctl_error_message(stderr: str) -> str:
    """Best-effort extraction of sbx-centersctl's {"error": "..."} stderr JSON."""
    import json as _json  # noqa: PLC0415
    try:
        msg = _json.loads(stderr).get("error")
        if msg:
            return str(msg)
    except (ValueError, AttributeError):
        pass
    return stderr.strip() or "sbx-centersctl failed"


def _ctl_json(stdout: str) -> Dict[str, Any]:
    """Parse sbx-centersctl's stdout JSON; a malformed reply is a 502, not a crash."""
    import json as _json  # noqa: PLC0415
    try:
        return _json.loads(stdout)
    except ValueError:
        raise HTTPException(502, "sbx-centersctl returned malformed JSON")


def _self_did_best_effort() -> Optional[str]:
    """Best-effort box did for route_config's self_did (interface symmetry only —
    see annuaire/config_router.py::route_config docstring; never required for
    correct proposal/effective resolution). Mirrors sbx-centersctl's own
    best-effort resolution in `cmd_route`. Never raises: an absent/malformed
    box key silently yields None rather than 500ing a read endpoint.
    """
    key_path = os.environ.get("ANNUAIRE_KEY_PATH", "/etc/secubox/secrets/annuaire/node.key")
    try:
        from annuaire.crypto import did_from_pubkey, public_from_private  # noqa: PLC0415
        with open(key_path, "r", encoding="ascii") as fh:
            priv = bytes.fromhex(fh.read().strip())
        if len(priv) != 32:
            return None
        return did_from_pubkey(public_from_private(priv))
    except Exception:
        return None


@app.get("/centers", dependencies=[Depends(require_lecture)])
async def list_centers():
    """Enrolled centers + their delegated (scope, layer) capabilities (public read).

    Derived from annuaire.grants.active_grants(journal, self_did) — one
    entry per center_did that currently holds ≥1 active grant ISSUED BY THIS
    BOX. Grant ops federate over the mesh, so a peer's self-issued grant for
    its own center could otherwise appear here as if this box had delegated
    it — self_did (best-effort) keeps this matrix sovereignty-scoped.
    """
    from annuaire.grants import active_grants  # noqa: PLC0415
    active = active_grants(list(get_journal().iter_entries()), _self_did_best_effort())
    by_center: Dict[str, List[Dict[str, Any]]] = {}
    for (scope, layer), grant in active.items():
        center_did = grant.get("center_did")
        by_center.setdefault(center_did, []).append({
            "grant_id": grant.get("grant_id"),
            "scope": scope,
            "layer": layer,
            "capability": grant.get("capability"),
        })
    centers = [
        {"center_did": did, "grants": sorted(g, key=lambda x: (x["scope"], x["layer"]))}
        for did, g in sorted(by_center.items())
    ]
    return {"centers": centers}


@app.get("/centers/ownership", dependencies=[Depends(require_lecture)])
async def centers_ownership():
    """(scope, layer) -> owning center matrix (public read), via grants.active_grants.

    Sovereignty-scoped: only shows grants ISSUED BY THIS BOX (self_did,
    best-effort) — see list_centers() docstring above.
    """
    from annuaire.grants import active_grants  # noqa: PLC0415
    active = active_grants(list(get_journal().iter_entries()), _self_did_best_effort())
    matrix = [
        {
            "scope": scope,
            "layer": layer,
            "owner": grant.get("center_did"),
            "grant_id": grant.get("grant_id"),
        }
        for (scope, layer), grant in sorted(active.items())
    ]
    return {"ownership": matrix}


@app.get("/centers/proposals", dependencies=[Depends(require_lecture)])
async def centers_proposals():
    """CONFIG_PUBLISH entries that failed to route (no grant / bad sig / hash
    mismatch / malformed) — pending operator review (public read).

    Calls config_router.route_config(apply=False): a read-only dry pass that
    collects the same "proposals" a real route would produce WITHOUT ever
    calling apply_composed — nothing on disk is touched by this GET.
    """
    from annuaire.config_router import route_config  # noqa: PLC0415
    entries = list(get_journal().iter_entries())
    result = route_config(
        entries, CONFIG_TARGET_DIR, _self_did_best_effort(), CONFIG_LOCAL_DIR, apply=False,
    )
    return {"proposals": result["proposals"]}


@app.get("/centers/effective/{scope}", dependencies=[Depends(require_lecture)])
async def centers_effective(scope: str):
    """Composed effective config for *scope* vs its local override layer (public read).

    Best-effort diff, dry-run via route_config(apply=False): "effective" is
    the fully composed baseline+override+local text a real route would write
    (never actually applied here); "local" is the raw local-layer file text
    on disk, if any — the two vantage points an operator needs to decide
    whether a local override still diverges from / is still needed on top of
    the granted centers' layers.

    *scope* is a public path parameter and must be validated as a safe bare
    filename component (same guard as config_apply._valid_scope) BEFORE it is
    ever used to build a Path — an unvalidated scope containing "/" or ".."
    could otherwise be joined into CONFIG_LOCAL_DIR and read an arbitrary
    file off disk.
    """
    from annuaire.config_apply import _valid_scope  # noqa: PLC0415
    if not _valid_scope(scope):
        return {"scope": scope, "status": "invalid-scope"}

    from annuaire.config_router import route_config  # noqa: PLC0415
    entries = list(get_journal().iter_entries())
    result = route_config(
        entries, CONFIG_TARGET_DIR, _self_did_best_effort(), CONFIG_LOCAL_DIR, apply=False,
    )
    composed = next((a for a in result["applied"] if a.get("scope") == scope), None)
    local_file = Path(CONFIG_LOCAL_DIR) / f"{scope}.toml"
    local_text = local_file.read_text() if local_file.is_file() else None
    return {
        "scope": scope,
        "status": composed.get("status") if composed else "no-layers",
        "effective": composed.get("text") if composed else None,
        "local": local_text,
    }


@app.post("/centers/grant", dependencies=[Depends(_require_jwt)])
async def centers_grant(req: CenterGrantRequest):
    """Delegate config authority over (scope, layer) to a center.

    Delegates to `sbx-centersctl grant <center_did> <scope> <layer>` — the
    box's signing key never enters this process. A rejection (non-delegatable
    scope, layer=="local", already-owned) comes back as ctl rc!=0 with a JSON
    {"error": reason} on stderr, surfaced here as HTTP 400.
    """
    rc, stdout, stderr = _centers_ctl(["grant", req.center_did, req.scope, req.layer])
    if rc != 0:
        raise HTTPException(400, _ctl_error_message(stderr))
    return _ctl_json(stdout)


@app.post("/centers/revoke", dependencies=[Depends(_require_jwt)])
async def centers_revoke(req: CenterRevokeRequest):
    """Withdraw a previously issued grant (delegates to `sbx-centersctl revoke <grant_id>`)."""
    rc, stdout, stderr = _centers_ctl(["revoke", req.grant_id])
    if rc != 0:
        raise HTTPException(400, _ctl_error_message(stderr))
    return _ctl_json(stdout)


@app.post("/centers/proposal/accept", dependencies=[Depends(_require_jwt)])
async def centers_proposal_accept(req: CenterProposalAcceptRequest):
    """Accept a pending proposal: grant the (scope, layer) it needed, then route it.

    Two sequential ctl delegations — `grant` (issues the missing delegated
    authority) followed by `route` (verifies + applies every now-routable
    scope, including this one, via the grant matrix). Either step failing
    (ctl rc != 0) surfaces as HTTP 400 without attempting the next step.
    """
    rc, stdout, stderr = _centers_ctl(["grant", req.center_did, req.scope, req.layer])
    if rc != 0:
        raise HTTPException(400, _ctl_error_message(stderr))
    granted = _ctl_json(stdout)

    rc, stdout, stderr = _centers_ctl(["route"])
    if rc != 0:
        raise HTTPException(400, _ctl_error_message(stderr))
    routed = _ctl_json(stdout)

    return {"grant": granted, "route": routed}


# ---------------------------------------------------------------------------
# Directory replication background loop (gondwana P1, #768)
#
# Runs IN-PROCESS (this service owns the journal → no JWT, no second writer).
# secubox-p2p owns the peer list (wg_mesh.json); we only read it. Disabled via
# ANNUAIRE_DIR_SYNC=0 (tests / off-box). The blocking fetch+merge runs in a
# worker thread so it never stalls the event loop.
# ---------------------------------------------------------------------------


def _publish_self_node() -> bool:
    """Publish this node's signed NodeRecord into the directory (idempotent). Rend True quand la box est inscrite (publiée ou déjà à jour).

    In-process (journal owner → no JWT, no write race). Requires the node
    identity key from `annuairectl init`; a no-op if absent. Skips when the
    latest record for this DID already matches the current mesh metadata, so a
    restart does not spam the log.

    False = pas encore possible (pas de clé d'identité, pas de maillage) : l'appelant RÉESSAIE (#2544). Avant, seul le démarrage essayait :
    une box neuve, sans maillage à ce moment-là, ne s'inscrivait jamais chez le maître.
    """
    key_path = os.environ.get("ANNUAIRE_KEY_PATH", "/etc/secubox/secrets/annuaire/node.key")
    if not os.path.exists(key_path):
        return False
    try:
        from annuaire.crypto import did_from_pubkey, public_from_private  # noqa: PLC0415
        from annuaire.mesh_sync import read_self_meta  # noqa: PLC0415
        from annuaire.verbs import _get_nodes, publish_node  # noqa: PLC0415

        with open(key_path, "r", encoding="ascii") as fh:
            priv = bytes.fromhex(fh.read().strip())
        if len(priv) != 32:
            return False
        meta = read_self_meta()
        if not meta:
            return False
        did = did_from_pubkey(public_from_private(priv))
        j = get_journal()
        fields = ("node_id", "boxname", "pubkey_wg", "mesh_ip", "ddns", "endpoint")
        existing = next((n for n in _get_nodes(j) if n.get("did") == did), None)
        if existing and all(existing.get(k) == meta[k] for k in fields):
            return True
        publish_node(j, priv, did, **meta)
        return True
    except Exception as e:  # noqa: BLE001
        logging.getLogger("secubox.annuaire.sync").warning("inscription de la box dans l'annuaire impossible : %s", e)
        return False


_NOEUD_INSCRIT = False


def _inscrire_si_besoin() -> bool:
    """Tente l'inscription tant qu'elle n'a pas abouti, puis ne relit plus rien (#2544) : appelé à chaque passage de synchro."""
    global _NOEUD_INSCRIT
    if not _NOEUD_INSCRIT:
        _NOEUD_INSCRIT = _publish_self_node()
        if _NOEUD_INSCRIT:
            logging.getLogger("secubox.annuaire.sync").info("box inscrite dans l'annuaire du maillage")
    return _NOEUD_INSCRIT


@app.on_event("startup")
async def _start_dir_sync():
    import asyncio  # noqa: PLC0415
    if os.environ.get("ANNUAIRE_DIR_SYNC", "1") != "1":
        return
    await asyncio.to_thread(_publish_self_node)
    await asyncio.to_thread(_charger_joignabilite)               # #3647
    asyncio.create_task(_dir_sync_loop())
    asyncio.create_task(_assist_sync_loop())


_sync_log = logging.getLogger("secubox.annuaire.sync")


def _cycle_sync(peers_path: str, ops: Optional[str] = None):
    """Un passage de synchronisation (#2540). Rend les totaux, ou None si rien n'a pu être tenté.

    Jamais d'exception vers l'appelant, mais plus de silence : un échec est journalisé (c'était `except Exception: pass`), et un passage qui
    ingère quelque chose aussi. Un passage sans changement reste muet (la voie rapide tourne toutes les 20 s)."""
    from annuaire import mesh_sync  # noqa: PLC0415
    from annuaire.mesh_sync import read_mesh_peers  # noqa: PLC0415
    voie = f"voie « {ops} »" if ops else "journal complet"
    try:
        peers = read_mesh_peers(peers_path)
        if not peers:
            return None
        # Maillage automatique (#2569) : les nœuds du répertoire s'ajoutent aux pairs WireGuard (étoile : satellite <-> satellite).
        meta = mesh_sync.read_self_meta(peers_path) or {}
        peers = mesh_sync.completer_pairs(peers, mesh_sync.noeuds_du_repertoire(get_journal()), soi=meta.get("mesh_ip", ""),
                                          reseau=mesh_sync.reseau_maillage(peers_path))
        sync_once = mesh_sync.sync_once
        suivi: Dict[str, bool] = {}
        res = (sync_once(get_journal(), peers, ops=ops, suivi=suivi) if ops
               else sync_once(get_journal(), peers, suivi=suivi))
        _noter_joignabilite(suivi)                                   # #3647 : période de grâce MirrorNet
        if not ops:                                                  # #3305 : droits de cette box, relevés au passage complet
            mesh_sync.relever_droits(peers)
    except Exception as e:  # noqa: BLE001 — la boucle ne meurt pas, mais elle le dit
        _sync_log.warning("synchronisation (%s) échouée : %s", voie, e)
        return None
    finally:
        _exporter_mirrornet()                                        # #3647 : même sans pair (nœud seul), l'export existe
    if res.get("ingested") or res.get("rejected") or res.get("errors"):
        _sync_log.info("synchronisation (%s) : %s ingéré(s), %s rejeté(s), %s pair(s) injoignable(s) sur %s", voie,
                       res.get("ingested", 0), res.get("rejected", 0), res.get("errors", 0), res.get("peers", 0) + res.get("errors", 0))
    return res


async def _dir_sync_loop():
    import asyncio  # noqa: PLC0415

    interval = int(os.environ.get("ANNUAIRE_DIR_SYNC_INTERVAL", "300"))
    peers_path = os.environ.get("ANNUAIRE_PEERS_PATH", "/var/lib/secubox/p2p/wg_mesh.json")
    while True:
        await asyncio.to_thread(_inscrire_si_besoin)
        await asyncio.to_thread(_cycle_sync, peers_path)
        await asyncio.sleep(interval)


async def _assist_sync_loop():
    """Voie rapide (#2540) : les demandes et offres d'assistance seulement, toutes les 20 s. Le journal entier (bannissements compris) garde ses 300 s."""
    import asyncio  # noqa: PLC0415

    interval = int(os.environ.get("ANNUAIRE_ASSIST_SYNC_INTERVAL", "20"))
    peers_path = os.environ.get("ANNUAIRE_PEERS_PATH", "/var/lib/secubox/p2p/wg_mesh.json")
    while True:
        await asyncio.sleep(interval)
        await asyncio.to_thread(_inscrire_si_besoin)
        # #3647 : les gestes d'abonnement (service_*) passent par la voie rapide : 20 s au lieu de 300 s.
        await asyncio.to_thread(_cycle_sync, peers_path, "assist_,service_")


@app.post("/sync/now", dependencies=[Depends(_require_jwt)])
async def sync_maintenant():
    """Un passage immédiat de la voie rapide (bouton « Synchroniser » de /assist/)."""
    peers_path = os.environ.get("ANNUAIRE_PEERS_PATH", "/var/lib/secubox/p2p/wg_mesh.json")
    res = await asyncio.to_thread(_cycle_sync, peers_path, "assist_")
    return {"ok": res is not None, "resultat": res}
