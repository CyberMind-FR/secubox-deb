# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_services.py
Pytest coverage for service offers + subscription feature.

Tests:
  - offer_service → appears in _get_offers; self-authored guard.
  - subscribe to AUTO offer → state APPROVED without any provider action.
  - subscribe to PENDING offer → state PENDING; provider approve → APPROVED.
  - subscribe to PENDING offer → provider reject → REJECTED.
  - Non-provider approve → PermissionError (defense-in-depth: approve entry
    authored by a wrong party does NOT flip the state).
  - revoke_offer by non-provider → PermissionError.
  - revoke_offer by provider → offer gone; new subscribe fails.
  - subscribe by OBSERVED (non-member) → PermissionError.
  - ingest_offer with valid sig → ingested; tampered/forged sig → ValueError.
  - Approve entry authored by non-provider does NOT count as approved.
"""
import hashlib
import os
import tempfile

import pytest

from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign, verify
from annuaire.log import Journal
from annuaire.model import (
    ApprovalMode,
    Identity,
    MemberState,
    Op,
    ServiceOffer,
    Subscription,
    SubscriptionState,
    now_rfc3339,
)
from annuaire.verbs import (
    _get_offer,
    _get_offers,
    approve_subscription,
    ingest_offer,
    offer_service,
    reject_subscription,
    revoke_offer,
    subscribe,
    subscription_state,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_journal(tmp_path):
    return Journal(str(tmp_path / "test.db"))


def _make_member(journal: Journal):
    """Bootstrap a MEMBER node: post a self-authored MEMBER Identity. Returns (priv, pub, did)."""
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    digest = hashlib.sha256(pub).hexdigest()[:32]

    ident = Identity(
        did=did,
        pubkey=pub.hex(),
        self_cert_digest=digest,
        state=MemberState.MEMBER,
    )
    full = ident.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    sig_hex = sign(priv, canonical_bytes(payload))

    journal.append(
        op=Op.INVITE_ACCEPT,
        payload_type="Identity",
        payload=payload,
        author=did,
        sig=sig_hex,
        author_pubkey_hex=pub.hex(),
    )
    return priv, pub, did


def _make_observed(journal: Journal):
    """Bootstrap an OBSERVED node. Returns (priv, pub, did)."""
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    digest = hashlib.sha256(pub).hexdigest()[:32]

    ident = Identity(
        did=did,
        pubkey=pub.hex(),
        self_cert_digest=digest,
        state=MemberState.OBSERVED,
    )
    full = ident.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    payload["state"] = MemberState.OBSERVED.value
    sig_hex = sign(priv, canonical_bytes(payload))

    journal.append(
        op=Op.AUTO_ADD,
        payload_type="Identity",
        payload=payload,
        author=did,
        sig=sig_hex,
        author_pubkey_hex=pub.hex(),
    )
    return priv, pub, did


# ---------------------------------------------------------------------------
# Model smoke tests (pre-existing, keep them)
# ---------------------------------------------------------------------------

def test_model_service_offer_constructable():
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    offer = ServiceOffer(
        service_id="abc123",
        provider=did,
        name="MyAPI",
        kind="api",
        endpoint="/api/v1/foo",
        scope={"isolation_domain": "fr-chambery"},
        approval_mode=ApprovalMode.AUTO,
        description="test service",
        created_at=now_rfc3339(),
        sig=None,
        signer_did=None,
    )
    assert offer.service_id == "abc123"
    assert offer.approval_mode == ApprovalMode.AUTO


def test_model_subscription_constructable():
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    sub = Subscription(
        subscription_id="sub123",
        subscriber=did,
        service_id="abc123",
        requested_at=now_rfc3339(),
        sig=None,
        signer_did=None,
    )
    assert sub.subscription_id == "sub123"


def test_op_enum_has_service_members():
    assert Op.SERVICE_OFFER.value == "service_offer"
    assert Op.SERVICE_REVOKE_OFFER.value == "service_revoke_offer"
    assert Op.SERVICE_SUBSCRIBE.value == "service_subscribe"
    assert Op.SERVICE_APPROVE.value == "service_approve"
    assert Op.SERVICE_REJECT.value == "service_reject"
    assert Op.SERVICE_REVOKE_SUB.value == "service_revoke_sub"
    assert ApprovalMode.AUTO.value == "auto"
    assert ApprovalMode.PENDING.value == "pending"
    assert SubscriptionState.APPROVED.value == "approved"
    assert SubscriptionState.PENDING.value == "pending"


# ---------------------------------------------------------------------------
# 1. offer_service → in _get_offers; self-authored
# ---------------------------------------------------------------------------

def test_offer_service_appears_in_get_offers(tmp_journal):
    """offer_service must result in the offer appearing in _get_offers."""
    priv, pub, did = _make_member(tmp_journal)

    offer = offer_service(
        tmp_journal, priv, did,
        name="TestSvc", kind="api", endpoint="http://local/api",
        approval_mode="auto",
    )

    offers = _get_offers(tmp_journal)
    assert len(offers) == 1
    assert offers[0]["service_id"] == offer.service_id
    assert offers[0]["provider"] == did
    assert offers[0]["name"] == "TestSvc"


def test_offer_service_multiple_offers(tmp_journal):
    """Two different providers can each have an offer; both appear."""
    priv_a, pub_a, did_a = _make_member(tmp_journal)
    priv_b, pub_b, did_b = _make_member(tmp_journal)

    offer_service(tmp_journal, priv_a, did_a, name="SvcA", kind="module", endpoint="/a")
    offer_service(tmp_journal, priv_b, did_b, name="SvcB", kind="api", endpoint="/b")

    offers = _get_offers(tmp_journal)
    assert len(offers) == 2
    sids = {o["provider"] for o in offers}
    assert did_a in sids
    assert did_b in sids


# ---------------------------------------------------------------------------
# 2. subscribe to AUTO offer → state APPROVED with no provider action
# ---------------------------------------------------------------------------

def test_subscribe_auto_mode_immediately_approved(tmp_journal):
    """AUTO approval_mode → subscription_state returns APPROVED without any provider action."""
    priv_p, pub_p, did_p = _make_member(tmp_journal)
    priv_s, pub_s, did_s = _make_member(tmp_journal)

    offer = offer_service(
        tmp_journal, priv_p, did_p,
        name="AutoSvc", kind="api", endpoint="/auto",
        approval_mode="auto",
    )

    sub = subscribe(tmp_journal, priv_s, did_s, offer.service_id)
    state = subscription_state(tmp_journal, sub.subscription_id)

    assert state == SubscriptionState.APPROVED, (
        f"AUTO offer subscription must be APPROVED immediately, got {state}"
    )


# ---------------------------------------------------------------------------
# 3. subscribe to PENDING offer → PENDING; provider approve → APPROVED
# ---------------------------------------------------------------------------

def test_subscribe_pending_mode_starts_pending(tmp_journal):
    """PENDING approval_mode → subscription_state is PENDING until approved."""
    priv_p, pub_p, did_p = _make_member(tmp_journal)
    priv_s, pub_s, did_s = _make_member(tmp_journal)

    offer = offer_service(
        tmp_journal, priv_p, did_p,
        name="PendingSvc", kind="api", endpoint="/pending",
        approval_mode="pending",
    )

    sub = subscribe(tmp_journal, priv_s, did_s, offer.service_id)
    state = subscription_state(tmp_journal, sub.subscription_id)

    assert state == SubscriptionState.PENDING, (
        f"PENDING offer subscription must start as PENDING, got {state}"
    )


def test_subscribe_pending_provider_approve_becomes_approved(tmp_journal):
    """PENDING → provider approve → state APPROVED."""
    priv_p, pub_p, did_p = _make_member(tmp_journal)
    priv_s, pub_s, did_s = _make_member(tmp_journal)

    offer = offer_service(
        tmp_journal, priv_p, did_p,
        name="PendingSvc", kind="api", endpoint="/pending",
        approval_mode="pending",
    )
    sub = subscribe(tmp_journal, priv_s, did_s, offer.service_id)

    # Before: PENDING
    assert subscription_state(tmp_journal, sub.subscription_id) == SubscriptionState.PENDING

    # Provider approves
    approve_subscription(tmp_journal, priv_p, did_p, sub.subscription_id)

    # After: APPROVED
    state = subscription_state(tmp_journal, sub.subscription_id)
    assert state == SubscriptionState.APPROVED, (
        f"After provider approval, state must be APPROVED, got {state}"
    )


# ---------------------------------------------------------------------------
# 4. subscribe to PENDING → provider reject → REJECTED
# ---------------------------------------------------------------------------

def test_subscribe_pending_provider_reject_becomes_rejected(tmp_journal):
    """PENDING → provider reject → state REJECTED."""
    priv_p, pub_p, did_p = _make_member(tmp_journal)
    priv_s, pub_s, did_s = _make_member(tmp_journal)

    offer = offer_service(
        tmp_journal, priv_p, did_p,
        name="PendingSvc", kind="api", endpoint="/pending",
        approval_mode="pending",
    )
    sub = subscribe(tmp_journal, priv_s, did_s, offer.service_id)

    reject_subscription(tmp_journal, priv_p, did_p, sub.subscription_id)

    state = subscription_state(tmp_journal, sub.subscription_id)
    assert state == SubscriptionState.REJECTED, (
        f"After provider rejection, state must be REJECTED, got {state}"
    )


# ---------------------------------------------------------------------------
# 5. Non-provider approve → PermissionError
# ---------------------------------------------------------------------------

def test_non_provider_approve_raises_permission_error(tmp_journal):
    """A non-provider cannot approve a subscription — must raise PermissionError."""
    priv_p, pub_p, did_p = _make_member(tmp_journal)
    priv_s, pub_s, did_s = _make_member(tmp_journal)
    # A third party attacker
    priv_att, pub_att, did_att = _make_member(tmp_journal)

    offer = offer_service(
        tmp_journal, priv_p, did_p,
        name="SecureSvc", kind="api", endpoint="/secure",
        approval_mode="pending",
    )
    sub = subscribe(tmp_journal, priv_s, did_s, offer.service_id)

    with pytest.raises(PermissionError):
        approve_subscription(tmp_journal, priv_att, did_att, sub.subscription_id)


def test_approve_entry_by_non_provider_does_not_approve(tmp_journal):
    """Defense-in-depth: an approve entry authored by a non-provider must NOT flip state.

    Even if such an entry were somehow written to the log, subscription_state()
    must not count it.  We simulate this by directly journal.append()-ing a
    SERVICE_APPROVE entry authored by an attacker and verifying the state stays PENDING.
    """
    priv_p, pub_p, did_p = _make_member(tmp_journal)
    priv_s, pub_s, did_s = _make_member(tmp_journal)
    priv_att, pub_att, did_att = _make_member(tmp_journal)

    offer = offer_service(
        tmp_journal, priv_p, did_p,
        name="SecureSvc", kind="api", endpoint="/secure",
        approval_mode="pending",
    )
    sub = subscribe(tmp_journal, priv_s, did_s, offer.service_id)

    # Directly forge an approve entry authored by the attacker (not the provider)
    forge_payload = {
        "subscription_id": sub.subscription_id,
        "service_id": offer.service_id,
        "approver": did_att,
        "approved_at": now_rfc3339(),
    }
    forge_sig = sign(priv_att, canonical_bytes(forge_payload))
    tmp_journal.append(
        op=Op.SERVICE_APPROVE,
        payload_type="ServiceApprove",
        payload=forge_payload,
        author=did_att,   # NOT the provider
        sig=forge_sig,
        author_pubkey_hex=pub_att.hex(),
    )

    # State must still be PENDING — the forged entry must be ignored
    state = subscription_state(tmp_journal, sub.subscription_id)
    assert state == SubscriptionState.PENDING, (
        f"A non-provider SERVICE_APPROVE must NOT change state; got {state}"
    )


# ---------------------------------------------------------------------------
# 6. revoke_offer by non-provider → PermissionError; by provider → offer gone
# ---------------------------------------------------------------------------

def test_revoke_offer_by_non_provider_raises(tmp_journal):
    """A non-provider cannot revoke an offer — must raise PermissionError."""
    priv_p, pub_p, did_p = _make_member(tmp_journal)
    priv_other, pub_other, did_other = _make_member(tmp_journal)

    offer = offer_service(
        tmp_journal, priv_p, did_p,
        name="RevokeMe", kind="api", endpoint="/r",
    )

    with pytest.raises(PermissionError):
        revoke_offer(tmp_journal, priv_other, did_other, offer.service_id)


def test_revoke_offer_by_provider_removes_from_catalog(tmp_journal):
    """Provider revokes their own offer → _get_offers no longer includes it."""
    priv_p, pub_p, did_p = _make_member(tmp_journal)

    offer = offer_service(
        tmp_journal, priv_p, did_p,
        name="Ephemeral", kind="api", endpoint="/ephemeral",
    )
    assert len(_get_offers(tmp_journal)) == 1

    revoke_offer(tmp_journal, priv_p, did_p, offer.service_id)
    assert len(_get_offers(tmp_journal)) == 0


def test_subscribe_to_revoked_offer_fails(tmp_journal):
    """Subscribing to a revoked offer must raise ValueError."""
    priv_p, pub_p, did_p = _make_member(tmp_journal)
    priv_s, pub_s, did_s = _make_member(tmp_journal)

    offer = offer_service(
        tmp_journal, priv_p, did_p,
        name="Gone", kind="api", endpoint="/gone",
    )
    revoke_offer(tmp_journal, priv_p, did_p, offer.service_id)

    with pytest.raises(ValueError):
        subscribe(tmp_journal, priv_s, did_s, offer.service_id)


# ---------------------------------------------------------------------------
# 7. subscribe by OBSERVED (non-member) → PermissionError
# ---------------------------------------------------------------------------

def test_subscribe_by_observed_raises_permission_error(tmp_journal):
    """An OBSERVED (non-member) node cannot subscribe — must raise PermissionError."""
    priv_p, pub_p, did_p = _make_member(tmp_journal)
    priv_obs, pub_obs, did_obs = _make_observed(tmp_journal)

    offer = offer_service(
        tmp_journal, priv_p, did_p,
        name="MemberOnly", kind="api", endpoint="/members",
    )

    with pytest.raises(PermissionError):
        subscribe(tmp_journal, priv_obs, did_obs, offer.service_id)


# ---------------------------------------------------------------------------
# 8. ingest_offer valid sig → ingested; tampered/forged sig → ValueError
# ---------------------------------------------------------------------------

def _build_signed_offer(priv: bytes, did: str, **kwargs) -> tuple:
    """Build a signed ServiceOffer and return (offer_obj, provider_pubkey_hex)."""
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
    from cryptography.hazmat.primitives import serialization

    priv_key = _ed25519.Ed25519PrivateKey.from_private_bytes(priv)
    pub_key = priv_key.public_key()
    pub_hex = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    service_id = os.urandom(16).hex()
    offer = ServiceOffer(
        service_id=service_id,
        provider=did,
        name=kwargs.get("name", "RemoteSvc"),
        kind=kwargs.get("kind", "api"),
        endpoint=kwargs.get("endpoint", "http://remote/api"),
        approval_mode=ApprovalMode(kwargs.get("approval_mode", "auto")),
        description=kwargs.get("description", ""),
    )
    full = offer.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    sig_hex = sign(priv, canonical_bytes(payload))
    signed_offer = ServiceOffer(**{**payload, "sig": sig_hex, "signer_did": did})
    return signed_offer, pub_hex


def test_ingest_offer_valid_sig_succeeds(tmp_journal):
    """ingest_offer with a valid provider sig must be accepted into the catalog."""
    # Remote provider keypair (unknown to local journal)
    priv_remote, pub_remote = generate_keypair()
    did_remote = did_from_pubkey(pub_remote)

    signed_offer, pub_hex = _build_signed_offer(priv_remote, did_remote, name="Remote")

    ingest_offer(tmp_journal, signed_offer, pub_hex)

    # The offer should appear in the journal
    offers = []
    for entry in tmp_journal.iter_entries():
        if entry.op == Op.SERVICE_OFFER:
            offers.append(entry.payload)
    assert any(o.get("service_id") == signed_offer.service_id for o in offers), (
        "Ingested offer must appear in the journal"
    )


def test_ingest_offer_wrong_pubkey_raises_value_error(tmp_journal):
    """ingest_offer with a pubkey that doesn't hash to the provider DID is rejected.

    This is the self-certifying guard: a supplied pubkey must satisfy
    did_from_pubkey(pubkey) == offer.provider. A completely different keypair's
    pubkey hashes to a different DID, so the offer is rejected BEFORE the
    signature is even checked — closing the "bring your own key, claim any DID"
    forgery.
    """
    priv_remote, pub_remote = generate_keypair()
    did_remote = did_from_pubkey(pub_remote)

    signed_offer, _correct_pub_hex = _build_signed_offer(priv_remote, did_remote)

    # Use a completely different keypair's pubkey
    _, wrong_pub = generate_keypair()
    wrong_pub_hex = wrong_pub.hex()

    with pytest.raises(ValueError, match="self-certification failed"):
        ingest_offer(tmp_journal, signed_offer, wrong_pub_hex)


def test_ingest_offer_tampered_sig_raises_value_error(tmp_journal):
    """ingest_offer with a tampered (wrong) sig must raise ValueError."""
    priv_remote, pub_remote = generate_keypair()
    did_remote = did_from_pubkey(pub_remote)

    signed_offer, pub_hex = _build_signed_offer(priv_remote, did_remote)

    # Tamper the sig by flipping a character
    bad_sig = "0" * 128  # all zeros — definitely invalid
    tampered = ServiceOffer(**{**signed_offer.model_dump(), "sig": bad_sig})

    with pytest.raises(ValueError, match="signature verification failed"):
        ingest_offer(tmp_journal, tampered, pub_hex)


def test_ingest_offer_missing_sig_raises_value_error(tmp_journal):
    """ingest_offer with no sig must raise ValueError immediately."""
    priv_remote, pub_remote = generate_keypair()
    did_remote = did_from_pubkey(pub_remote)

    # Build offer without a sig
    offer_no_sig = ServiceOffer(
        service_id=os.urandom(16).hex(),
        provider=did_remote,
        name="Unsigned",
        kind="api",
        endpoint="/unsigned",
        sig=None,
    )

    with pytest.raises(ValueError, match="no signature"):
        ingest_offer(tmp_journal, offer_no_sig, pub_remote.hex())


def test_ingest_offer_forged_provider_did_raises(tmp_journal):
    """Forging a provider DID (signing with wrong key) must be rejected."""
    priv_legit, pub_legit = generate_keypair()
    did_legit = did_from_pubkey(pub_legit)

    priv_attacker, pub_attacker = generate_keypair()
    did_attacker = did_from_pubkey(pub_attacker)

    # Attacker signs a payload claiming to be did_legit
    service_id = os.urandom(16).hex()
    offer = ServiceOffer(
        service_id=service_id,
        provider=did_legit,  # claims to be the legit provider
        name="Forged",
        kind="api",
        endpoint="/forged",
    )
    full = offer.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    # Attacker signs with THEIR key
    bad_sig = sign(priv_attacker, canonical_bytes(payload))
    forged_offer = ServiceOffer(**{**payload, "sig": bad_sig, "signer_did": did_attacker})

    # Verifying against the LEGIT provider's pubkey must fail
    with pytest.raises(ValueError, match="signature verification failed"):
        ingest_offer(tmp_journal, forged_offer, pub_legit.hex())


# ---------------------------------------------------------------------------
# 9. Comprehensive: reject then non-provider-approve does not override
# ---------------------------------------------------------------------------

def test_reject_then_non_provider_approve_stays_rejected(tmp_journal):
    """Once rejected by the provider, a non-provider approve must not override."""
    priv_p, pub_p, did_p = _make_member(tmp_journal)
    priv_s, pub_s, did_s = _make_member(tmp_journal)
    priv_att, pub_att, did_att = _make_member(tmp_journal)

    offer = offer_service(
        tmp_journal, priv_p, did_p,
        name="SecureSvc2", kind="api", endpoint="/s2",
        approval_mode="pending",
    )
    sub = subscribe(tmp_journal, priv_s, did_s, offer.service_id)

    # Provider rejects
    reject_subscription(tmp_journal, priv_p, did_p, sub.subscription_id)

    # Attacker writes a SERVICE_APPROVE directly
    forge_payload = {
        "subscription_id": sub.subscription_id,
        "service_id": offer.service_id,
        "approver": did_att,
        "approved_at": now_rfc3339(),
    }
    forge_sig = sign(priv_att, canonical_bytes(forge_payload))
    tmp_journal.append(
        op=Op.SERVICE_APPROVE,
        payload_type="ServiceApprove",
        payload=forge_payload,
        author=did_att,
        sig=forge_sig,
        author_pubkey_hex=pub_att.hex(),
    )

    # State must remain REJECTED (revoke takes priority, and the forged approve is ignored)
    state = subscription_state(tmp_journal, sub.subscription_id)
    assert state == SubscriptionState.REJECTED, (
        f"After provider reject + forged approve, state must be REJECTED, got {state}"
    )


# ---------------------------------------------------------------------------
# 10. _get_offer returns None for unknown service_id
# ---------------------------------------------------------------------------

def test_get_offer_unknown_returns_none(tmp_journal):
    """_get_offer for an unknown service_id must return None."""
    result = _get_offer(tmp_journal, "nonexistent-service-id")
    assert result is None


# ---------------------------------------------------------------------------
# 11. subscription_state raises for unknown subscription_id
# ---------------------------------------------------------------------------

def test_subscription_state_unknown_raises(tmp_journal):
    """subscription_state for an unknown subscription_id must raise ValueError."""
    with pytest.raises(ValueError, match="not found"):
        subscription_state(tmp_journal, "nonexistent-sub-id")
