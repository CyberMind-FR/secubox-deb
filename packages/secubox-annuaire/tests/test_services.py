# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_services.py
Pytest coverage for service offers + subscription feature.
"""
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_journal(tmp_path):
    return Journal(str(tmp_path / "test.db"))


def make_member(journal: Journal):
    """Create a MEMBER node: auto_add + invite + accept_invite."""
    # Founder key
    founder_priv, founder_pub = generate_keypair()
    founder_did = did_from_pubkey(founder_pub)

    # Bootstrap founder as MEMBER via auto_add + self-invite trick:
    # 1. Auto-add founder as OBSERVED
    import hashlib
    digest = hashlib.sha256(founder_pub).hexdigest()[:32]
    ident = Identity(
        did=founder_did,
        pubkey=founder_pub.hex(),
        self_cert_digest=digest,
        state=MemberState.OBSERVED,
    )
    full = ident.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    payload["state"] = MemberState.OBSERVED.value
    sig_hex = sign(founder_priv, canonical_bytes(payload))
    ident_with_sig = Identity(**{**full, "sig": sig_hex, "signer_did": founder_did})
    from annuaire.verbs import auto_add
    auto_add(journal, ident_with_sig)

    # 2. Promote to MEMBER directly (post MEMBER Identity self-authored)
    ident_member = Identity(
        did=founder_did,
        pubkey=founder_pub.hex(),
        self_cert_digest=digest,
        state=MemberState.MEMBER,
        invited_by=None,
    )
    full_m = ident_member.model_dump()
    payload_m = {k: v for k, v in full_m.items() if k not in ("sig", "signer_did")}
    sig_m = sign(founder_priv, canonical_bytes(payload_m))
    journal.append(
        op=Op.INVITE_ACCEPT,
        payload_type="Identity",
        payload=payload_m,
        author=founder_did,
        sig=sig_m,
        author_pubkey_hex=founder_pub.hex(),
    )
    return founder_priv, founder_pub, founder_did


def make_two_members(journal: Journal):
    """Return (priv_a, pub_a, did_a, priv_b, pub_b, did_b) both MEMBER."""
    priv_a, pub_a, did_a = make_member(journal)

    priv_b, pub_b = generate_keypair()
    did_b = did_from_pubkey(pub_b)
    from annuaire.verbs import invite, accept_invite
    inv = invite(journal, priv_a, did_a, domain="test")
    accept_invite(journal, priv_b, did_b, inv)

    return priv_a, pub_a, did_a, priv_b, pub_b, did_b


# ---------------------------------------------------------------------------
# Smoke: model constructable
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
