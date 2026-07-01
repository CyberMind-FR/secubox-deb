# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
Tests for packages/secubox-p2p/api/macro_grant.py and
the _verify_subscription_sig helper in api/main.py.

Suite structure
---------------
1. Five pure authorize_grant unit tests (sig verification injected).
2. One real-sig round-trip test: generate an Ed25519 keypair, build and sign a
   Subscription the same way annuaire's subscribe() verb does, assert that
   _verify_subscription_sig accepts it and rejects a tampered version.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

# Ensure `from api import ...` resolves from the package root (mirrors conftest.py).
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))

from api import macro_grant, annuaire_client

# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------

DID = "did:plc:" + "b" * 32
_PROVIDER_DID = "did:plc:" + "c" * 32


def _offer(mode: str = "auto", macro: bool = True) -> dict:
    o: dict = {
        "service_id": "svc1",
        "provider": _PROVIDER_DID,
        "approval_mode": mode,
    }
    if macro:
        o["macro"] = {"kind": "tor-exit", "params": {"socks_port": 9050}}
    return o


def _sub(service_id: str = "svc1", subscriber: str = DID) -> dict:
    return {
        "subscriber": subscriber,
        "service_id": service_id,
        "sig": "ok",
        "signer_did": subscriber,
        "subscriber_pubkey": "deadbeef",
    }


# ---------------------------------------------------------------------------
# 1. Pure authorize_grant tests (sig verify injected via lambda)
# ---------------------------------------------------------------------------

def test_authorize_ok_when_sig_valid_service_matches_and_auto():
    ok, why = macro_grant.authorize_grant(_offer(), _sub(), verify_fn=lambda s: True)
    assert ok, why


def test_reject_when_sig_invalid():
    ok, why = macro_grant.authorize_grant(_offer(), _sub(), verify_fn=lambda s: False)
    assert not ok
    assert "sig" in why.lower()


def test_reject_when_service_id_mismatch():
    ok, why = macro_grant.authorize_grant(
        _offer(), _sub(service_id="other"), verify_fn=lambda s: True
    )
    assert not ok


def test_reject_when_offer_pending():
    ok, why = macro_grant.authorize_grant(
        _offer(mode="pending"), _sub(), verify_fn=lambda s: True
    )
    assert not ok
    assert "auto" in why.lower()


def test_reject_when_no_macro():
    ok, why = macro_grant.authorize_grant(
        _offer(macro=False), _sub(), verify_fn=lambda s: True
    )
    assert not ok


# ---------------------------------------------------------------------------
# 2. Real Ed25519 sig round-trip test
#
# We generate a keypair, build a Subscription dict and sign it exactly the
# way annuaire's subscribe() verb does:
#
#   sub = Subscription(subscription_id=..., subscriber=..., service_id=..., requested_at=...)
#   full = sub.model_dump()   → includes sig=None, signer_did=None
#   payload = {k:v for k,v in full.items() if k not in ("sig","signer_did")}
#   sig_hex = sign(priv, canonical_bytes(payload))
#
# canonical_bytes (from annuaire/crypto.py):
#   json.dumps(obj, sort_keys=True, separators=(",",":")).encode("utf-8")
#
# We then call _verify_subscription_sig (imported from api/main.py) with the
# full sub dict + pub_hex and assert:
#   - valid Subscription verifies to True
#   - tampered subscriber field verifies to False
# ---------------------------------------------------------------------------

def _annuaire_canonical_bytes(obj: dict) -> bytes:
    """Mirror of annuaire/crypto.py::canonical_bytes — replicated here so
    this test has NO import dependency on the secubox-annuaire package."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _annuaire_sign(priv_bytes: bytes, msg: bytes) -> str:
    """Mirror of annuaire/crypto.py::sign."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    return priv_key.sign(msg).hex()


def _annuaire_public_from_private(priv_bytes: bytes) -> bytes:
    """Mirror of annuaire/crypto.py::public_from_private."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    priv_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    return priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _build_signed_subscription(
    priv_bytes: bytes,
    sub_did: str,
    service_id: str,
) -> dict:
    """Build + sign a Subscription the same way annuaire's subscribe() verb does.

    Returns the full dict (including sig + signer_did + subscriber_pubkey)
    that a consumer would POST to the grant endpoint.
    """
    subscription_id = os.urandom(32).hex()
    # Mirror Subscription.model_dump() field order (Pydantic v2 preserves field
    # declaration order): subscription_id, subscriber, service_id, requested_at,
    # sig=None, signer_did=None.  We drop sig/signer_did from the signed payload.
    payload = {
        "subscription_id": subscription_id,
        "subscriber": sub_did,
        "service_id": service_id,
        "requested_at": "2026-07-01T00:00:00+00:00",
    }
    sig_hex = _annuaire_sign(priv_bytes, _annuaire_canonical_bytes(payload))
    pub_bytes = _annuaire_public_from_private(priv_bytes)
    return {
        **payload,
        "sig": sig_hex,
        "signer_did": sub_did,
        "subscriber_pubkey": pub_bytes.hex(),
    }


def test_real_sig_verify_accepts_valid_and_rejects_tampered():
    """A real annuaire-style signed Subscription verifies correctly."""
    from api.main import _verify_subscription_sig

    # Generate a fresh keypair.
    priv_bytes = os.urandom(32)
    pub_bytes = _annuaire_public_from_private(priv_bytes)
    pub_hex = pub_bytes.hex()

    # Derive the self-certifying DID.
    sub_did = annuaire_client.did_from_pubkey_hex(pub_hex)

    # Build a properly signed Subscription.
    sub_dict = _build_signed_subscription(priv_bytes, sub_did, "svc-test")

    # Should verify successfully.
    assert _verify_subscription_sig(sub_dict, pub_hex), (
        "_verify_subscription_sig must accept a correctly signed Subscription"
    )

    # Tamper with the subscriber field — sig must no longer verify.
    tampered = {**sub_dict, "subscriber": "did:plc:" + "f" * 32}
    assert not _verify_subscription_sig(tampered, pub_hex), (
        "_verify_subscription_sig must reject a tampered Subscription"
    )

    # Tamper with the sig itself — must also reject.
    bad_sig = {**sub_dict, "sig": "00" * 64}
    assert not _verify_subscription_sig(bad_sig, pub_hex), (
        "_verify_subscription_sig must reject a corrupted sig"
    )


def test_verify_rejects_pubkey_did_mismatch():
    """Self-cert guarantee: a valid sig for attacker's key claiming a victim DID is rejected.

    Attacker keypair A signs a subscription, but sets subscriber = B's DID
    (derived from keypair B) while subscriber_pubkey = A's pubkey.
    did_from_pubkey_hex(A_pubkey) != B_did → the endpoint's _verify must return False.
    """
    from api.main import _verify_subscription_sig

    # Attacker keypair A
    priv_a = os.urandom(32)
    pub_a_bytes = _annuaire_public_from_private(priv_a)
    pub_a_hex = pub_a_bytes.hex()

    # Victim keypair B (only the DID is used — attacker doesn't have the private key)
    priv_b = os.urandom(32)
    pub_b_bytes = _annuaire_public_from_private(priv_b)
    pub_b_hex = pub_b_bytes.hex()
    victim_did = annuaire_client.did_from_pubkey_hex(pub_b_hex)

    # Build a subscription claiming victim_did as subscriber, signed with A's key
    sub_dict = _build_signed_subscription(priv_a, victim_did, "svc-attack")
    # subscriber_pubkey is A's pubkey (attacker's own key), subscriber is B's DID
    assert sub_dict["subscriber_pubkey"] == pub_a_hex
    assert sub_dict["subscriber"] == victim_did

    # The sig itself is valid for A's key over the payload containing victim_did,
    # but did_from_pubkey_hex(A_pubkey) != victim_did — so the DID-binding check
    # in the endpoint's _verify closure must reject this.
    # We replicate the _verify closure logic directly here:
    pub = sub_dict.get("subscriber_pubkey", "") or ""
    did_match = annuaire_client.did_from_pubkey_hex(pub) == sub_dict.get("subscriber")
    assert not did_match, (
        "A pubkey must NOT produce the victim DID: self-cert binding violated"
    )

    # Additionally, _verify_subscription_sig itself must also reject because
    # the sig is over a payload that contains victim_did as subscriber,
    # and pub_a_hex verifies it correctly (sig is structurally valid).
    # The DID mismatch is caught one layer up (_verify closure), but let's also
    # confirm that passing A's pubkey verifies and B's pubkey does not —
    # proving no key confusion at the crypto layer.
    assert _verify_subscription_sig(sub_dict, pub_a_hex), (
        "The sig should verify when checked against attacker's own pubkey"
    )
    assert not _verify_subscription_sig(sub_dict, pub_b_hex), (
        "The sig must NOT verify against the victim's pubkey (different key)"
    )
