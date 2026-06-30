# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_crypto.py
Tests for annuaire.crypto — Ed25519 sign/verify, DID derivation, canonical bytes.
All tests follow TDD: written before implementation.
"""
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
from cryptography.hazmat.primitives import serialization

from annuaire.crypto import (
    generate_keypair,
    sign,
    verify,
    did_from_pubkey,
    canonical_bytes,
    MembershipProver,
    verify_nizk,
)


# ---------------------------------------------------------------------------
# Helpers — generate a real keypair for tests
# ---------------------------------------------------------------------------

def _make_keypair():
    """Return (priv_bytes_raw, pub_bytes_raw)."""
    priv = _ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_raw, pub_raw


# ---------------------------------------------------------------------------
# generate_keypair
# ---------------------------------------------------------------------------

def test_generate_keypair_returns_32_byte_keys():
    priv, pub = generate_keypair()
    assert len(priv) == 32, "Ed25519 raw private key must be 32 bytes"
    assert len(pub) == 32, "Ed25519 raw public key must be 32 bytes"


def test_generate_keypair_produces_distinct_keys_each_call():
    _, pub1 = generate_keypair()
    _, pub2 = generate_keypair()
    assert pub1 != pub2, "Each call should produce a fresh keypair"


# ---------------------------------------------------------------------------
# sign / verify round-trip
# ---------------------------------------------------------------------------

def test_sign_verify_round_trip():
    priv, pub = _make_keypair()
    msg = b"hello annuaire"
    sig_hex = sign(priv, msg)
    pub_hex = pub.hex()
    assert verify(pub_hex, msg, sig_hex), "Round-trip sign/verify must succeed"


def test_verify_rejects_wrong_signature():
    priv, pub = _make_keypair()
    msg = b"legitimate message"
    sig_hex = sign(priv, msg)
    # Flip the last byte
    sig_bytes = bytearray(bytes.fromhex(sig_hex))
    sig_bytes[-1] ^= 0xFF
    bad_sig = bytes(sig_bytes).hex()
    pub_hex = pub.hex()
    assert not verify(pub_hex, msg, bad_sig), "Corrupted signature must be rejected"


def test_verify_rejects_wrong_key():
    priv1, _pub1 = _make_keypair()
    _priv2, pub2 = _make_keypair()
    msg = b"signed by key1"
    sig_hex = sign(priv1, msg)
    assert not verify(pub2.hex(), msg, sig_hex), "Signature from key1 must not verify under key2"


def test_verify_rejects_tampered_message():
    priv, pub = _make_keypair()
    original_msg = b"original"
    sig_hex = sign(priv, original_msg)
    tampered_msg = b"tampered"
    assert not verify(pub.hex(), tampered_msg, sig_hex), "Tampered message must not verify"


def test_sign_returns_hex_string_of_correct_length():
    priv, _ = _make_keypair()
    sig_hex = sign(priv, b"test")
    # Ed25519 signature is 64 bytes → 128 hex chars
    assert isinstance(sig_hex, str)
    assert len(sig_hex) == 128


# ---------------------------------------------------------------------------
# did_from_pubkey
# ---------------------------------------------------------------------------

def test_did_from_pubkey_has_correct_prefix():
    _, pub = _make_keypair()
    did = did_from_pubkey(pub)
    assert did.startswith("did:plc:"), "DID must start with did:plc:"


def test_did_from_pubkey_suffix_is_32_hex_chars():
    _, pub = _make_keypair()
    did = did_from_pubkey(pub)
    suffix = did[len("did:plc:"):]
    assert len(suffix) == 32, "DID suffix must be 32 hex characters (sha256[:32])"
    assert all(c in "0123456789abcdef" for c in suffix), "DID suffix must be lowercase hex"


def test_did_from_pubkey_is_deterministic():
    _, pub = _make_keypair()
    assert did_from_pubkey(pub) == did_from_pubkey(pub), "Same pubkey must always yield same DID"


def test_did_from_pubkey_matches_identity_manager_formula():
    """Mirror the exact formula from packages/secubox-identity/api/main.py."""
    import hashlib
    _, pub = _make_keypair()
    expected = "did:plc:" + hashlib.sha256(pub).hexdigest()[:32]
    assert did_from_pubkey(pub) == expected


# ---------------------------------------------------------------------------
# canonical_bytes
# ---------------------------------------------------------------------------

def test_canonical_bytes_is_stable_across_dict_ordering():
    d1 = {"b": 2, "a": 1, "z": "hello"}
    d2 = {"z": "hello", "a": 1, "b": 2}
    assert canonical_bytes(d1) == canonical_bytes(d2), "canonical_bytes must be key-order-independent"


def test_canonical_bytes_returns_bytes():
    assert isinstance(canonical_bytes({"x": 1}), bytes)


def test_canonical_bytes_differs_on_different_payloads():
    assert canonical_bytes({"a": 1}) != canonical_bytes({"a": 2})


def test_canonical_bytes_no_whitespace():
    b = canonical_bytes({"key": "value"})
    assert b"  " not in b, "canonical encoding must not contain double spaces"
    assert b"\n" not in b, "canonical encoding must not contain newlines"


# ---------------------------------------------------------------------------
# NIZK interface stubs
# ---------------------------------------------------------------------------

def test_membership_prover_is_instantiatable():
    """The MembershipProver interface must be importable and instantiatable."""
    prover = MembershipProver()
    assert prover is not None


def test_verify_nizk_default_allows_known_member():
    """v0 default: log-state membership — a member not in revoked set is allowed."""
    log_state = {"members": {"did:plc:abcd1234abcd1234abcd1234abcd1234"}, "revoked": set()}
    result = verify_nizk(
        proof=None,
        domain="fr-chambery",
        subject_did="did:plc:abcd1234abcd1234abcd1234abcd1234",
        log_state=log_state,
    )
    assert result is True


def test_verify_nizk_default_rejects_revoked_member():
    """v0 default: a revoked member must not pass the NIZK stub."""
    did = "did:plc:abcd1234abcd1234abcd1234abcd1234"
    log_state = {"members": {did}, "revoked": {did}}
    result = verify_nizk(
        proof=None,
        domain="fr-chambery",
        subject_did=did,
        log_state=log_state,
    )
    assert result is False


def test_verify_nizk_default_rejects_unknown_member():
    """v0 default: a DID never added to members is not a member."""
    log_state = {"members": set(), "revoked": set()}
    result = verify_nizk(
        proof=None,
        domain="fr-chambery",
        subject_did="did:plc:deadbeefdeadbeefdeadbeefdeadbeef",
        log_state=log_state,
    )
    assert result is False
