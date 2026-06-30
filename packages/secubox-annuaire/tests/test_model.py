# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_model.py
Tests for annuaire.model — Pydantic v2 data objects, validators,
compute_entry_hash, BLAKE2b chain link.
All tests follow TDD: written before implementation.
"""
import hashlib
import pytest
from pydantic import ValidationError

from annuaire.model import (
    Identity,
    Attestation,
    Invitation,
    Proposal,
    RevocationNotice,
    WitnessAttest,
    LogEntry,
    JuridictionTag,
    MemberState,
    Op,
    ProposalType,
    QuorumRule,
    RevocationScope,
    GENESIS_HASH,
    compute_entry_hash,
    now_rfc3339,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_did_and_digest():
    """Return a (did, pubkey_hex, self_cert_digest) triple that satisfies the validator."""
    import os
    raw_pub = os.urandom(32)
    digest = hashlib.sha256(raw_pub).hexdigest()[:32]
    did = f"did:plc:{digest}"
    return did, raw_pub.hex(), digest


# ---------------------------------------------------------------------------
# JuridictionTag
# ---------------------------------------------------------------------------

def test_juridiction_tag_accepts_valid_zone():
    tag = JuridictionTag(
        isolation_domain="fr-chambery",
        legal_regime="FR",
        consented=True,
    )
    assert tag.isolation_domain == "fr-chambery"


def test_juridiction_tag_rejects_lat_long_in_isolation_domain():
    with pytest.raises(ValidationError, match="zones, not coordinates"):
        JuridictionTag(
            isolation_domain="48.5833,6.3",
            legal_regime="FR",
            consented=True,
        )


def test_juridiction_tag_rejects_lat_long_in_legal_regime():
    with pytest.raises(ValidationError, match="zones, not coordinates"):
        JuridictionTag(
            isolation_domain="fr-chambery",
            legal_regime="48.5,5.5",
            consented=True,
        )


def test_juridiction_tag_forbids_extra_fields():
    with pytest.raises(ValidationError):
        JuridictionTag(
            isolation_domain="fr-chambery",
            legal_regime="FR",
            consented=True,
            latitude=45.5,  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# Identity — self-certification validator
# ---------------------------------------------------------------------------

def test_identity_accepts_self_certifying_did():
    did, pub_hex, digest = _valid_did_and_digest()
    ident = Identity(did=did, pubkey=pub_hex, self_cert_digest=digest)
    assert ident.did == did
    assert ident.state == MemberState.OBSERVED  # default state


def test_identity_rejects_digest_not_matching_did():
    did, pub_hex, digest = _valid_did_and_digest()
    wrong_digest = "a" * 32  # doesn't match did suffix
    # Only fails if it's actually different from did suffix
    if wrong_digest != digest:
        with pytest.raises(ValidationError, match="self_cert_digest does not match did"):
            Identity(did=did, pubkey=pub_hex, self_cert_digest=wrong_digest)


def test_identity_rejects_malformed_did_pattern():
    with pytest.raises(ValidationError):
        Identity(
            did="not-a-did",
            pubkey="aa" * 32,
            self_cert_digest="a" * 32,
        )


def test_identity_default_state_is_observed():
    did, pub_hex, digest = _valid_did_and_digest()
    ident = Identity(did=did, pubkey=pub_hex, self_cert_digest=digest)
    assert ident.state == MemberState.OBSERVED


def test_identity_forbids_extra_fields():
    did, pub_hex, digest = _valid_did_and_digest()
    with pytest.raises(ValidationError):
        Identity(
            did=did,
            pubkey=pub_hex,
            self_cert_digest=digest,
            coordinate=45.0,  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------

def test_attestation_accepts_valid_object():
    did1, _, _ = _valid_did_and_digest()
    did2, _, _ = _valid_did_and_digest()
    a = Attestation(
        attester=did1,
        subject=did2,
        context="mesh.route",
        domain="fr-chambery",
    )
    assert a.revoked is False
    assert 0.0 <= a.weight <= 1.0


def test_attestation_weight_clamp():
    did1, _, _ = _valid_did_and_digest()
    did2, _, _ = _valid_did_and_digest()
    with pytest.raises(ValidationError):
        Attestation(attester=did1, subject=did2, context="x", domain="y", weight=1.5)


# ---------------------------------------------------------------------------
# Invitation
# ---------------------------------------------------------------------------

def test_invitation_co_stake_defaults_true():
    did, _, _ = _valid_did_and_digest()
    inv = Invitation(
        invite_id="ff" * 32,
        inviter=did,
        domain="fr-chambery",
        expires_at="2027-01-01T00:00:00Z",
    )
    assert inv.co_stake is True
    assert inv.max_uses == 1


# ---------------------------------------------------------------------------
# RevocationNotice — bounded cascade
# ---------------------------------------------------------------------------

def test_revocation_notice_cascade_depth_limit():
    did, _, _ = _valid_did_and_digest()
    with pytest.raises(ValidationError):
        RevocationNotice(
            revocation_id="ee" * 32,
            revoker=did,
            target=did,
            reason="test",
            cascade_depth=9,  # > 8 not allowed
        )


def test_revocation_notice_defaults_self_scope():
    did, _, _ = _valid_did_and_digest()
    r = RevocationNotice(
        revocation_id="ee" * 32,
        revoker=did,
        target=did,
        reason="misbehaviour",
    )
    assert r.scope == RevocationScope.SELF


# ---------------------------------------------------------------------------
# Proposal
# ---------------------------------------------------------------------------

def test_proposal_quorum_threshold_must_exceed_half():
    did, _, _ = _valid_did_and_digest()
    with pytest.raises(ValidationError):
        Proposal(
            proposal_id="dd" * 32,
            proposer=did,
            ptype=ProposalType.CHANGE_PROTOCOL,
            domain="fr-chambery",
            closes_at="2027-01-01T00:00:00Z",
            quorum_threshold=0.5,  # must be > 0.5
        )


def test_proposal_default_quorum_rule_is_one_node_one_voice():
    did, _, _ = _valid_did_and_digest()
    p = Proposal(
        proposal_id="dd" * 32,
        proposer=did,
        ptype=ProposalType.QUORUM_REVISION,
        domain="fr-chambery",
        closes_at="2027-01-01T00:00:00Z",
    )
    assert p.quorum_rule == QuorumRule.ONE_NODE_ONE_VOICE


# ---------------------------------------------------------------------------
# WitnessAttest
# ---------------------------------------------------------------------------

def test_witness_attest_valid():
    did, _, _ = _valid_did_and_digest()
    w = WitnessAttest(
        witness=did,
        domain="fr-chambery",
        log_height=0,
        merkle_root="aa" * 32,
    )
    assert w.log_height == 0


# ---------------------------------------------------------------------------
# LogEntry — structure
# ---------------------------------------------------------------------------

def _minimal_log_entry(height=0, prev_hash=GENESIS_HASH):
    did, _, _ = _valid_did_and_digest()
    payload = {"test": "data"}
    import json
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = "aa" * 64  # 128-char hex — placeholder (not verified in model)
    entry_hash = compute_entry_hash(prev_hash, payload_bytes, sig)
    return LogEntry(
        height=height,
        op=Op.AUTO_ADD,
        prev_hash=prev_hash,
        payload_type="Identity",
        payload=payload,
        author=did,
        sig=sig,
        entry_hash=entry_hash,
    )


def test_log_entry_genesis_uses_genesis_hash():
    entry = _minimal_log_entry(height=0, prev_hash=GENESIS_HASH)
    assert entry.prev_hash == GENESIS_HASH
    assert entry.height == 0


def test_log_entry_height_must_be_non_negative():
    with pytest.raises(ValidationError):
        did, _, _ = _valid_did_and_digest()
        LogEntry(
            height=-1,
            op=Op.AUTO_ADD,
            prev_hash=GENESIS_HASH,
            payload_type="Identity",
            payload={},
            author=did,
            sig="aa" * 64,
            entry_hash="bb" * 32,
        )


# ---------------------------------------------------------------------------
# compute_entry_hash
# ---------------------------------------------------------------------------

def test_compute_entry_hash_is_deterministic():
    prev = GENESIS_HASH
    payload = b'{"op":"test"}'
    sig = "cc" * 64
    h1 = compute_entry_hash(prev, payload, sig)
    h2 = compute_entry_hash(prev, payload, sig)
    assert h1 == h2, "compute_entry_hash must be deterministic"


def test_compute_entry_hash_changes_on_payload_change():
    prev = GENESIS_HASH
    sig = "cc" * 64
    h1 = compute_entry_hash(prev, b'{"a":1}', sig)
    h2 = compute_entry_hash(prev, b'{"a":2}', sig)
    assert h1 != h2, "Hash must change when payload changes"


def test_compute_entry_hash_changes_on_prev_hash_change():
    prev1 = GENESIS_HASH
    prev2 = "1" * 64
    payload = b'{"x":"y"}'
    sig = "cc" * 64
    assert compute_entry_hash(prev1, payload, sig) != compute_entry_hash(prev2, payload, sig)


def test_compute_entry_hash_changes_on_sig_change():
    prev = GENESIS_HASH
    payload = b'{"x":"y"}'
    h1 = compute_entry_hash(prev, payload, "aa" * 64)
    h2 = compute_entry_hash(prev, payload, "bb" * 64)
    assert h1 != h2


def test_compute_entry_hash_returns_64_hex_chars():
    h = compute_entry_hash(GENESIS_HASH, b"payload", "aa" * 64)
    assert len(h) == 64  # BLAKE2b-256 → 32 bytes → 64 hex
    assert all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------------------
# now_rfc3339 utility
# ---------------------------------------------------------------------------

def test_now_rfc3339_returns_string():
    ts = now_rfc3339()
    assert isinstance(ts, str)
    assert "T" in ts  # RFC 3339 has 'T' between date and time


def test_now_rfc3339_includes_utc_offset():
    ts = now_rfc3339()
    assert "+" in ts or ts.endswith("Z") or ts.endswith("+00:00"), \
        "Timestamp must include UTC offset"
