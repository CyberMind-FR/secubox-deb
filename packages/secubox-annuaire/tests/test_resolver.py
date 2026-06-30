# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_resolver.py
Tests for annuaire.resolver — the can() access adjudicator.
All tests follow TDD: written before implementation.
"""
import hashlib
from typing import Optional
import pytest

from annuaire.model import (
    Identity,
    Attestation,
    MemberState,
    Op,
    GENESIS_HASH,
)
from annuaire.crypto import generate_keypair, sign, did_from_pubkey, canonical_bytes
from annuaire.log import Journal
from annuaire.resolver import can, Decision


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_identity_and_keypair():
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    digest = hashlib.sha256(pub).hexdigest()[:32]
    ident = Identity(did=did, pubkey=pub.hex(), self_cert_digest=digest)
    return priv, pub, did, ident


def _append_identity(journal: Journal, priv, did, ident: Identity, op=Op.AUTO_ADD,
                     pub_hex: Optional[str] = None):
    payload = ident.model_dump()
    cb = canonical_bytes(payload)
    sig = sign(priv, cb)
    # pub_hex is available from ident.pubkey for bootstrap
    author_pubkey_hex = pub_hex or ident.pubkey
    return journal.append(op, "Identity", payload, did, sig,
                          author_pubkey_hex=author_pubkey_hex)


def _append_attestation(journal: Journal, priv, attester_did: str, attest: Attestation,
                        pub_hex: Optional[str] = None):
    payload = attest.model_dump()
    cb = canonical_bytes(payload)
    sig = sign(priv, cb)
    return journal.append(Op.ATTEST, "Attestation", payload, attester_did, sig,
                          author_pubkey_hex=pub_hex)


def _make_full_member_setup(journal: Journal):
    """
    Create a MEMBER-state identity with a supporting attestation.
    Returns (priv, did, attestation) ready for can() tests.
    """
    priv, pub, did, ident = _make_identity_and_keypair()
    ident_member = Identity(
        did=did,
        pubkey=pub.hex(),
        self_cert_digest=hashlib.sha256(pub).hexdigest()[:32],
        state=MemberState.MEMBER,
    )
    _append_identity(journal, priv, did, ident_member, op=Op.INVITE_ACCEPT)

    # Attester can be the same did for this test (self-attesting domain membership)
    attest = Attestation(
        attester=did,
        subject=did,
        context="mesh.route",
        domain="fr-chambery",
    )
    _append_attestation(journal, priv, did, attest)
    return priv, did, attest


# ---------------------------------------------------------------------------
# Decision dataclass
# ---------------------------------------------------------------------------

def test_decision_has_allowed_and_reasons():
    d = Decision(allowed=True, reasons=["reconciled"])
    assert d.allowed is True
    assert "reconciled" in d.reasons


# ---------------------------------------------------------------------------
# can() — unknown identity
# ---------------------------------------------------------------------------

def test_can_denies_unknown_identity(tmp_path):
    journal = Journal(db_path=str(tmp_path / "t.db"))
    d = can(
        journal=journal,
        subject_did="did:plc:deadbeefdeadbeefdeadbeefdeadbeef",
        action="attest",
        target="mesh.route",
        domain="fr-chambery",
    )
    assert d.allowed is False
    assert any("unknown" in r.lower() or "identity" in r.lower() for r in d.reasons)


# ---------------------------------------------------------------------------
# can() — ALLOWS when all four legs hold
# ---------------------------------------------------------------------------

def test_can_allows_member_with_valid_attestation(tmp_path):
    journal = Journal(db_path=str(tmp_path / "t.db"))
    priv, did, attest = _make_full_member_setup(journal)

    d = can(
        journal=journal,
        subject_did=did,
        action="attest",
        target="mesh.route",
        domain="fr-chambery",
    )
    assert d.allowed is True, f"Expected ALLOW, got reasons: {d.reasons}"


# ---------------------------------------------------------------------------
# can() — DENIES revoked member
# ---------------------------------------------------------------------------

def test_can_denies_revoked_member(tmp_path):
    journal = Journal(db_path=str(tmp_path / "t.db"))
    priv, pub, did, ident = _make_identity_and_keypair()
    # Add as REVOKED state
    ident_revoked = Identity(
        did=did,
        pubkey=pub.hex(),
        self_cert_digest=hashlib.sha256(pub).hexdigest()[:32],
        state=MemberState.REVOKED,
    )
    _append_identity(journal, priv, did, ident_revoked, op=Op.REVOKE)

    d = can(
        journal=journal,
        subject_did=did,
        action="attest",
        target="mesh.route",
        domain="fr-chambery",
    )
    assert d.allowed is False
    assert any("revoked" in r.lower() for r in d.reasons)


# ---------------------------------------------------------------------------
# can() — DENIES with no in-scope attestation
# ---------------------------------------------------------------------------

def test_can_denies_member_without_attestation(tmp_path):
    journal = Journal(db_path=str(tmp_path / "t.db"))
    priv, pub, did, ident = _make_identity_and_keypair()
    # Add as MEMBER but no attestation for the requested context
    ident_member = Identity(
        did=did,
        pubkey=pub.hex(),
        self_cert_digest=hashlib.sha256(pub).hexdigest()[:32],
        state=MemberState.MEMBER,
    )
    _append_identity(journal, priv, did, ident_member, op=Op.INVITE_ACCEPT)
    # NO attestation appended

    d = can(
        journal=journal,
        subject_did=did,
        action="attest",
        target="mesh.route",
        domain="fr-chambery",
    )
    assert d.allowed is False
    assert any("attestation" in r.lower() for r in d.reasons)


# ---------------------------------------------------------------------------
# can() — DENIES on broken chain
# ---------------------------------------------------------------------------

def test_can_denies_on_broken_chain(tmp_path):
    """A tampered journal must cause can() to return allowed=False."""
    import sqlite3
    journal = Journal(db_path=str(tmp_path / "t.db"))
    priv, did, attest = _make_full_member_setup(journal)

    # Tamper with height=0
    con = sqlite3.connect(str(tmp_path / "t.db"))
    con.execute("UPDATE log SET entry_hash = ? WHERE height = 0", ("dead" * 16,))
    con.commit()
    con.close()

    d = can(
        journal=journal,
        subject_did=did,
        action="attest",
        target="mesh.route",
        domain="fr-chambery",
    )
    assert d.allowed is False
    assert any("chain" in r.lower() or "tamper" in r.lower() or "broken" in r.lower()
               for r in d.reasons), f"Expected chain-related reason, got: {d.reasons}"


# ---------------------------------------------------------------------------
# can() — OBSERVED status alone never yields allow for MEMBER-gated actions
# ---------------------------------------------------------------------------

def test_can_denies_observed_for_member_gated_action(tmp_path):
    """AUTO-ADD/OBSERVED alone must never grant attest/vote/invite/name.bind."""
    journal = Journal(db_path=str(tmp_path / "t.db"))
    priv, pub, did, ident = _make_identity_and_keypair()
    # OBSERVED state (AUTO_ADD default)
    _append_identity(journal, priv, did, ident, op=Op.AUTO_ADD)

    for action in ("attest", "vote", "invite", "name.bind", "service.publish"):
        d = can(
            journal=journal,
            subject_did=did,
            action=action,
            target="any",
            domain="fr-chambery",
        )
        assert d.allowed is False, (
            f"OBSERVED identity must NOT be allowed for action={action!r}"
        )


def test_can_allows_observed_for_read_public(tmp_path):
    """OBSERVED identities must be allowed the minimal read.public right."""
    journal = Journal(db_path=str(tmp_path / "t.db"))
    priv, pub, did, ident = _make_identity_and_keypair()
    _append_identity(journal, priv, did, ident, op=Op.AUTO_ADD)

    d = can(
        journal=journal,
        subject_did=did,
        action="read.public",
        target="any",
        domain="fr-chambery",
    )
    assert d.allowed is True, f"OBSERVED identity should be allowed read.public, got: {d.reasons}"


# ---------------------------------------------------------------------------
# can() — reasons surfaced in Decision
# ---------------------------------------------------------------------------

def test_can_returns_structured_decision_with_reasons(tmp_path):
    journal = Journal(db_path=str(tmp_path / "t.db"))
    d = can(
        journal=journal,
        subject_did="did:plc:deadbeefdeadbeefdeadbeefdeadbeef",
        action="attest",
        target="x",
        domain="fr-chambery",
    )
    assert isinstance(d, Decision)
    assert isinstance(d.reasons, list)
    assert len(d.reasons) > 0, "Decision must always carry at least one reason"
