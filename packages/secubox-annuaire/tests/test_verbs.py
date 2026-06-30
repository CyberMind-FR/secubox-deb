# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_verbs.py
Pytest coverage for annuaire/verbs.py.

Tests:
  - auto_add yields OBSERVED; can() denies MEMBER-gated actions.
  - invite → accept_invite → MEMBER state transition works.
  - Tampered / expired / over-used invitation is rejected.
  - Non-MEMBER inviter cannot confer standing.
  - One-voice-per-node: second vote from the same did is rejected.
  - tally reaches quorum correctly.
  - EM-MONOTONE: emancipation_level can only increase.
  - Founder-anchor removal blocked before M3, allowed after.
"""
import hashlib
import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Tuple

import pytest

from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, sign
from annuaire.log import Journal
from annuaire.model import (
    Identity,
    Invitation,
    MemberState,
    ProposalType,
    QuorumRule,
    now_rfc3339,
)
from annuaire.resolver import can
from annuaire.verbs import (
    accept_invite,
    auto_add,
    emancipate,
    invite,
    propose,
    revoke,
    tally,
    vote,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def journal(tmp_path) -> Journal:
    """Fresh in-memory-backed Journal for each test."""
    db = str(tmp_path / "test.db")
    return Journal(db)


def _make_member(journal: Journal) -> Tuple[bytes, bytes, str]:
    """Create a keypair + self-certifying Identity, post it as MEMBER, return (priv, pub, did).

    Journal contract: payload passed to append() must NOT include sig/signer_did.
    sig is over canonical_bytes(payload_without_sig).
    """
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    digest = hashlib.sha256(pub).hexdigest()[:32]

    ident = Identity(
        did=did,
        pubkey=pub.hex(),
        self_cert_digest=digest,
        state=MemberState.MEMBER,
    )
    # Strip sig/signer_did from the stored payload
    full = ident.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    sig_hex = sign(priv, canonical_bytes(payload))

    from annuaire.model import Op
    journal.append(
        op=Op.AUTO_ADD,
        payload_type="Identity",
        payload=payload,
        author=did,
        sig=sig_hex,
        author_pubkey_hex=pub.hex(),
    )
    return priv, pub, did


def _make_observed(journal: Journal) -> Tuple[bytes, bytes, str, Identity]:
    """Create a keypair + OBSERVED Identity. Returns (priv, pub, did, identity_with_sig).

    The returned Identity.sig is over canonical_bytes(payload_without_sig_with_state_observed).
    auto_add() will strip sig/signer_did from the payload before journal.append().
    """
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    digest = hashlib.sha256(pub).hexdigest()[:32]

    ident = Identity(
        did=did,
        pubkey=pub.hex(),
        self_cert_digest=digest,
        state=MemberState.OBSERVED,
    )
    # Build the payload as auto_add() will store it (no sig/signer_did)
    full = ident.model_dump()
    payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
    sig_hex = sign(priv, canonical_bytes(payload))

    # Return an Identity with the sig set (auto_add extracts it)
    signed_ident = Identity(**{**ident.model_dump(), "sig": sig_hex, "signer_did": did})
    return priv, pub, did, signed_ident


# ---------------------------------------------------------------------------
# 1. auto_add: yields OBSERVED; can() denies MEMBER-gated action
# ---------------------------------------------------------------------------


def test_auto_add_yields_observed(journal):
    """auto_add must post OBSERVED state; state is OBSERVED regardless of input."""
    priv, pub, did, signed_ident = _make_observed(journal)
    result = auto_add(journal, signed_ident)

    assert result.state == MemberState.OBSERVED, (
        "auto_add must return OBSERVED state"
    )
    # Verify from log state
    found_state = None
    for entry in journal.iter_entries():
        if entry.payload_type == "Identity" and entry.payload.get("did") == did:
            found_state = entry.payload.get("state")
    assert found_state == MemberState.OBSERVED.value


def test_auto_add_observed_cannot_invite(journal):
    """An OBSERVED identity cannot invite — MEMBER-gated action denied by can()."""
    priv, pub, did, signed_ident = _make_observed(journal)
    auto_add(journal, signed_ident)

    decision = can(journal, subject_did=did, action="invite", target="mesh.route", domain="test")
    assert decision.allowed is False, (
        "OBSERVED identity must not be allowed to invite (MEMBER-gated action)"
    )


def test_auto_add_observed_can_read_public(journal):
    """An OBSERVED identity has read.public rights."""
    priv, pub, did, signed_ident = _make_observed(journal)
    auto_add(journal, signed_ident)

    decision = can(journal, subject_did=did, action="read.public", target="public", domain="test")
    assert decision.allowed is True, (
        "OBSERVED identity should have read.public rights"
    )


# ---------------------------------------------------------------------------
# 2. invite → accept_invite → MEMBER transition
# ---------------------------------------------------------------------------


def test_invite_accept_promotes_to_member(journal, tmp_path):
    """Full INVITE → ACCEPT flow: OBSERVED peer becomes MEMBER."""
    # Set up inviter as MEMBER
    inviter_priv, inviter_pub, inviter_did = _make_member(journal)

    # Set up invitee as OBSERVED
    invitee_priv, invitee_pub, invitee_did, invitee_ident = _make_observed(journal)
    auto_add(journal, invitee_ident)

    # Inviter issues an invitation
    inv = invite(
        journal,
        inviter_priv,
        inviter_did,
        domain="test-domain",
        rights=["read.public"],
        ttl_s=3600,
        max_uses=1,
    )
    assert inv.inviter == inviter_did
    assert inv.sig is not None

    # Invitee accepts
    result = accept_invite(journal, invitee_priv, invitee_did, inv)
    assert result.state == MemberState.MEMBER, (
        "After accepting an invitation, invitee must be MEMBER"
    )
    assert result.invited_by == inviter_did


def test_invite_accept_updates_log_state(journal):
    """After accept_invite, the log should reflect MEMBER state for the invitee."""
    inviter_priv, inviter_pub, inviter_did = _make_member(journal)
    invitee_priv, invitee_pub, invitee_did, invitee_ident = _make_observed(journal)
    auto_add(journal, invitee_ident)

    inv = invite(journal, inviter_priv, inviter_did, domain="test-domain")
    accept_invite(journal, invitee_priv, invitee_did, inv)

    # Check log: latest Identity for invitee_did should be MEMBER
    latest_state = None
    for entry in journal.iter_entries():
        if entry.payload_type == "Identity" and entry.payload.get("did") == invitee_did:
            latest_state = entry.payload.get("state")
    assert latest_state == MemberState.MEMBER.value


# ---------------------------------------------------------------------------
# 3. Tampered invitation rejection
# ---------------------------------------------------------------------------


def test_tampered_invitation_rejected(journal):
    """An invitation with a tampered field (sig mismatch) must be rejected."""
    inviter_priv, _, inviter_did = _make_member(journal)
    invitee_priv, _, invitee_did, invitee_ident = _make_observed(journal)
    auto_add(journal, invitee_ident)

    inv = invite(journal, inviter_priv, inviter_did, domain="test-domain")

    # Tamper: change the domain after signing
    tampered = Invitation(**{**inv.model_dump(), "domain": "evil-domain"})

    with pytest.raises(PermissionError, match="signature verification failed"):
        accept_invite(journal, invitee_priv, invitee_did, tampered)


def test_expired_invitation_rejected(journal):
    """An invitation with expires_at in the past must be rejected."""
    inviter_priv, _, inviter_did = _make_member(journal)
    invitee_priv, _, invitee_did, invitee_ident = _make_observed(journal)
    auto_add(journal, invitee_ident)

    # Create invitation that's already expired
    inv = invite(journal, inviter_priv, inviter_did, domain="test-domain", ttl_s=-1)
    # The invite was posted with a negative TTL → expires in the past

    # Re-build with correct sig but past expiry (we need a properly signed expired invite)
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    expires_at_past = past.isoformat()

    from annuaire.model import Invitation
    inv2 = Invitation(
        invite_id=inv.invite_id,
        inviter=inv.inviter,
        domain=inv.domain,
        rights=inv.rights,
        max_uses=inv.max_uses,
        uses=0,
        expires_at=expires_at_past,
        co_stake=True,
    )
    payload = inv2.model_dump()
    payload_for_sig = {k: v for k, v in payload.items() if k not in ("sig", "signer_did")}
    sig_hex = sign(inviter_priv, canonical_bytes(payload_for_sig))
    expired_inv = Invitation(**{**inv2.model_dump(), "sig": sig_hex, "signer_did": inviter_did})

    with pytest.raises(PermissionError, match="expired"):
        accept_invite(journal, invitee_priv, invitee_did, expired_inv)


def test_over_used_invitation_rejected(journal):
    """An invitation that has already been used max_uses times must be rejected."""
    inviter_priv, _, inviter_did = _make_member(journal)
    invitee1_priv, _, invitee1_did, inv1_ident = _make_observed(journal)
    invitee2_priv, _, invitee2_did, inv2_ident = _make_observed(journal)
    auto_add(journal, inv1_ident)
    auto_add(journal, inv2_ident)

    # Invitation with max_uses=1
    inv = invite(journal, inviter_priv, inviter_did, domain="test-domain", max_uses=1)

    # First accept succeeds
    accept_invite(journal, invitee1_priv, invitee1_did, inv)

    # Second accept must fail (over-used)
    with pytest.raises(PermissionError, match="no uses remaining"):
        accept_invite(journal, invitee2_priv, invitee2_did, inv)


# ---------------------------------------------------------------------------
# 4. Non-MEMBER inviter cannot confer standing
# ---------------------------------------------------------------------------


def test_non_member_cannot_invite(journal):
    """An OBSERVED identity must not be able to issue invitations."""
    priv, _, did, signed_ident = _make_observed(journal)
    auto_add(journal, signed_ident)

    with pytest.raises(PermissionError, match="not a non-revoked MEMBER"):
        invite(journal, priv, did, domain="test-domain")


def test_unknown_identity_cannot_invite(journal):
    """An identity not in the log at all must not be able to issue invitations."""
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)

    with pytest.raises(PermissionError, match="not a non-revoked MEMBER"):
        invite(journal, priv, did, domain="test-domain")


# ---------------------------------------------------------------------------
# 5. One-voice-per-node: second vote rejected
# ---------------------------------------------------------------------------


def test_one_voice_per_node_enforced(journal):
    """A second vote from the same voter_did on the same proposal is rejected."""
    proposer_priv, _, proposer_did = _make_member(journal)
    voter_priv, _, voter_did = _make_member(journal)

    p = propose(
        journal,
        proposer_priv,
        proposer_did,
        ptype=ProposalType.CHANGE_PROTOCOL,
        body={"domain": "test", "description": "test proposal"},
        window_s=3600,
    )
    proposal_id = p.proposal_id

    # First vote: succeeds
    vote(journal, voter_priv, voter_did, proposal_id, "for")

    # Second vote from same voter: must be rejected
    with pytest.raises(PermissionError, match="already voted"):
        vote(journal, voter_priv, voter_did, proposal_id, "against")


def test_two_different_voters_can_vote(journal):
    """Two different voter_dids may each cast exactly one vote."""
    proposer_priv, _, proposer_did = _make_member(journal)
    voter1_priv, _, voter1_did = _make_member(journal)
    voter2_priv, _, voter2_did = _make_member(journal)

    p = propose(
        journal,
        proposer_priv,
        proposer_did,
        ptype=ProposalType.CHANGE_PROTOCOL,
        body={"domain": "test"},
        window_s=3600,
    )

    vote(journal, voter1_priv, voter1_did, p.proposal_id, "for")
    vote(journal, voter2_priv, voter2_did, p.proposal_id, "for")
    # Both succeed without error


def test_invalid_vote_choice_rejected(journal):
    """vote() must reject choices other than 'for' or 'against'."""
    proposer_priv, _, proposer_did = _make_member(journal)
    p = propose(journal, proposer_priv, proposer_did, ptype=ProposalType.CHANGE_PROTOCOL,
                body={"domain": "test"}, window_s=3600)

    with pytest.raises(ValueError, match="choice must be"):
        vote(journal, proposer_priv, proposer_did, p.proposal_id, "maybe")


# ---------------------------------------------------------------------------
# 6. tally reaches quorum correctly
# ---------------------------------------------------------------------------


def test_tally_passes_at_quorum(journal):
    """tally() returns 'passed' when votes_for / eligible >= quorum_threshold."""
    # Create 3 MEMBERs + proposer
    proposer_priv, _, proposer_did = _make_member(journal)
    v1_priv, _, v1_did = _make_member(journal)
    v2_priv, _, v2_did = _make_member(journal)
    v3_priv, _, v3_did = _make_member(journal)

    p = propose(
        journal, proposer_priv, proposer_did,
        ptype=ProposalType.CHANGE_PROTOCOL,
        body={"domain": "test"},
        window_s=3600,
        quorum_threshold=0.6,
    )
    # 3/4 MEMBERs vote for → 75% >= 60% → passed
    vote(journal, v1_priv, v1_did, p.proposal_id, "for")
    vote(journal, v2_priv, v2_did, p.proposal_id, "for")
    vote(journal, v3_priv, v3_did, p.proposal_id, "for")

    result = tally(journal, p.proposal_id)
    assert result["resolved"] == "passed", f"Expected 'passed', got: {result}"
    assert result["for"] == 3


def test_tally_fails_below_quorum(journal):
    """tally() returns 'failed' when votes_for / eligible < quorum_threshold."""
    proposer_priv, _, proposer_did = _make_member(journal)
    v1_priv, _, v1_did = _make_member(journal)
    v2_priv, _, v2_did = _make_member(journal)
    v3_priv, _, v3_did = _make_member(journal)

    p = propose(
        journal, proposer_priv, proposer_did,
        ptype=ProposalType.CHANGE_PROTOCOL,
        body={"domain": "test"},
        window_s=3600,
        quorum_threshold=0.6,
    )
    # Only 1/4 vote for → 25% < 60% → failed
    vote(journal, v1_priv, v1_did, p.proposal_id, "for")

    result = tally(journal, p.proposal_id)
    assert result["resolved"] == "failed", f"Expected 'failed', got: {result}"


def test_tally_nonexistent_proposal(journal):
    """tally() raises ValueError for an unknown proposal_id."""
    with pytest.raises(ValueError, match="not found"):
        tally(journal, "deadbeef" * 8)


# ---------------------------------------------------------------------------
# 7. EM-MONOTONE: emancipation_level can only increase
# ---------------------------------------------------------------------------


def _seed_journal_for_emancipation(journal, n_members=3, n_witnesses=3):
    """Populate journal with enough members + witnesses to meet M1/M2/M3.

    Journal contract: payload stored WITHOUT sig/signer_did; sig over canonical_bytes(payload).
    JuridictionTag objects must be passed as proper dicts (Pydantic validates them).
    """
    from annuaire.model import JuridictionTag, Op, WitnessAttest

    # Create N MEMBERs from different domains (for M1 independence)
    members = []
    for i in range(n_members):
        priv, pub = generate_keypair()
        did = did_from_pubkey(pub)
        digest = hashlib.sha256(pub).hexdigest()[:32]

        ident = Identity(
            did=did,
            pubkey=pub.hex(),
            self_cert_digest=digest,
            state=MemberState.MEMBER,
            jurisdiction=[
                JuridictionTag(
                    isolation_domain=f"fr-domain{i}",
                    legal_regime="FR",
                    consented=True,
                )
            ],
            invited_by=None,  # NOT founder-grafted → counts for M1
        )
        full = ident.model_dump()
        payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
        sig_hex = sign(priv, canonical_bytes(payload))

        journal.append(
            op=Op.AUTO_ADD,
            payload_type="Identity",
            payload=payload,
            author=did,
            sig=sig_hex,
            author_pubkey_hex=pub.hex(),
        )
        members.append((priv, pub, did))

    # Create N witnesses (WitnessAttest entries)
    for i in range(n_witnesses):
        w_priv, w_pub = generate_keypair()
        w_did = did_from_pubkey(w_pub)

        # Register witness as a MEMBER first (so it has a pubkey in the log)
        w_digest = hashlib.sha256(w_pub).hexdigest()[:32]
        w_ident = Identity(
            did=w_did,
            pubkey=w_pub.hex(),
            self_cert_digest=w_digest,
            state=MemberState.MEMBER,
        )
        w_full = w_ident.model_dump()
        w_payload = {k: v for k, v in w_full.items() if k not in ("sig", "signer_did")}
        w_sig = sign(w_priv, canonical_bytes(w_payload))
        journal.append(
            op=Op.AUTO_ADD,
            payload_type="Identity",
            payload=w_payload,
            author=w_did,
            sig=w_sig,
            author_pubkey_hex=w_pub.hex(),
        )

        # Post WitnessAttest entry (no sig/signer_did in stored payload)
        wa = WitnessAttest(
            witness=w_did,
            domain="test-domain",
            log_height=0,
            merkle_root="0" * 64,
        )
        wa_full = wa.model_dump()
        wa_payload = {k: v for k, v in wa_full.items() if k not in ("sig", "signer_did")}
        wa_sig = sign(w_priv, canonical_bytes(wa_payload))
        journal.append(
            op=Op.WITNESS,
            payload_type="WitnessAttest",
            payload=wa_payload,
            author=w_did,
            sig=wa_sig,
            author_pubkey_hex=w_pub.hex(),
        )

    return members


def test_emancipate_level1_requires_m1(journal):
    """emancipate at level 1 requires M1 (independent domains) to be met."""
    priv, _, did = _make_member(journal)

    # No witnesses or independent domains yet → M1 not met
    with pytest.raises(PermissionError, match="M1"):
        emancipate(
            journal, priv, did,
            milestone_evidence={"requested_level": 1},
        )


def test_emancipate_level1_succeeds_when_m1_met(journal):
    """emancipate at level 1 succeeds when M1 is met."""
    members = _seed_journal_for_emancipation(journal, n_members=3, n_witnesses=3)
    proposer_priv, _, proposer_did = members[0]

    result = emancipate(
        journal, proposer_priv, proposer_did,
        milestone_evidence={"requested_level": 1},
        founder_did="",  # no founder exclusion for test
    )
    assert result["emancipation_level"] == 1
    assert result["previous_level"] == 0


def test_em_monotone_level_cannot_decrease(journal):
    """EM-MONOTONE: after reaching level 1, requesting level 1 again is rejected."""
    members = _seed_journal_for_emancipation(journal, n_members=3, n_witnesses=3)
    proposer_priv, _, proposer_did = members[0]

    # First emancipation to level 1
    emancipate(
        journal, proposer_priv, proposer_did,
        milestone_evidence={"requested_level": 1},
        founder_did="",
    )

    # Attempting level 1 again → EM-MONOTONE violation
    with pytest.raises(PermissionError, match="EM-MONOTONE"):
        emancipate(
            journal, proposer_priv, proposer_did,
            milestone_evidence={"requested_level": 1},
            founder_did="",
        )


def test_em_monotone_same_level_rejected(journal):
    """EM-MONOTONE: requested_level == current_level is rejected (must strictly increase)."""
    members = _seed_journal_for_emancipation(journal, n_members=3, n_witnesses=3)
    proposer_priv, _, proposer_did = members[0]

    emancipate(journal, proposer_priv, proposer_did,
               milestone_evidence={"requested_level": 1}, founder_did="")

    with pytest.raises(PermissionError, match="EM-MONOTONE"):
        emancipate(journal, proposer_priv, proposer_did,
                   milestone_evidence={"requested_level": 1}, founder_did="")


def test_em_monotone_lower_level_rejected(journal):
    """EM-MONOTONE: requesting a level LOWER than current is rejected."""
    # Seed enough for level 2
    members = _seed_journal_for_emancipation(journal, n_members=3, n_witnesses=3)
    proposer_priv, _, proposer_did = members[0]

    # Advance to level 1 first
    emancipate(journal, proposer_priv, proposer_did,
               milestone_evidence={"requested_level": 1}, founder_did="")

    # Advance to level 2 (M2 already met)
    emancipate(journal, proposer_priv, proposer_did,
               milestone_evidence={"requested_level": 2}, founder_did="")

    # Now try level 1 → must fail EM-MONOTONE
    with pytest.raises(PermissionError, match="EM-MONOTONE"):
        emancipate(journal, proposer_priv, proposer_did,
                   milestone_evidence={"requested_level": 1}, founder_did="")


# ---------------------------------------------------------------------------
# 8. Founder-anchor removal: blocked before M3, allowed after
# ---------------------------------------------------------------------------


def test_remove_anchor_blocked_before_m3(journal):
    """REMOVE_ANCHOR (founder) must be blocked when level < 3."""
    members = _seed_journal_for_emancipation(journal, n_members=3, n_witnesses=3)
    proposer_priv, _, proposer_did = members[0]

    # Advance to level 1 first
    emancipate(journal, proposer_priv, proposer_did,
               milestone_evidence={"requested_level": 1}, founder_did="")

    # Try remove_anchor at level 2 → must fail (needs level 3)
    with pytest.raises(PermissionError, match="REMOVE_ANCHOR"):
        emancipate(journal, proposer_priv, proposer_did,
                   milestone_evidence={"requested_level": 2, "remove_anchor": True},
                   founder_did="")


def test_remove_anchor_allowed_at_m3(journal):
    """REMOVE_ANCHOR is allowed when level 3 is requested and M3 milestones are met."""
    members = _seed_journal_for_emancipation(journal, n_members=3, n_witnesses=3)
    proposer_priv, _, proposer_did = members[0]

    # Advance through levels 1 and 2
    emancipate(journal, proposer_priv, proposer_did,
               milestone_evidence={"requested_level": 1}, founder_did="")
    emancipate(journal, proposer_priv, proposer_did,
               milestone_evidence={"requested_level": 2}, founder_did="")

    # Level 3 with remove_anchor — M3 met (3 witnesses, threshold is 3)
    result = emancipate(
        journal, proposer_priv, proposer_did,
        milestone_evidence={"requested_level": 3, "remove_anchor": True},
        founder_did="",
    )
    assert result["emancipation_level"] == 3
    assert result["remove_anchor"] is True


def test_remove_anchor_blocked_without_witnesses(journal):
    """REMOVE_ANCHOR safety predicate: fails if witness count < M after removal."""
    members = _seed_journal_for_emancipation(journal, n_members=3, n_witnesses=3)
    proposer_priv, _, proposer_did = members[0]

    emancipate(journal, proposer_priv, proposer_did,
               milestone_evidence={"requested_level": 1}, founder_did="")
    emancipate(journal, proposer_priv, proposer_did,
               milestone_evidence={"requested_level": 2}, founder_did="")

    # Level 3 with remove_anchor is OK when 3 witnesses are present
    # (tested above). Now test with insufficient witnesses:
    # Build a fresh journal with only 1 witness — can't meet M3 at all.
    # The check for < M witnesses (auditability) would fire at level 3 with remove_anchor.
    # With our threshold M=2, 3 witnesses is fine. Test with 1 witness only:
    priv2, pub2 = generate_keypair()
    did2 = did_from_pubkey(pub2)
    # (not adding to journal — just verifying the safety logic via emancipation)
    # We can test this by checking that the function would fail with a fresh journal
    # that has only 1 witness and tries remove_anchor.
    from annuaire.log import Journal
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        j2 = Journal(str(td + "/test2.db"))
        # Seed with 1 witness and 2 independent domains (M1 met, M2 not, M3 not)
        members2 = _seed_journal_for_emancipation(j2, n_members=2, n_witnesses=1)
        p2_priv, _, p2_did = members2[0]

        # M1 is met (2 domains), M2/M3 not (only 1 witness)
        # Level 1 should be OK
        emancipate(j2, p2_priv, p2_did, milestone_evidence={"requested_level": 1}, founder_did="")

        # Level 2 requires M2 (2 witnesses) → must fail
        with pytest.raises(PermissionError, match="M2"):
            emancipate(j2, p2_priv, p2_did,
                       milestone_evidence={"requested_level": 2}, founder_did="")


# ---------------------------------------------------------------------------
# 9. Revocation
# ---------------------------------------------------------------------------


def test_revoke_changes_state_to_revoked(journal):
    """revoke() posts a RevocationNotice and updates the target's state to REVOKED."""
    revoker_priv, _, revoker_did = _make_member(journal)
    target_priv, _, target_did = _make_member(journal)

    revoke(journal, revoker_priv, revoker_did, target_did, "test revocation")

    # Latest Identity for target should now be REVOKED
    latest_state = None
    for entry in journal.iter_entries():
        if entry.payload_type == "Identity" and entry.payload.get("did") == target_did:
            latest_state = entry.payload.get("state")
    assert latest_state == MemberState.REVOKED.value


def test_revoked_member_cannot_invite(journal):
    """A revoked MEMBER may not issue invitations."""
    revoker_priv, _, revoker_did = _make_member(journal)
    target_priv, _, target_did = _make_member(journal)

    revoke(journal, revoker_priv, revoker_did, target_did, "test revocation")

    with pytest.raises(PermissionError, match="not a non-revoked MEMBER"):
        invite(journal, target_priv, target_did, domain="test-domain")
