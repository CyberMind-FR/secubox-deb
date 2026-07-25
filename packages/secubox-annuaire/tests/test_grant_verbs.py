# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: tests/test_grant_verbs.py
Pytest coverage for annuaire/verbs.py::grant_issue / grant_revoke.

Tests:
  - grant_issue appends a GRANT_ISSUE entry and grants.owner() sees it.
  - grant_issue on a NON_DELEGATABLE scope ("auth") raises ValueError.
  - grant_issue on layer="local" raises ValueError.
  - A second grant_issue on the same (scope, layer) raises ValueError ("already-owned").
  - grant_revoke appends a GRANT_REVOKE entry and grants.owner() then returns None.
  - The appended entry's sig verifies against canonical_bytes(payload) with the
    box's pubkey — same signing idiom as invite()/propose().
"""
import pytest

from annuaire import grants
from annuaire.crypto import canonical_bytes, did_from_pubkey, generate_keypair, verify
from annuaire.log import Journal
from annuaire.model import Op
from annuaire.verbs import grant_issue, grant_revoke


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def journal(tmp_path) -> Journal:
    """Fresh in-memory-backed Journal for each test."""
    db = str(tmp_path / "test.db")
    return Journal(db)


@pytest.fixture()
def box(journal):
    """A box keypair (issuer of grants) — not a journal MEMBER, self-certifying only."""
    priv, pub = generate_keypair()
    did = did_from_pubkey(pub)
    return priv, pub, did


@pytest.fixture()
def center_did():
    """A center DID to receive grants (only the did:plc shape matters here)."""
    _, pub = generate_keypair()
    return did_from_pubkey(pub)


# ---------------------------------------------------------------------------
# grant_issue: happy path
# ---------------------------------------------------------------------------


def test_grant_issue_appends_and_owner_sees_it(journal, box, center_did):
    box_priv, box_pub, box_did = box

    result = grant_issue(journal, box_priv, box_did, center_did, "firewall", "baseline")

    assert result["center_did"] == center_did
    assert result["scope"] == "firewall"
    assert result["layer"] == "baseline"
    assert result["capability"] == "config"
    assert result["issued_by"] == box_did
    assert result["sig"]

    entries = list(journal.iter_entries())
    grant_entries = [e for e in entries if e.op == Op.GRANT_ISSUE]
    assert len(grant_entries) == 1

    assert grants.owner(entries, "firewall", "baseline") == center_did


def test_grant_issue_default_capability_is_config(journal, box, center_did):
    box_priv, box_pub, box_did = box
    result = grant_issue(journal, box_priv, box_did, center_did, "netdata", "override")
    assert result["capability"] == "config"


# ---------------------------------------------------------------------------
# grant_issue: rejections (validated BEFORE any journal write)
# ---------------------------------------------------------------------------


def test_grant_issue_non_delegatable_scope_rejected(journal, box, center_did):
    box_priv, box_pub, box_did = box

    with pytest.raises(ValueError, match="scope-not-delegatable"):
        grant_issue(journal, box_priv, box_did, center_did, "auth", "baseline")

    # Nothing was written to the journal on rejection.
    assert list(journal.iter_entries()) == []


def test_grant_issue_local_layer_rejected(journal, box, center_did):
    box_priv, box_pub, box_did = box

    with pytest.raises(ValueError, match="layer-local-not-delegatable"):
        grant_issue(journal, box_priv, box_did, center_did, "firewall", "local")

    assert list(journal.iter_entries()) == []


def test_grant_issue_second_grant_same_scope_layer_rejected(journal, box, center_did):
    box_priv, box_pub, box_did = box

    grant_issue(journal, box_priv, box_did, center_did, "firewall", "baseline")

    other_priv, other_pub = generate_keypair()
    other_center_did = did_from_pubkey(other_pub)

    with pytest.raises(ValueError, match="already-owned"):
        grant_issue(journal, box_priv, box_did, other_center_did, "firewall", "baseline")

    # Still only one GRANT_ISSUE entry — the rejected attempt wrote nothing.
    entries = list(journal.iter_entries())
    assert len([e for e in entries if e.op == Op.GRANT_ISSUE]) == 1
    assert grants.owner(entries, "firewall", "baseline") == center_did


# ---------------------------------------------------------------------------
# grant_revoke
# ---------------------------------------------------------------------------


def test_grant_revoke_clears_ownership(journal, box, center_did):
    box_priv, box_pub, box_did = box

    issued = grant_issue(journal, box_priv, box_did, center_did, "firewall", "baseline")
    assert grants.owner(list(journal.iter_entries()), "firewall", "baseline") == center_did

    result = grant_revoke(journal, box_priv, box_did, issued["grant_id"])

    assert result["grant_id"] == issued["grant_id"]
    assert result["issued_by"] == box_did
    assert result["sig"]

    entries = list(journal.iter_entries())
    revoke_entries = [e for e in entries if e.op == Op.GRANT_REVOKE]
    assert len(revoke_entries) == 1

    assert grants.owner(entries, "firewall", "baseline") is None


def test_grant_revoke_then_reissue_same_scope_layer_succeeds(journal, box, center_did):
    """A revoked (scope, layer) is free again — validate_issue no longer sees it."""
    box_priv, box_pub, box_did = box

    issued = grant_issue(journal, box_priv, box_did, center_did, "firewall", "baseline")
    grant_revoke(journal, box_priv, box_did, issued["grant_id"])

    new_center_priv, new_center_pub = generate_keypair()
    new_center_did = did_from_pubkey(new_center_pub)

    reissued = grant_issue(journal, box_priv, box_did, new_center_did, "firewall", "baseline")
    entries = list(journal.iter_entries())
    assert grants.owner(entries, "firewall", "baseline") == new_center_did
    assert reissued["center_did"] == new_center_did


# ---------------------------------------------------------------------------
# Signature integrity — same idiom as invite()/propose()
# ---------------------------------------------------------------------------


def test_grant_issue_entry_signature_verifies(journal, box, center_did):
    box_priv, box_pub, box_did = box

    grant_issue(journal, box_priv, box_did, center_did, "firewall", "baseline")

    entries = list(journal.iter_entries())
    entry = next(e for e in entries if e.op == Op.GRANT_ISSUE)

    assert verify(box_pub.hex(), canonical_bytes(entry.payload), entry.sig)


def test_grant_revoke_entry_signature_verifies(journal, box, center_did):
    box_priv, box_pub, box_did = box

    issued = grant_issue(journal, box_priv, box_did, center_did, "firewall", "baseline")
    grant_revoke(journal, box_priv, box_did, issued["grant_id"])

    entries = list(journal.iter_entries())
    entry = next(e for e in entries if e.op == Op.GRANT_REVOKE)

    assert verify(box_pub.hex(), canonical_bytes(entry.payload), entry.sig)
