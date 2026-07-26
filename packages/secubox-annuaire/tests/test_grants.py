# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from annuaire import grants
from annuaire.model import GENESIS_HASH, LogEntry, Op
A = "did:plc:" + ("a"*32); B = "did:plc:" + ("b"*32)

def _issue(gid, center, scope, layer):
    # author == issued_by: a GRANT_ISSUE is self-certifying (Journal.append sets
    # author from the signing key; model.py Grant requires entry.author == issued_by).
    return {"op": "grant_issue", "payload": {"grant_id": gid, "center_did": center,
            "capability": "config", "scope": scope, "layer": layer, "issued_by": B},
            "author": B}
def _revoke(gid):
    return {"op": "grant_revoke", "payload": {"grant_id": gid, "issued_by": B}}

def test_active_grant_and_owner():
    e = [_issue("g1", A, "firewall", "baseline")]
    assert grants.owner(e, "firewall", "baseline") == A
    assert grants.can_push(e, A, "firewall", "baseline") is True
    assert grants.can_push(e, A, "firewall", "override") is False

def test_revoke_drops_owner():
    e = [_issue("g1", A, "firewall", "baseline"), _revoke("g1")]
    assert grants.owner(e, "firewall", "baseline") is None
    assert grants.can_push(e, A, "firewall", "baseline") is False

def test_validate_issue_rejects_local_and_secrets_and_dup():
    assert grants.validate_issue([], "firewall", "local") == "layer-local-not-delegatable"
    assert grants.validate_issue([], "auth", "baseline") == "scope-not-delegatable"
    e = [_issue("g1", A, "firewall", "baseline")]
    assert grants.validate_issue(e, "firewall", "baseline") == "already-owned"
    assert grants.validate_issue(e, "firewall", "override") is None

def test_zero_center_autonomous():
    assert grants.owner([], "firewall", "baseline") is None

def _log_entry(height, op, payload, author=B):
    """Build a real annuaire.log.LogEntry — attribute access, NOT subscriptable.

    Mirrors what annuaire.log.Journal.iter_entries() actually yields. If
    grants.py regresses to entry["op"]/entry["payload"] this raises
    TypeError: 'LogEntry' object is not subscriptable.
    """
    return LogEntry(
        height=height,
        op=Op(op),
        prev_hash=GENESIS_HASH,
        payload_type="Grant",
        payload=payload,
        author=author,
        sig="deadbeef",
        entry_hash="a" * 64,
    )

def test_accepts_real_logentry_objects_attribute_access():
    """Guard: grants.py must tolerate LogEntry (attribute) as well as dict (subscript).

    list(journal.iter_entries()) is the standard call pattern from T6/T7
    integration call sites — entries are LogEntry objects, not dicts.
    """
    e = [
        _log_entry(0, "grant_issue", {"grant_id": "g1", "center_did": A,
                    "capability": "config", "scope": "firewall",
                    "layer": "baseline", "issued_by": B}),
    ]
    assert grants.owner(e, "firewall", "baseline") == A
    assert grants.can_push(e, A, "firewall", "baseline") is True
    assert grants.can_push(e, A, "firewall", "override") is False
    assert grants.validate_issue(e, "firewall", "baseline") == "already-owned"

    e.append(_log_entry(1, "grant_revoke", {"grant_id": "g1", "issued_by": B}))
    assert grants.owner(e, "firewall", "baseline") is None
    assert grants.can_push(e, A, "firewall", "baseline") is False

def test_accepts_mixed_dict_and_logentry_entries():
    """Both entry shapes must be usable in the same list without error."""
    e = [
        _issue("g1", A, "firewall", "baseline"),
        _log_entry(1, "grant_revoke", {"grant_id": "g1", "issued_by": B}),
    ]
    assert grants.owner(e, "firewall", "baseline") is None


# ---------------------------------------------------------------------------
# Sovereignty filter (self_did) — a grant is only real delegated authority
# when THIS box issued it. Grant ops federate (dir_sync), so a mesh peer's
# self-issued grant for its own center must never be honored as local
# authority. See grants.active_grants()'s sovereignty-filter docstring.
# ---------------------------------------------------------------------------

BOX = "did:plc:" + "0" * 32   # this box's own sovereign did
PAIR = "did:plc:" + "9" * 32  # a mesh peer's did — NOT this box


def test_owner_filters_by_self_did_ignores_foreign_grant():
    e = [_issue("g1", A, "firewall", "baseline")]  # issued_by=B (test fixture's default)
    # No self_did (compat, low-level tests): unfiltered, as before.
    assert grants.owner(e, "firewall", "baseline") == A
    # self_did given but grant issued_by B != self_did -> not honored.
    assert grants.owner(e, "firewall", "baseline", self_did=BOX) is None
    assert grants.can_push(e, A, "firewall", "baseline", self_did=BOX) is False
    # Only honored when self_did matches the grant's issued_by.
    assert grants.owner(e, "firewall", "baseline", self_did=B) == A
    assert grants.can_push(e, A, "firewall", "baseline", self_did=B) is True


def test_validate_issue_already_owned_is_scoped_to_self_did():
    """A foreign (peer-issued) grant on (scope, layer) must not block this
    box's own GRANT_ISSUE for that same (scope, layer) — but this box's OWN
    prior grant still does."""
    foreign = {"op": "grant_issue", "payload": {
        "grant_id": "g1", "center_did": A, "capability": "config",
        "scope": "firewall", "layer": "baseline", "issued_by": PAIR,
    }, "author": PAIR}  # self-certifying: peer authored its own grant
    assert grants.validate_issue([foreign], "firewall", "baseline", self_did=BOX) is None

    own = {"op": "grant_issue", "payload": {
        "grant_id": "g2", "center_did": A, "capability": "config",
        "scope": "firewall", "layer": "baseline", "issued_by": BOX,
    }, "author": BOX}  # self-certifying: this box authored its own grant
    assert grants.validate_issue(
        [foreign, own], "firewall", "baseline", self_did=BOX
    ) == "already-owned"


# ---------------------------------------------------------------------------
# Verified-author binding (fail-closed): a GRANT_ISSUE is self-certifying —
# entry.author == issued_by (model.py Grant). A mesh peer can validly SIGN a
# GRANT_ISSUE (author=ATTACKER) whose payload LIES "issued_by=VICTIM"; on
# import it is well-formed and correctly signed. active_grants must bind the
# VERIFIED author, never the payload's claimed issued_by. See the fail-closed
# author check in grants.active_grants().
# ---------------------------------------------------------------------------

def test_forged_grant_issue_author_mismatch_not_honored():
    from annuaire import releases
    ATTACKER = "did:plc:" + "a" * 32
    VICTIM = "did:plc:" + "5" * 32
    # ATTACKER signs a GRANT_ISSUE granting itself capability=release, but the
    # payload falsely claims VICTIM issued it. author != issued_by -> forged.
    forged = {"op": "grant_issue", "payload": {
        "grant_id": "gforge", "center_did": ATTACKER, "capability": "release",
        "scope": "release", "layer": "baseline", "issued_by": VICTIM,
    }, "author": ATTACKER}
    # VICTIM (self_did) never signed this — it must not appear in its grants.
    assert grants.active_grants([forged], self_did=VICTIM) == {}
    assert grants.owner([forged], "release", "baseline", self_did=VICTIM) is None
    # And the release-grant resolver must reject the forgery too.
    assert releases.has_release_grant([forged], ATTACKER, VICTIM) is False
