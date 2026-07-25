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
    return {"op": "grant_issue", "payload": {"grant_id": gid, "center_did": center,
            "capability": "config", "scope": scope, "layer": layer, "issued_by": B}}
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
