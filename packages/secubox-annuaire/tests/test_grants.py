# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from annuaire import grants
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
