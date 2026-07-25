# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from annuaire.model import Op
from annuaire import assist

BOX = "did:plc:" + "1" * 32
CENTER = "did:plc:" + "2" * 32
OTHER = "did:plc:" + "3" * 32


def e(op, **payload):
    return {"op": op.value if hasattr(op, "value") else op, "payload": payload}


def test_active_session_single_and_expiry():
    entries = [
        e(Op.ASSIST_SESSION_OPEN, session_id="s1", req_id="r1", center_did=CENTER,
          issued_by=BOX, token_hash="a" * 64, expires_ts="2026-07-25T12:00:00Z"),
    ]
    # before expiry
    s = assist.active_session(entries, BOX, now_ts="2026-07-25T11:00:00Z")
    assert s and s["session_id"] == "s1"
    # after expiry -> fail-closed None
    assert assist.active_session(entries, BOX, now_ts="2026-07-25T13:00:00Z") is None


def test_close_ends_session():
    entries = [
        e(Op.ASSIST_SESSION_OPEN, session_id="s1", req_id="r1", center_did=CENTER,
          issued_by=BOX, token_hash="a" * 64, expires_ts="2026-07-25T23:00:00Z"),
        e(Op.ASSIST_SESSION_CLOSE, session_id="s1", issued_by=BOX, reason="done"),
    ]
    assert assist.active_session(entries, BOX, now_ts="2026-07-25T12:00:00Z") is None


def test_sovereignty_ignores_foreign_session():
    # a session OPEN authored by someone else (federated) is NOT ours
    entries = [
        e(Op.ASSIST_SESSION_OPEN, session_id="sX", req_id="rX", center_did=CENTER,
          issued_by=OTHER, token_hash="a" * 64, expires_ts="2026-07-25T23:00:00Z"),
    ]
    assert assist.active_session(entries, BOX, now_ts="2026-07-25T12:00:00Z") is None


def test_console_active_and_revoke():
    entries = [
        e(Op.ASSIST_CONSOLE_GRANT, session_id="s1", issued_by=BOX,
          expires_ts="2026-07-25T13:00:00Z"),
    ]
    assert assist.console_active(entries, "s1", now_ts="2026-07-25T12:00:00Z")
    assert not assist.console_active(entries, "s1", now_ts="2026-07-25T14:00:00Z")
    entries.append(e(Op.ASSIST_CONSOLE_REVOKE, session_id="s1", issued_by=BOX))
    assert not assist.console_active(entries, "s1", now_ts="2026-07-25T12:30:00Z")


def test_multiple_active_sessions_raises():
    entries = [
        e(Op.ASSIST_SESSION_OPEN, session_id="s1", req_id="r1", center_did=CENTER,
          issued_by=BOX, token_hash="a" * 64, expires_ts="2026-07-25T23:00:00Z"),
        e(Op.ASSIST_SESSION_OPEN, session_id="s2", req_id="r2", center_did=CENTER,
          issued_by=BOX, token_hash="b" * 64, expires_ts="2026-07-25T23:00:00Z"),
    ]
    with pytest.raises(assist.AssistError):
        assist.active_session(entries, BOX, now_ts="2026-07-25T12:00:00Z")


def test_pending_requests_drops_foreign_per_incident():
    # a per-incident request authored by some OTHER did must never surface as
    # "pending" for this box — that would let a federated peer's request
    # masquerade as ours (sovereignty hole).
    entries = [
        e(Op.ASSIST_REQUEST, req_id="r-foreign", center_did=CENTER,
          mode="per-incident", scope="dns", issued_by=OTHER),
        e(Op.ASSIST_REQUEST, req_id="r-self", center_did=CENTER,
          mode="per-incident", scope="dns", issued_by=BOX),
        e(Op.ASSIST_REQUEST, req_id="r-standing", center_did=CENTER,
          mode="standing", scope="dns", issued_by=CENTER),
    ]
    out = {p["req_id"] for p in assist.pending_requests(entries, BOX)}
    assert out == {"r-self", "r-standing"}
    assert "r-foreign" not in out


def test_can_open_rejects_foreign_per_incident_request():
    # accepted, no active session — but issued_by is a foreign did and mode
    # is per-incident: must be refused, not silently opened.
    entries = [
        e(Op.ASSIST_REQUEST, req_id="r-foreign", center_did=CENTER,
          mode="per-incident", scope="dns", issued_by=OTHER),
        e(Op.ASSIST_ACCEPT, req_id="r-foreign", issued_by=CENTER),
    ]
    ok, reason = assist.can_open(entries, "r-foreign", BOX, now_ts="2026-07-25T12:00:00Z")
    assert (ok, reason) == (False, "not-authorized")


def test_can_open_allows_self_authored_accepted_request():
    entries = [
        e(Op.ASSIST_REQUEST, req_id="r-self", center_did=CENTER,
          mode="per-incident", scope="dns", issued_by=BOX),
        e(Op.ASSIST_ACCEPT, req_id="r-self", issued_by=CENTER),
    ]
    ok, reason = assist.can_open(entries, "r-self", BOX, now_ts="2026-07-25T12:00:00Z")
    assert (ok, reason) == (True, "ok")


# ---------------------------------------------------------------------------
# Standing mode REQUIRES an active capability="assist" Grant for the center
# (spec: per-incident's own box-authored request IS the authority; standing
# is NOT — it must be backed by a real, self-issued delegation).
# ---------------------------------------------------------------------------

def _grant_issue(gid, center_did, capability, scope, issued_by):
    return {"op": Op.GRANT_ISSUE.value, "payload": {
        "grant_id": gid, "center_did": center_did, "capability": capability,
        "scope": scope, "layer": "baseline", "issued_by": issued_by}}


def test_can_open_standing_without_grant_is_refused():
    entries = [
        e(Op.ASSIST_REQUEST, req_id="r-standing", center_did=CENTER,
          mode="standing", scope="dns", issued_by=CENTER),
        e(Op.ASSIST_ACCEPT, req_id="r-standing", issued_by=CENTER),
    ]
    ok, reason = assist.can_open(entries, "r-standing", BOX, now_ts="2026-07-25T12:00:00Z")
    assert (ok, reason) == (False, "no-standing-grant")


def test_can_open_standing_with_active_assist_grant_is_allowed():
    entries = [
        e(Op.ASSIST_REQUEST, req_id="r-standing", center_did=CENTER,
          mode="standing", scope="dns", issued_by=CENTER),
        e(Op.ASSIST_ACCEPT, req_id="r-standing", issued_by=CENTER),
        _grant_issue("g1", CENTER, "assist", "dns", BOX),
    ]
    ok, reason = assist.can_open(entries, "r-standing", BOX, now_ts="2026-07-25T12:00:00Z")
    assert (ok, reason) == (True, "ok")


def test_can_open_standing_ignores_non_assist_capability_grant():
    # A "config" capability grant for the same center must not satisfy the
    # standing assist-grant requirement — capability must be exactly "assist".
    entries = [
        e(Op.ASSIST_REQUEST, req_id="r-standing", center_did=CENTER,
          mode="standing", scope="dns", issued_by=CENTER),
        e(Op.ASSIST_ACCEPT, req_id="r-standing", issued_by=CENTER),
        _grant_issue("g1", CENTER, "config", "dns", BOX),
    ]
    ok, reason = assist.can_open(entries, "r-standing", BOX, now_ts="2026-07-25T12:00:00Z")
    assert (ok, reason) == (False, "no-standing-grant")


def test_can_open_standing_ignores_foreign_issued_grant():
    # A capability="assist" grant that THIS box never issued (e.g. a mesh
    # peer's federated grant naming itself) must not count — active_grants'
    # sovereignty filter already scopes this to issued_by == self_did.
    entries = [
        e(Op.ASSIST_REQUEST, req_id="r-standing", center_did=CENTER,
          mode="standing", scope="dns", issued_by=CENTER),
        e(Op.ASSIST_ACCEPT, req_id="r-standing", issued_by=CENTER),
        _grant_issue("g1", CENTER, "assist", "dns", OTHER),
    ]
    ok, reason = assist.can_open(entries, "r-standing", BOX, now_ts="2026-07-25T12:00:00Z")
    assert (ok, reason) == (False, "no-standing-grant")
