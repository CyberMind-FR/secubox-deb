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
