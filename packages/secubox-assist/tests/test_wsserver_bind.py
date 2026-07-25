# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from assist import wsserver, token


def test_mesh_bind_absent_iface_fails_closed():
    with pytest.raises(wsserver.BindError):
        wsserver.mesh_bind_ip("nonexistent-iface-xyz")


@pytest.mark.asyncio
async def test_authorize_matches_token_hash():
    tok, h = token.mint()
    entries = [{"op": "assist_session_open", "payload": {
        "session_id": "s1", "req_id": "r1", "center_did": "did:plc:" + "2"*32,
        "issued_by": "did:plc:" + "1"*32, "token_hash": h,
        "expires_ts": "2999-01-01T00:00:00Z"}}]
    self_did = "did:plc:" + "1"*32
    s = await wsserver.authorize(tok, entries, self_did, now_ts="2026-07-25T00:00:00Z")
    assert s["session_id"] == "s1"


@pytest.mark.asyncio
async def test_authorize_rejects_wrong_token():
    tok, h = token.mint()
    entries = [{"op": "assist_session_open", "payload": {
        "session_id": "s1", "req_id": "r1", "center_did": "did:plc:" + "2"*32,
        "issued_by": "did:plc:" + "1"*32, "token_hash": h,
        "expires_ts": "2999-01-01T00:00:00Z"}}]
    with pytest.raises(wsserver.AuthError):
        await wsserver.authorize("bogus", entries, "did:plc:" + "1"*32,
                                 now_ts="2026-07-25T00:00:00Z")


@pytest.mark.asyncio
async def test_authorize_rejects_multiple_active_sessions_as_autherror():
    tok1, h1 = token.mint()
    tok2, h2 = token.mint()
    self_did = "did:plc:" + "1"*32
    entries = [
        {"op": "assist_session_open", "payload": {
            "session_id": "s1", "req_id": "r1", "center_did": "did:plc:" + "2"*32,
            "issued_by": self_did, "token_hash": h1,
            "expires_ts": "2999-01-01T00:00:00Z"}},
        {"op": "assist_session_open", "payload": {
            "session_id": "s2", "req_id": "r2", "center_did": "did:plc:" + "3"*32,
            "issued_by": self_did, "token_hash": h2,
            "expires_ts": "2999-01-01T00:00:00Z"}},
    ]
    with pytest.raises(wsserver.AuthError):
        await wsserver.authorize(tok1, entries, self_did,
                                 now_ts="2026-07-25T00:00:00Z")
