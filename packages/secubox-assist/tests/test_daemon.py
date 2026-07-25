# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
assist.daemon — self_did resolution must never touch the sovereign PRIVATE
key (FINDING 1) and the mid-session recheck must bind to the SAME session
the socket authorized, not merely "a session is active" (FINDING 4).
"""
import importlib
import json

import pytest

from assist import daemon, token, audit

SELF = "did:plc:" + "1" * 32
CENTER = "did:plc:" + "2" * 32


# ---------------------------------------------------------------------------
# FINDING 1 — public-source self_did, never the private key, cached once
# ---------------------------------------------------------------------------

def test_resolve_self_did_prefers_env_var(monkeypatch):
    monkeypatch.setenv("SECUBOX_SELF_DID", SELF)
    assert daemon._resolve_self_did() == SELF


def test_resolve_self_did_reads_public_file_when_env_absent(tmp_path, monkeypatch):
    monkeypatch.delenv("SECUBOX_SELF_DID", raising=False)
    did_file = tmp_path / "node.did"
    did_file.write_text(SELF + "\n")
    monkeypatch.setenv("ANNUAIRE_DID_PATH", str(did_file))
    assert daemon._resolve_self_did() == SELF


def test_resolve_self_did_none_when_neither_present(tmp_path, monkeypatch):
    monkeypatch.delenv("SECUBOX_SELF_DID", raising=False)
    monkeypatch.setenv("ANNUAIRE_DID_PATH", str(tmp_path / "missing.did"))
    assert daemon._resolve_self_did() is None


def test_resolve_self_did_never_opens_the_private_key(tmp_path, monkeypatch):
    """Even when a (garbage) private key file is reachable, resolution must
    fall through to None rather than ever opening ANNUAIRE_KEY_PATH — a
    network-facing daemon must never hold/read the sovereign private key."""
    key_path = tmp_path / "node.key"
    key_path.write_text("not-a-valid-hex-key-and-must-never-be-read")
    monkeypatch.setenv("ANNUAIRE_KEY_PATH", str(key_path))
    monkeypatch.delenv("SECUBOX_SELF_DID", raising=False)
    monkeypatch.setenv("ANNUAIRE_DID_PATH", str(tmp_path / "missing.did"))
    # Would raise (bytes.fromhex on garbage) if the private key were ever
    # touched by resolution; instead it must cleanly fall back to None.
    assert daemon._resolve_self_did() is None


def test_self_did_cached_at_module_load_not_per_connection(monkeypatch):
    monkeypatch.setenv("SECUBOX_SELF_DID", "did:plc:" + "c" * 32)
    importlib.reload(daemon)
    assert daemon.SELF_DID == "did:plc:" + "c" * 32
    # Mutating the env AFTER load must NOT change the cached module value —
    # it is read once at import, never per-connection.
    monkeypatch.setenv("SECUBOX_SELF_DID", "did:plc:" + "d" * 32)
    assert daemon.SELF_DID == "did:plc:" + "c" * 32
    # restore a clean module state for subsequent tests in this process
    monkeypatch.delenv("SECUBOX_SELF_DID", raising=False)
    importlib.reload(daemon)


# ---------------------------------------------------------------------------
# FINDING 4 — mid-session recheck must bind to the SAME session_id
# ---------------------------------------------------------------------------

class FakeWS:
    """Minimal async websocket stand-in: one recv() for the token, then an
    async-iterable stream of already-queued JSON action messages."""

    def __init__(self, tok, messages):
        self._tok = tok
        self._messages = list(messages)
        self.sent = []

    async def recv(self):
        return self._tok

    async def send(self, msg):
        self.sent.append(json.loads(msg))

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._messages:
            raise StopAsyncIteration
        return self._messages.pop(0)


@pytest.mark.asyncio
async def test_recheck_rejects_when_operator_reopened_a_new_session(monkeypatch, tmp_path):
    """s1 authorizes the socket; the operator then closes s1 and opens s2
    (still "a session is active" — but NOT the one this socket authorized).
    The socket must be cut off with session-ended, not silently ride s2."""
    monkeypatch.setattr(daemon, "SELF_DID", SELF)
    monkeypatch.setattr(audit, "AUDIT_PATH", str(tmp_path / "audit.log"))
    tok, h = token.mint()

    entries_at_connect = [{"op": "assist_session_open", "payload": {
        "session_id": "s1", "req_id": "r1", "center_did": CENTER,
        "issued_by": SELF, "token_hash": h,
        "expires_ts": "2999-01-01T00:00:00Z"}}]

    entries_after_reopen = [
        {"op": "assist_session_open", "payload": {
            "session_id": "s1", "req_id": "r1", "center_did": CENTER,
            "issued_by": SELF, "token_hash": h,
            "expires_ts": "2999-01-01T00:00:00Z"}},
        {"op": "assist_session_close", "payload": {
            "session_id": "s1", "issued_by": SELF, "reason": "done"}},
        {"op": "assist_session_open", "payload": {
            "session_id": "s2", "req_id": "r2", "center_did": CENTER,
            "issued_by": SELF, "token_hash": "b" * 64,
            "expires_ts": "2999-01-01T00:00:00Z"}},
    ]

    calls = {"n": 0}

    def fake_read_entries():
        calls["n"] += 1
        return entries_at_connect if calls["n"] == 1 else entries_after_reopen

    monkeypatch.setattr(daemon, "_read_entries", fake_read_entries)

    ws = FakeWS(tok, [json.dumps({"action": "diag.collect"})])
    await daemon.handler(ws)

    assert ws.sent[0]["ok"] is True and ws.sent[0]["session_id"] == "s1"
    assert ws.sent[-1] == {"ok": False, "error": "session-ended"}


@pytest.mark.asyncio
async def test_recheck_allows_the_same_session_to_keep_running(monkeypatch, tmp_path):
    monkeypatch.setattr(daemon, "SELF_DID", SELF)
    monkeypatch.setattr(audit, "AUDIT_PATH", str(tmp_path / "audit.log"))
    tok, h = token.mint()

    entries = [{"op": "assist_session_open", "payload": {
        "session_id": "s1", "req_id": "r1", "center_did": CENTER,
        "issued_by": SELF, "token_hash": h,
        "expires_ts": "2999-01-01T00:00:00Z"}}]

    monkeypatch.setattr(daemon, "_read_entries", lambda: entries)

    ws = FakeWS(tok, [json.dumps({"action": "diag.collect"})])
    await daemon.handler(ws)

    assert ws.sent[0]["ok"] is True and ws.sent[0]["session_id"] == "s1"
    assert ws.sent[-1]["ok"] is True
    assert "output" in ws.sent[-1]
