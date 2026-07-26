# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os
import pytest
from assist import console


def test_guard_denies_without_console_grant():
    entries = []  # no CONSOLE_GRANT
    with pytest.raises(console.ConsoleDenied):
        console.guard(entries, "s1", now_ts="2026-07-25T12:00:00Z")


def test_guard_allows_with_grant():
    entries = [{"op": "assist_console_grant", "author": "did:plc:" + "1"*32, "payload": {
        "session_id": "s1", "issued_by": "did:plc:" + "1"*32,
        "expires_ts": "2999-01-01T00:00:00Z"}}]
    console.guard(entries, "s1", now_ts="2026-07-25T12:00:00Z")  # no raise


@pytest.mark.skipif(os.geteuid() == 0, reason="test asserts non-root refusal path only off-root")
def test_console_refuses_root(monkeypatch):
    monkeypatch.setattr(console.os, "geteuid", lambda: 0)
    cs = console.ConsoleSession(audit_path="/dev/null")
    with pytest.raises(console.ConsoleDenied):
        cs.open("s1", "did:center")
