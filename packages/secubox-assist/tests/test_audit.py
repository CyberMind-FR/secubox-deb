# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
from assist import audit


def test_append_only_and_json_lines(tmp_path):
    p = tmp_path / "audit.log"
    audit.record("session.open", "s1", "did:box", {"req_id": "r1"}, path=str(p))
    audit.record("console.keystroke", "s1", "did:center", {"bytes": 3}, path=str(p))
    lines = p.read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["event"] == "session.open" and first["session_id"] == "s1"
    assert "ts" in first
    # second append does not truncate the first
    assert json.loads(lines[1])["event"] == "console.keystroke"
