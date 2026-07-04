# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Spool plumbing for PeerTube admin ops (#798)."""
import json
from pathlib import Path
from api import main as m


def test_spool_op_writes_request(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "OPS_DIR", tmp_path)
    op_id = m._spool_op("reset-password", password="s3cr3t")
    assert len(op_id) >= 8 and all(c in "0123456789abcdef" for c in op_id)
    req = json.loads((tmp_path / f"{op_id}.request.json").read_text())
    assert req["op"] == "reset-password" and req["id"] == op_id and req["password"] == "s3cr3t"
    assert (tmp_path / f"{op_id}.request.json").stat().st_mode & 0o777 == 0o600


def test_read_op_result_pending_then_done(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "OPS_DIR", tmp_path)
    assert m._read_op_result("abc12345")["status"] == "pending"
    (tmp_path / "abc12345.result.json").write_text(json.dumps({"status": "done", "detail": "ok"}))
    r = m._read_op_result("abc12345")
    assert r["status"] == "done" and r["detail"] == "ok"


def test_read_op_result_rejects_bad_id(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "OPS_DIR", tmp_path)
    assert m._read_op_result("../etc/passwd")["status"] == "error"
