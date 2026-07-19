# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

from api.audit import record


def test_record_appends_one_json_line(tmp_path):
    log = tmp_path / "audit.log"
    record({"module": "lyrion", "action": "stop", "result": "ok"}, path=log)
    record({"module": "lyrion", "action": "start", "result": "ok"}, path=log)
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["module"] == "lyrion"
    assert json.loads(lines[1])["action"] == "start"


def test_record_never_raises_on_bad_dir(tmp_path):
    # best-effort: an unwritable path must not crash the caller (audit failure
    # is reported by the orchestrator, never fatal to the apply).
    record({"x": 1}, path=tmp_path / "nope" / "deep" / "audit.log")  # no raise
