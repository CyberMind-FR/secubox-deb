# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.audit — append-only, per-line JSON audit of every
assist event (request→accept→open→each action→console→keystrokes→close).
Never truncates; opens 'a' and fsyncs. CSPN immutability requirement.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

AUDIT_PATH = os.environ.get("SECUBOX_ASSIST_AUDIT", "/var/log/secubox/audit.log")


def record(event: str, session_id: str, actor: str, detail: dict,
           *, path: Optional[str] = None) -> None:
    line = json.dumps({
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "src": "secubox-assist",
        "event": event,
        "session_id": session_id,
        "actor": actor,
        "detail": detail,
    }, separators=(",", ":"), sort_keys=True)
    with open(path or AUDIT_PATH, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())
