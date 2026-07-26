# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.console — console escalation pty, gated by a live
CONSOLE_GRANT (double-consent). Runs under the daemon's non-root user; refuses
to run as root. Every keystroke is audited (byte count, not raw content).
"""
from __future__ import annotations

import os
import pty
import signal
from typing import Optional

from . import audit

try:
    from annuaire import assist as _assist
except Exception:  # pragma: no cover
    _assist = None


class ConsoleDenied(Exception):
    """Console not granted, or refused (root)."""


def guard(entries, session_id: str, now_ts: str) -> None:
    if _assist is None or not _assist.console_active(entries, session_id, now_ts):
        raise ConsoleDenied("console not granted (double-consent required)")


class ConsoleSession:
    def __init__(self, audit_path: Optional[str] = None):
        self._pid = None
        self._fd = None
        self._audit_path = audit_path
        self._session_id: Optional[str] = None
        self._center: Optional[str] = None

    def open(self, session_id: str, center_did: str):
        if os.geteuid() == 0:
            raise ConsoleDenied("refuse-root")
        self._session_id = session_id
        self._center = center_did
        pid, fd = pty.fork()
        if pid == 0:  # child
            os.execv("/bin/bash", ["/bin/bash", "-i"])
        self._pid, self._fd = pid, fd
        audit.record("console.open", session_id, center_did, {"pid": pid},
                     path=self._audit_path)

    def write(self, data: bytes):
        audit.record("console.keystroke", self._session_id, self._center,
                     {"bytes": len(data)}, path=self._audit_path)
        os.write(self._fd, data)

    def read(self, n: int = 4096) -> bytes:
        return os.read(self._fd, n)

    def close(self):
        if self._pid:
            try:
                os.kill(self._pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            audit.record("console.close", self._session_id, self._center, {},
                         path=self._audit_path)
            self._pid = None
