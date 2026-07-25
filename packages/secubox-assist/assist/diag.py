# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: assist.diag — read-only diagnostic bundle with conservative
redaction. Never touches /etc/secubox/secrets or any *.key; secrets that slip
into logs are scrubbed by redact() before they leave the box.
"""
from __future__ import annotations

import re
import subprocess
from typing import Dict, List

from .catalog import MODULE_ALLOW

_SECRET_KV = re.compile(
    r"(?i)\b(token|secret|password|passwd|api[-_]?key|authorization|bearer)\b"
    r"\s*[:=]\s*[\"']?[^\s\"']+")
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{40,}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@([\w-]+\.[\w.-]+)\b")


def redact(text: str) -> str:
    text = _SECRET_KV.sub(lambda m: m.group(1) + "=***", text)
    text = _LONG_HEX.sub("***", text)
    text = _EMAIL.sub(r"***@\1", text)
    return text


def _run(argv: List[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception as exc:  # noqa: BLE001 — diag must never crash the session
        return f"<diag error: {exc}>"


def collect(now_ts: str) -> Dict:
    modules = []
    for unit in sorted(MODULE_ALLOW):
        active = _run(["systemctl", "is-active", unit]).strip()
        modules.append({"unit": unit, "active": active})
    logs = {}
    for unit in sorted(MODULE_ALLOW):
        logs[unit] = redact(_run(
            ["journalctl", "-u", unit, "-n", "50", "--no-pager"]))
    return {
        "generated_at": now_ts,
        "modules": modules,
        "logs": logs,
        "config_effective": {"note": "non-secret effective config summary"},
    }
