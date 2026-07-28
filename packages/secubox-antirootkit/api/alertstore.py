# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit in-process alert store (v1)

A small, capped, module-level alert queue shared between the exec-watch
daemon (api/daemon.py — appends an alert whenever it jails an unknown
process) and the FastAPI GET /alerts endpoint (api/main.py — reads it).

This is intentionally NOT the durable record: api.execlog.ExecLog is the
append-only forensic log of every decision. This store only exists so
GET /alerts reflects real jail events instead of a hardcoded empty stub,
for the panel's live alert queue. It is not persisted across process
restarts.
"""

from __future__ import annotations

MAX_ALERTS = 500

_alerts: list[dict] = []


def append(alert: dict) -> None:
    """Append an alert. Caps the store at MAX_ALERTS, dropping the oldest
    entries first so it can never grow unbounded on a live box."""
    _alerts.append(dict(alert))
    overflow = len(_alerts) - MAX_ALERTS
    if overflow > 0:
        del _alerts[:overflow]


def recent(limit: int = 100) -> list[dict]:
    """Return up to `limit` alerts, most-recent-first."""
    return list(reversed(_alerts[-limit:])) if limit > 0 else []


def clear() -> None:
    """Reset the store. Used by tests to avoid cross-test pollution of
    this module-level singleton."""
    _alerts.clear()
