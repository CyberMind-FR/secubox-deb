# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: health-doctor runner (issue #212).

Runs all registered checks, persists result JSON, emits CSPN journal events
on state transitions (ok->fail and fail->ok). Designed to be called from:
  - secubox-health-doctor.timer (every 60s)
  - healthctl check (on demand)
  - POST /api/v1/health-doctor/run (admin trigger)
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from . import checks

log = logging.getLogger("secubox.health_doctor")

CACHE_PATH = Path("/var/cache/secubox/health-doctor.json")
EMPTY_STATE: dict = {"generated_at": None, "checks": {}, "summary": {}}


def _load_previous() -> dict:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text())
        except Exception as e:
            log.warning("health-doctor cache unreadable: %s", e)
    return dict(EMPTY_STATE)


def _persist(state: dict) -> None:
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(json.dumps(state, indent=2, default=str))
    except Exception as e:
        log.warning("health-doctor persist failed: %s", e)


def _emit_journal(event: str, name: str, ok: bool, details: dict) -> None:
    """Emit a structured journal event (RFC 3339 + JSON details) per CSPN."""
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "check": name,
        "ok": ok,
        "details": details,
    }
    log.info(json.dumps(payload))


def run_once() -> dict:
    """Run every registered check, return the new state dict, persist it."""
    previous = _load_previous()
    prev_checks = previous.get("checks", {})
    now = datetime.now(timezone.utc).isoformat()
    state: Dict[str, Any] = {
        "generated_at": now,
        "checks": {},
        "summary": {"total": 0, "ok": 0, "fail": 0, "transitions": []},
    }
    for name, fn in checks.REGISTRY.items():
        t0 = time.time()
        try:
            ok, details = fn()
        except Exception as exc:
            ok, details = False, {"error": f"{type(exc).__name__}: {exc}"}
        elapsed = time.time() - t0
        entry = {
            "ok": ok,
            "details": details,
            "elapsed_ms": int(elapsed * 1000),
            "ts": now,
        }
        state["checks"][name] = entry
        state["summary"]["total"] += 1
        if ok:
            state["summary"]["ok"] += 1
        else:
            state["summary"]["fail"] += 1
        # State-transition events (ok->fail and fail->ok only)
        prev_ok = prev_checks.get(name, {}).get("ok")
        if prev_ok is not None and prev_ok != ok:
            transition = "fail->ok" if ok else "ok->fail"
            state["summary"]["transitions"].append({"check": name, "transition": transition})
            _emit_journal(
                f"health_doctor_{'recovered' if ok else 'failed'}",
                name, ok, details,
            )
    _persist(state)
    return state


def current() -> dict:
    """Read the persisted cache. Returns empty state on first call."""
    return _load_previous()
