# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: federation
Federation health-check store — debounced up/down status with persistence.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path


class HealthStore:
    """
    Debounced health-check store for federation services.

    Records up/down events with configurable failure threshold before marking
    a service as "down". Persists state to JSON with 0600 file permissions.
    """

    def __init__(self, fail_threshold: int = 3, clock=None):
        """
        Initialize HealthStore.

        Args:
            fail_threshold: Number of consecutive failures before marking "down"
            clock: Optional clock function (default: time.time)
        """
        self._fail_threshold = fail_threshold
        self._clock = clock if clock is not None else time.time
        self._svc: dict[str, dict] = {}

    def record(self, service_id: str, ok: bool, latency_ms: float | None = None) -> None:
        """
        Record a health check result.

        Args:
            service_id: Service identifier
            ok: True if check succeeded, False if failed
            latency_ms: Optional latency in milliseconds
        """
        entry = self._svc.setdefault(
            service_id,
            {
                "status": "up",
                "consecutive_failures": 0,
                "latency_ms": None,
                "last_ok": None,
                "last_check": None,
            },
        )

        now = self._clock()
        entry["last_check"] = now

        if ok:
            entry["status"] = "up"
            entry["consecutive_failures"] = 0
            entry["latency_ms"] = latency_ms
            entry["last_ok"] = now
        else:
            entry["consecutive_failures"] += 1
            if entry["consecutive_failures"] >= self._fail_threshold:
                entry["status"] = "down"
            # else: status unchanged (debounce)

    def status_of(self, service_id: str) -> dict:
        """
        Get status snapshot for a service.

        Args:
            service_id: Service identifier

        Returns:
            Dict with status, consecutive_failures, latency_ms, last_ok, last_check
        """
        return dict(
            self._svc.get(
                service_id,
                {
                    "status": "unknown",
                    "consecutive_failures": 0,
                    "latency_ms": None,
                    "last_ok": None,
                    "last_check": None,
                },
            )
        )

    def snapshot(self) -> dict:
        """
        Get a deep copy of all service states.

        Returns:
            Dict mapping service_id -> status dict
        """
        return {sid: dict(e) for sid, e in self._svc.items()}

    def save(self, path) -> None:
        """
        Persist store to JSON file with 0600 permissions.

        Args:
            path: File path (str or Path)
        """
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self._svc))
        os.chmod(p, 0o600)

    def load(self, path) -> None:
        """
        Load store from JSON file.

        Args:
            path: File path (str or Path)
        """
        p = Path(path)
        if not p.exists():
            return
        try:
            self._svc = json.loads(p.read_text())
        except (ValueError, OSError):
            pass
