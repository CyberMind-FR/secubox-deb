# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: federation
Federation health-check store — debounced up/down status with persistence.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

from . import annuaire_client


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


class HealthChecker:
    """
    Async sweeper that probes a set of federation services and records
    liveness into a HealthStore.

    The probe itself is injected (real network probing is a later task);
    this class only owns the sweep loop, concurrency bound, and opt-in gate.
    """

    def __init__(
        self,
        services_fn,
        probe_fn,
        store,
        interval: int = 30,
        max_concurrency: int = 20,
        enabled: bool = False,
    ):
        """
        Initialize HealthChecker.

        Args:
            services_fn: Callable returning a list of service dicts
                (each with at least an "id" key).
            probe_fn: `async def probe(service) -> tuple[bool, float | None]`
                returning (ok, latency_ms).
            store: HealthStore instance to record results into.
            interval: Seconds between sweeps in the background run() loop.
            max_concurrency: Maximum number of probes in flight at once.
            enabled: Opt-in flag; sweep_once() is a no-op while False.
        """
        self._services_fn = services_fn
        self._probe_fn = probe_fn
        self._store = store
        self._interval = interval
        self._enabled = enabled
        self._max_concurrency = max_concurrency
        self._sem = asyncio.Semaphore(max_concurrency)
        self._task = None

    async def sweep_once(self) -> int:
        """
        Probe every service returned by services_fn(), bounded by the
        concurrency semaphore, and record each result into the store.

        Returns:
            The number of services probed (0 if disabled).
        """
        if not self._enabled:
            return 0

        services = self._services_fn() or []

        async def _one(svc):
            async with self._sem:
                try:
                    ok, latency = await self._probe_fn(svc)
                except Exception:
                    ok, latency = False, None
                self._store.record(svc["id"], ok, latency)

        await asyncio.gather(*[_one(s) for s in services])
        return len(services)

    async def run(self):
        """Background loop: sweep on interval while enabled; cancel-safe."""
        while True:
            if self._enabled:
                try:
                    await self.sweep_once()
                except Exception:
                    pass
            await asyncio.sleep(self._interval)

    def start(self):
        """Start the background sweep loop as an asyncio task."""
        self._task = asyncio.create_task(self.run())

    async def stop(self):
        """Cancel the background sweep loop, swallowing CancelledError."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


async def default_probe(
    service: dict, timeout: float = 5.0
) -> tuple[bool, float | None]:
    """
    Liveness probe for a federated service.

    HTTP(S) GET of <base><health_path> when the service carries an http(s)
    url/endpoint; otherwise a TCP connect to host:port. Any error or timeout
    is swallowed and reported as (False, None) — this function never raises.

    Args:
        service: Service dict with "url" or "endpoint" (and optional
            "health_path", default "/health").
        timeout: Overall timeout in seconds for the probe.

    Returns:
        (ok, latency_ms) — latency_ms is None when ok is False.
    """
    if not isinstance(service, dict):
        return (False, None)

    endpoint = service.get("url") or service.get("endpoint") or ""
    health_path = service.get("health_path", "/health")
    if not endpoint:
        return (False, None)

    t0 = time.monotonic()
    try:
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            import aiohttp  # noqa: PLC0415

            url = endpoint.rstrip("/") + health_path
            timeout_cfg = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_cfg) as sess:
                async with sess.get(url, ssl=False) as resp:
                    ok = 200 <= resp.status < 400
                    await resp.read()
            return (ok, (time.monotonic() - t0) * 1000.0)
        else:
            host, _, port = endpoint.rpartition(":")
            if not host or not port.isdigit():
                return (False, None)
            fut = asyncio.open_connection(host, int(port))
            reader, writer = await asyncio.wait_for(fut, timeout)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1.0)
            except Exception:  # noqa: BLE001
                pass
            return (True, (time.monotonic() - t0) * 1000.0)
    except Exception:  # noqa: BLE001
        return (False, None)


def services_from_registry() -> list[dict]:
    """
    Best-effort list of federated services to health-check, sourced from the
    local annuaire catalog.

    Each returned dict has at least "id" and "endpoint" (health_path is
    included with a "/health" default). If the annuaire is unreachable or
    the catalog is empty, returns []. Never raises.
    """
    try:
        catalog, err = annuaire_client.get_catalog()
        if err or not catalog:
            return []
        # get_catalog() returns a list of service dicts; tolerate a dict
        # wrapper ({"services": [...]}) too, in case the shape evolves.
        services = catalog.get("services", catalog) if isinstance(catalog, dict) else catalog
        out = []
        for s in services or []:
            if not isinstance(s, dict):
                continue
            sid = s.get("id") or s.get("service_id") or s.get("name")
            if not sid:
                continue
            out.append(
                {
                    "id": sid,
                    "endpoint": s.get("endpoint") or s.get("url") or "",
                    "health_path": s.get("health_path", "/health"),
                }
            )
        return out
    except Exception:  # noqa: BLE001
        return []
