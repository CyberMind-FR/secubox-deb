# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import asyncio

import pytest
from api.federation import HealthChecker, HealthStore


def test_debounce_up_down_up():
    """Test debouncing: failures are buffered until threshold, recovery resets counter."""
    store = HealthStore(fail_threshold=3)

    # Service starts up
    store.record("s", True)
    assert store.status_of("s")["status"] == "up"

    # First failure: status unchanged (debounce, 1 < 3)
    store.record("s", False)
    assert store.status_of("s")["status"] == "up"

    # Second failure: status unchanged (debounce, 2 < 3)
    store.record("s", False)
    assert store.status_of("s")["status"] == "up"

    # Third failure: status changes to "down" (threshold reached)
    store.record("s", False)
    assert store.status_of("s")["status"] == "down"

    # Recovery: status goes back to "up", failures reset, latency recorded
    store.record("s", True, 12.0)
    status = store.status_of("s")
    assert status["status"] == "up"
    assert status["consecutive_failures"] == 0
    assert status["latency_ms"] == 12.0


def test_unknown_service():
    """Test that an unknown service returns 'unknown' status."""
    store = HealthStore()
    status = store.status_of("never")
    assert status["status"] == "unknown"


def test_save_load_roundtrip_0600(tmp_path):
    """Test persistence: save to file with 0600 perms, load into new store, verify snapshot."""
    store = HealthStore()

    # Record some services
    store.record("svc1", True, 5.0)
    store.record("svc2", False)
    store.record("svc2", False)

    snapshot_before = store.snapshot()

    # Save to file
    db_file = tmp_path / "h.json"
    store.save(db_file)

    # Verify file permissions are 0600
    mode = db_file.stat().st_mode & 0o777
    assert mode == 0o600, f"Expected 0600, got {oct(mode)}"

    # Load into new store
    store2 = HealthStore()
    store2.load(db_file)
    snapshot_after = store2.snapshot()

    # Verify snapshots match
    assert snapshot_before == snapshot_after


@pytest.mark.asyncio
async def test_sweep_marks_up_and_down():
    """sweep_once probes every service and records ok/down into the store."""

    def services_fn():
        return [{"id": "a"}, {"id": "b"}]

    async def probe_fn(svc):
        if svc["id"] == "a":
            return True, 5.0
        return False, None

    store = HealthStore(fail_threshold=1)
    checker = HealthChecker(services_fn, probe_fn, store, enabled=True)

    n = await checker.sweep_once()

    assert n == 2
    assert store.status_of("a")["status"] == "up"
    assert store.status_of("b")["status"] == "down"


@pytest.mark.asyncio
async def test_disabled_no_probe():
    """sweep_once is a no-op when the checker is not enabled."""

    def services_fn():
        return [{"id": "a"}, {"id": "b"}]

    async def probe_fn(svc):
        if svc["id"] == "a":
            return True, 5.0
        return False, None

    store = HealthStore(fail_threshold=1)
    checker = HealthChecker(services_fn, probe_fn, store, enabled=False)

    n = await checker.sweep_once()

    assert n == 0
    assert store.status_of("a")["status"] == "unknown"


@pytest.mark.asyncio
async def test_concurrency_cap():
    """sweep_once never lets more than max_concurrency probes run concurrently."""

    counters = {"current": 0, "peak": 0}

    def services_fn():
        return [{"id": f"s{i}"} for i in range(10)]

    async def probe_fn(svc):
        counters["current"] += 1
        counters["peak"] = max(counters["peak"], counters["current"])
        for _ in range(3):
            await asyncio.sleep(0)
        counters["current"] -= 1
        return True, 1.0

    store = HealthStore(fail_threshold=1)
    checker = HealthChecker(services_fn, probe_fn, store, max_concurrency=3, enabled=True)

    await checker.sweep_once()

    assert counters["peak"] <= 3


@pytest.mark.asyncio
async def test_probe_exception_marks_down():
    """A probe_fn that raises is treated as a failure, never propagates."""

    def services_fn():
        return [{"id": "a"}]

    async def probe_fn(svc):
        raise RuntimeError("boom")

    store = HealthStore(fail_threshold=1)
    checker = HealthChecker(services_fn, probe_fn, store, enabled=True)

    n = await checker.sweep_once()

    assert n == 1
    assert store.status_of("a")["status"] == "down"
