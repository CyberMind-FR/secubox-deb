# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import asyncio

import aiohttp
import aiohttp.web
import pytest
from api.federation import HealthChecker, HealthStore, default_probe, services_from_registry


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


async def _run_health_server(status: int):
    """Start a real aiohttp server with a single /health route returning
    `status`, bound to an ephemeral port. Returns (runner, site, port) —
    caller must site.stop() / runner.cleanup()."""
    import socket as _socket

    async def handler(_request):
        return aiohttp.web.Response(status=status, text="ok" if status < 400 else "nope")

    app = aiohttp.web.Application()
    app.router.add_get("/health", handler)
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    site = aiohttp.web.SockSite(runner, sock)
    await site.start()
    return runner, site, port


@pytest.mark.asyncio
async def test_probe_http_200_ok():
    """A service whose /health handler returns 200 probes as (True, latency>0)."""
    runner, site, port = await _run_health_server(200)
    try:
        ok, latency = await default_probe({"endpoint": f"http://127.0.0.1:{port}"})
        assert ok is True
        assert isinstance(latency, float)
        assert latency > 0
    finally:
        await site.stop()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_probe_http_500_down():
    """A service whose /health handler returns 500 probes as not-ok."""
    runner, site, port = await _run_health_server(500)
    try:
        ok, _latency = await default_probe({"endpoint": f"http://127.0.0.1:{port}"})
        assert ok is False
    finally:
        await site.stop()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_probe_tcp_closed_port_down():
    """A TCP probe against a closed/unbound port fails fast with (False, None)."""
    ok, latency = await default_probe({"endpoint": "127.0.0.1:1"}, timeout=1.0)
    assert ok is False
    assert latency is None


@pytest.mark.asyncio
async def test_probe_no_endpoint_down():
    """A service with neither url nor endpoint never raises and reports down."""
    ok, latency = await default_probe({})
    assert ok is False
    assert latency is None


def test_services_from_registry_maps_ids(monkeypatch):
    """services_from_registry() normalizes the annuaire catalog shape into
    {"id", "endpoint", "health_path"} dicts."""
    import api.federation as federation_mod

    fake_catalog = [
        {"service_id": "svc-a", "endpoint": "http://127.0.0.1:9001", "name": "A"},
        {"service_id": "svc-b", "endpoint": "127.0.0.1:9002", "health_path": "/healthz"},
    ]

    def fake_get_catalog():
        return fake_catalog, None

    monkeypatch.setattr(federation_mod.annuaire_client, "get_catalog", fake_get_catalog)

    services = federation_mod.services_from_registry()

    assert services == [
        {"id": "svc-a", "endpoint": "http://127.0.0.1:9001", "health_path": "/health"},
        {"id": "svc-b", "endpoint": "127.0.0.1:9002", "health_path": "/healthz"},
    ]


def test_services_from_registry_annuaire_error_returns_empty(monkeypatch):
    """When the local annuaire is unreachable (error string set), return []."""
    import api.federation as federation_mod

    def fake_get_catalog_error():
        return [], "ConnectionRefusedError: [Errno 111]"

    monkeypatch.setattr(federation_mod.annuaire_client, "get_catalog", fake_get_catalog_error)

    assert federation_mod.services_from_registry() == []


def test_services_from_registry_raises_returns_empty(monkeypatch):
    """If get_catalog itself raises, services_from_registry never propagates."""
    import api.federation as federation_mod

    def fake_get_catalog_raises():
        raise RuntimeError("boom")

    monkeypatch.setattr(federation_mod.annuaire_client, "get_catalog", fake_get_catalog_raises)

    assert federation_mod.services_from_registry() == []


@pytest.mark.asyncio
async def test_probe_non_dict_service_returns_false():
    """A non-dict service (None, str, ...) never raises — reported as (False, None)."""
    assert await default_probe(None) == (False, None)
    assert await default_probe("nope") == (False, None)


@pytest.mark.asyncio
async def test_publish_fn_called_after_sweep():
    """When a publish_fn is passed, it is called once per sweep_once() with
    the store's snapshot, after every service has been probed."""

    def services_fn():
        return [{"id": "a"}]

    async def probe_fn(svc):
        return True, 5.0

    published = []
    store = HealthStore(fail_threshold=1)
    checker = HealthChecker(
        services_fn, probe_fn, store, enabled=True, publish_fn=published.append
    )

    n = await checker.sweep_once()

    assert n == 1
    assert len(published) == 1
    assert published[0]["a"]["status"] == "up"


def test_make_dht_publisher_writes_health():
    """make_dht_publisher(dht) returns a publish_fn that stores each service's
    health under node_id_for('health:'+service_id).hex() via dht.put_health."""
    from api.dht import node_id_for
    from api.federation import make_dht_publisher

    class FakeDHT:
        def __init__(self):
            self.calls = []

        def put_health(self, key_hex, blob):
            self.calls.append((key_hex, blob))

    fake = FakeDHT()
    publish_fn = make_dht_publisher(fake)

    snapshot = {"svc-a": {"status": "up", "last_check": 123.0}}
    publish_fn(snapshot)

    assert len(fake.calls) == 1
    key_hex, blob = fake.calls[0]
    assert key_hex == node_id_for("health:svc-a").hex()
    assert blob["service_id"] == "svc-a"
    assert blob["status"] == "up"
