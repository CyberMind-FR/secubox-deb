# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for Project B Task 5 (#820): wiring the
presence collectors into the off-loop `Collector` cycle + the `/presence*`
read API in `api/main.py`.

Mirrors this package's existing test style (`tests/test_endpoints.py`,
`tests/test_lazy_init.py`): handlers are called DIRECTLY as plain Python
functions (never through a `TestClient`/real HTTP round-trip) — that is
exactly what "plain `def`, threadpooled by FastAPI" buys us, and it's how
every other nac test already exercises the router.
"""
import inspect

import pytest

USER = {"sub": "tester"}


def _setup(tmp_path, monkeypatch):
    """Fresh DeviceStore + PresenceStore sharing one throwaway devices.db,
    wired onto `api.main`'s module globals directly (bypassing `_do_init`,
    exactly like `test_endpoints.py`'s `_setup` does for `store`)."""
    from api.store import DeviceStore
    from api.presence.store import PresenceStore
    import api.main as main

    db_path = str(tmp_path / "devices.db")
    monkeypatch.setattr(main, "DEVICES_DB_PATH", db_path)
    monkeypatch.setattr(main, "store", DeviceStore(db_path))
    monkeypatch.setattr(main, "presence_store", PresenceStore(db_path))
    main.stats_cache.clear()
    return main


def _seed(presence_store, plane, identity, **extra):
    row = {"id": f"{plane}:{identity}", "plane": plane, "identity": identity}
    row.update(extra)
    presence_store.upsert(row)


# ─── GET /presence ───────────────────────────────────────────────────────


def test_list_presence_filters_by_plane(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    _seed(main.presence_store, "wan", "1.2.3.4", geo_cc="US")
    _seed(main.presence_store, "lan", "aa:bb:cc:00:00:01", device_mac="aa:bb:cc:00:00:01")
    _seed(main.presence_store, "kbin", "deadbeef01")

    result = main.list_presence(plane="wan", user=USER)

    assert result["count"] == 1
    assert result["items"][0]["id"] == "wan:1.2.3.4"
    assert result["items"][0]["plane"] == "wan"


def test_list_presence_no_filter_returns_all(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    _seed(main.presence_store, "wan", "1.2.3.4")
    _seed(main.presence_store, "lan", "aa:bb:cc:00:00:01")

    result = main.list_presence(user=USER)

    assert result["count"] == 2


def test_list_presence_guards_missing_store(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "presence_store", None)

    result = main.list_presence(user=USER)

    assert result == {"items": [], "count": 0}


# ─── GET /presence/{pid} ─────────────────────────────────────────────────


def test_get_presence_returns_seeded_row(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    _seed(main.presence_store, "wan", "1.2.3.4", geo_cc="FR")

    result = main.get_presence("wan:1.2.3.4", user=USER)

    assert result["id"] == "wan:1.2.3.4"
    assert result["geo_cc"] == "FR"


def test_get_presence_404_for_missing(tmp_path, monkeypatch):
    from fastapi import HTTPException

    main = _setup(tmp_path, monkeypatch)

    with pytest.raises(HTTPException) as exc_info:
        main.get_presence("wan:9.9.9.9", user=USER)

    assert exc_info.value.status_code == 404


def test_get_presence_guards_missing_store(tmp_path, monkeypatch):
    from fastapi import HTTPException

    main = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "presence_store", None)

    with pytest.raises(HTTPException) as exc_info:
        main.get_presence("wan:1.2.3.4", user=USER)

    assert exc_info.value.status_code == 404


# ─── GET /presence/geo ───────────────────────────────────────────────────


def test_presence_geo_aggregates_by_country_and_asn(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    _seed(main.presence_store, "wan", "1.1.1.1", geo_cc="US", geo_asn="AS13335")
    _seed(main.presence_store, "wan", "2.2.2.2", geo_cc="US", geo_asn="AS15169")
    _seed(main.presence_store, "wan", "3.3.3.3", geo_cc="FR", geo_asn="AS13335")
    _seed(main.presence_store, "lan", "aa:bb:cc:00:00:01")  # no geo -> excluded

    result = main.presence_geo(user=USER)

    assert result["by_country"] == {"US": 2, "FR": 1}
    assert result["by_asn"] == {"AS13335": 2, "AS15169": 1}


def test_presence_geo_guards_missing_store(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "presence_store", None)

    result = main.presence_geo(user=USER)

    assert result == {"by_country": {}, "by_asn": {}}


# ─── GET /presence/alerts ────────────────────────────────────────────────


def test_presence_alerts_returns_recorded_alerts(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    main.presence_store.record_alert("wan", "warn", "bot surge")

    result = main.presence_alerts_list(user=USER)

    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["plane"] == "wan"
    assert result["alerts"][0]["tier"] == "warn"


def test_presence_alerts_guards_missing_store(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "presence_store", None)

    assert main.presence_alerts_list(user=USER) == {"alerts": []}


# ─── POST /presence/sync ─────────────────────────────────────────────────


def test_presence_sync_calls_all_three_collectors(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    calls = []

    def fake_local(store, device_store):
        calls.append("local")
        return 1

    def fake_wan(store, geo_enrich=None):
        calls.append("wan")
        return 2

    def fake_kbin(store):
        calls.append("kbin")
        return 3

    monkeypatch.setattr(main, "collect_local", fake_local)
    monkeypatch.setattr(main, "collect_wan", fake_wan)
    monkeypatch.setattr(main, "collect_kbin", fake_kbin)

    result = main.presence_sync(user=USER)

    assert set(calls) == {"local", "wan", "kbin"}
    assert result == {"synced": 6}


def test_presence_sync_one_failing_collector_does_not_block_others(tmp_path, monkeypatch):
    """Mirrors the off-loop `Collector.cycle_once` contract: each plane is
    independently guarded, so a raising collector never prevents the
    other two from running (fail-safe, #820 Task 5)."""
    main = _setup(tmp_path, monkeypatch)
    calls = []

    def raising_local(store, device_store):
        raise RuntimeError("boom")

    def fake_wan(store, geo_enrich=None):
        calls.append("wan")
        return 5

    def fake_kbin(store):
        calls.append("kbin")
        return 7

    monkeypatch.setattr(main, "collect_local", raising_local)
    monkeypatch.setattr(main, "collect_wan", fake_wan)
    monkeypatch.setattr(main, "collect_kbin", fake_kbin)

    result = main.presence_sync(user=USER)

    assert set(calls) == {"wan", "kbin"}
    assert result == {"synced": 12}


def test_presence_sync_guards_missing_store(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "presence_store", None)

    assert main.presence_sync(user=USER) == {"synced": 0}


# ─── _do_init() builds presence_store idempotently ──────────────────────


def test_do_init_builds_presence_store_idempotently(tmp_path, monkeypatch):
    import api.main as main

    monkeypatch.setattr(main, "DEVICES_DB_PATH", str(tmp_path / "d.db"))
    monkeypatch.setattr(main, "MACGUARD_DEVICES_JSON", str(tmp_path / "absent-mg.json"))
    monkeypatch.setattr(main, "DEVICEINTEL_DEVICES_JSON", str(tmp_path / "absent-di.json"))
    monkeypatch.setattr(main, "IOTGUARD_DEVICES_DB", str(tmp_path / "absent-iot.db"))
    monkeypatch.setattr(main, "store", None)
    monkeypatch.setattr(main, "collector", None)
    monkeypatch.setattr(main, "oui_map", None)
    monkeypatch.setattr(main, "presence_store", None)
    monkeypatch.setattr(main, "_initialized", False)
    monkeypatch.setattr(main, "_collector_started", False)

    assert main.presence_store is None
    main._do_init()

    assert main.presence_store is not None
    assert main.collector is not None
    assert main.collector.presence_store is main.presence_store

    first_presence_store = main.presence_store
    main._do_init()  # second call is a no-op
    assert main.presence_store is first_presence_store


# ─── plain `def` + JWT-gated ─────────────────────────────────────────────


PRESENCE_HANDLERS = [
    "list_presence",
    "presence_geo",
    "presence_alerts_list",
    "presence_sync",
    "get_presence",
]


def test_presence_handlers_are_plain_def():
    import api.main as main

    for name in PRESENCE_HANDLERS:
        fn = getattr(main, name)
        assert not inspect.iscoroutinefunction(fn), f"{name} must be plain def, not async def"


def test_presence_handlers_are_jwt_gated():
    from fastapi import Depends
    from secubox_core.auth import require_jwt
    import api.main as main

    for name in PRESENCE_HANDLERS:
        fn = getattr(main, name)
        sig = inspect.signature(fn)
        assert "user" in sig.parameters, f"{name} has no `user` dependency parameter"
        default = sig.parameters["user"].default
        assert isinstance(default, type(Depends(require_jwt))), f"{name}'s user param is not a Depends(...)"
        assert default.dependency is require_jwt, f"{name} is not gated by require_jwt"
