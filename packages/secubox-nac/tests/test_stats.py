# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for `GET /stats` (#820: the shared
sidebar polls `/api/v1/nac/stats` for its aggregation badge, but nac only
served `/summary` -> 404) and `DeviceStore.count_by()` (its whitelisted
GROUP BY backing the by_source/by_type breakdown).
"""

import inspect


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_nft(monkeypatch, main):
    sets: dict = {}

    def fake_add(set_name, element):
        sets.setdefault(set_name, set()).add(element)
        return True

    def fake_delete(set_name, element):
        sets.get(set_name, set()).discard(element)
        return True

    def fake_list(set_name):
        return sorted(sets.get(set_name, set()))

    monkeypatch.setattr(main, "_nft_add_element", fake_add)
    monkeypatch.setattr(main, "_nft_delete_element", fake_delete)
    monkeypatch.setattr(main, "_nft_list_set", fake_list)
    return sets


def _setup(tmp_path, monkeypatch):
    """Fresh DeviceStore + JSON side files under tmp_path, fake nft."""
    from api.store import DeviceStore
    import api.main as main

    monkeypatch.setattr(main, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "HISTORY_FILE", tmp_path / "history.json")
    monkeypatch.setattr(main, "CLIENTS_META_FILE", tmp_path / "clients.json")
    monkeypatch.setattr(main, "ZONE_ASSIGNMENTS_FILE", tmp_path / "zone_assignments.json")
    main.store = DeviceStore(str(tmp_path / "d.db"))
    _fake_nft(monkeypatch, main)
    main.stats_cache.clear()
    return main


USER = {"sub": "tester"}


# --- GET /stats ---


def test_stats_is_plain_def_not_async():
    """#820 hard constraint: nac is aggregator-mounted on a shared single
    loop — `stats` must be plain `def` (FastAPI threadpools it), never
    `async def` (which would block the whole board on the event loop)."""
    import api.main as main

    assert not inspect.iscoroutinefunction(main.stats)


def test_stats_returns_five_keys_reflecting_seeded_devices(tmp_path, monkeypatch):
    main = _setup(tmp_path, monkeypatch)

    main.store.upsert({
        "mac": "aa:bb:cc:00:09:01", "ip": "10.0.0.1", "device_type": "camera",
        "source": "arp", "last_seen": 1,
    })
    main.store.upsert({
        "mac": "aa:bb:cc:00:09:02", "ip": "10.0.0.2", "device_type": "camera",
        "source": "dnsmasq", "last_seen": 1,
    })
    main.store.upsert({
        "mac": "aa:bb:cc:00:09:03", "ip": "10.0.0.3", "device_type": "phone",
        "source": "dnsmasq", "last_seen": 1,
    })

    result = main.stats(user=USER)

    assert set(result.keys()) == {"devices", "blocked", "quarantine", "by_source", "by_type"}
    assert isinstance(result["devices"], int) and result["devices"] == 3
    assert isinstance(result["blocked"], int)
    assert isinstance(result["quarantine"], int)
    assert isinstance(result["by_source"], dict)
    assert isinstance(result["by_type"], dict)

    assert result["by_source"] == {"arp": 1, "dnsmasq": 2}
    assert result["by_type"] == {"camera": 2, "phone": 1}


def test_stats_guards_none_store(tmp_path, monkeypatch):
    """If the lazy-init store singleton is still None (never initialized),
    `/stats` must degrade to empty aggregations rather than raising —
    matching how `clients()` already guards `store` elsewhere."""
    main = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "store", None)

    result = main.stats(user=USER)

    assert result["by_source"] == {}
    assert result["by_type"] == {}


# --- DeviceStore.count_by() ---


def test_count_by_whitelisted_column_groups_counts(tmp_path):
    from api.store import DeviceStore

    s = DeviceStore(str(tmp_path / "d.db"))
    s.upsert({"mac": "aa:bb:cc:00:0a:01", "source": "arp", "last_seen": 1})
    s.upsert({"mac": "aa:bb:cc:00:0a:02", "source": "arp", "last_seen": 1})
    s.upsert({"mac": "aa:bb:cc:00:0a:03", "source": "dnsmasq", "last_seen": 1})

    assert s.count_by("source") == {"arp": 2, "dnsmasq": 1}


def test_count_by_rejects_non_whitelisted_column(tmp_path):
    """The column name is interpolated into the SQL text (can't be a bound
    parameter) — a non-whitelisted value (including an injection attempt)
    must return `{}`, never execute."""
    from api.store import DeviceStore

    s = DeviceStore(str(tmp_path / "d.db"))
    s.upsert({"mac": "aa:bb:cc:00:0a:04", "source": "arp", "last_seen": 1})

    assert s.count_by("mac; DROP TABLE devices;--") == {}
    assert s.count_by("notacolumn") == {}
    # sanity: the table survived the attempted injection string above
    assert s.count() == 1


def test_count_by_groups_null_values_under_unknown(tmp_path):
    from api.store import DeviceStore

    s = DeviceStore(str(tmp_path / "d.db"))
    # zone is left unset (NULL, no SQL DEFAULT on that column)
    s.upsert({"mac": "aa:bb:cc:00:0a:05", "source": "arp", "last_seen": 1})

    assert s.count_by("zone") == {"unknown": 1}
