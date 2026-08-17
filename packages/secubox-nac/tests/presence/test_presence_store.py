# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for `PresenceStore` (Project B, Task 1, #820).

Covers `pid()`, best-value upsert (geo/device_mac never null-clobbered,
`hits` increment, `last_seen` always updated), `first_seen` set-once,
plane/tier filtered `list()`, `count()`, and the `presence_alerts` table.
"""


def test_pid():
    from api.presence.store import pid
    assert pid("wan", "1.2.3.4") == "wan:1.2.3.4"
    assert pid("lan", "aa:bb:cc:00:00:01") == "lan:aa:bb:cc:00:00:01"


def test_upsert_best_value_and_hits(tmp_path):
    from api.presence.store import PresenceStore, pid
    s = PresenceStore(str(tmp_path / "devices.db"))
    ident = pid("wan", "1.2.3.4")
    s.upsert({
        "id": ident, "plane": "wan", "identity": "1.2.3.4",
        "geo_cc": "FR", "geo_asn": "AS1234", "geo_org": "Acme ISP",
        "provenance": "geo", "client_type": "browser",
        "first_seen": 100, "last_seen": 100,
    })
    d = s.get(ident)
    assert d["geo_cc"] == "FR" and d["hits"] == 1

    # Re-upsert with NO geo fields: previously learned geo must survive,
    # hits must increment, last_seen must move forward.
    s.upsert({
        "id": ident, "plane": "wan", "identity": "1.2.3.4",
        "last_seen": 200,
    })
    d = s.get(ident)
    assert d["geo_cc"] == "FR"
    assert d["geo_asn"] == "AS1234"
    assert d["last_seen"] == 200
    assert d["hits"] == 2
    assert s.count() == 1


def test_list_filters(tmp_path):
    from api.presence.store import PresenceStore, pid
    s = PresenceStore(str(tmp_path / "devices.db"))
    s.upsert({
        "id": pid("wan", "1.2.3.4"), "plane": "wan", "identity": "1.2.3.4",
        "first_seen": 100, "last_seen": 100,
    })
    s.upsert({
        "id": pid("lan", "aa:bb:cc:00:00:01"), "plane": "lan",
        "identity": "aa:bb:cc:00:00:01", "device_mac": "aa:bb:cc:00:00:01",
        "first_seen": 50, "last_seen": 300,
    })
    wan_only = s.list(plane="wan")
    assert len(wan_only) == 1 and wan_only[0]["plane"] == "wan"

    all_rows = s.list()
    assert len(all_rows) == 2
    # newest last_seen first
    assert all_rows[0]["identity"] == "aa:bb:cc:00:00:01"

    assert s.count() == 2
    assert s.count(plane="lan") == 1


def test_first_seen_preserved(tmp_path):
    from api.presence.store import PresenceStore, pid
    s = PresenceStore(str(tmp_path / "devices.db"))
    ident = pid("wan", "9.9.9.9")
    s.upsert({
        "id": ident, "plane": "wan", "identity": "9.9.9.9",
        "first_seen": 100, "last_seen": 100,
    })
    s.upsert({
        "id": ident, "plane": "wan", "identity": "9.9.9.9",
        "first_seen": 999, "last_seen": 200,
    })
    d = s.get(ident)
    assert d["first_seen"] == 100
    assert d["last_seen"] == 200


def test_prune_wan_deletes_only_old_low_hit_wan_rows(tmp_path):
    """#820 whole-branch fix I1 (spec §9 age-out): `prune_wan` must only
    delete `wan` rows that are BOTH stale (`last_seen` older than
    `max_age_days`) AND low-value (`hits < min_hits`) — a stale-but-
    frequently-seen row, a recent-but-low-hit row, and any lan/wg row
    (regardless of age/hits) must all survive."""
    import time

    from api.presence.store import PresenceStore, pid

    s = PresenceStore(str(tmp_path / "devices.db"))
    now = int(time.time())
    old_ts = now - 10 * 86400  # older than the default 7-day cutoff
    recent_ts = now - 1 * 86400  # within the default 7-day cutoff

    # old + low-hit (hits == 1) -> pruned.
    s.upsert({"id": pid("wan", "1.1.1.1"), "plane": "wan", "identity": "1.1.1.1", "last_seen": old_ts})

    # old + high-hit (5 upserts -> hits == 5, the default min_hits) -> kept.
    for _ in range(5):
        s.upsert({"id": pid("wan", "2.2.2.2"), "plane": "wan", "identity": "2.2.2.2", "last_seen": old_ts})

    # recent + low-hit -> kept (not stale enough).
    s.upsert({"id": pid("wan", "3.3.3.3"), "plane": "wan", "identity": "3.3.3.3", "last_seen": recent_ts})

    # lan/wg rows, old + low-hit -> must NEVER be touched by prune_wan.
    s.upsert({
        "id": pid("lan", "aa:bb:cc:00:00:01"), "plane": "lan",
        "identity": "aa:bb:cc:00:00:01", "last_seen": old_ts,
    })
    s.upsert({
        "id": pid("wg", "aa:bb:cc:00:00:02"), "plane": "wg",
        "identity": "aa:bb:cc:00:00:02", "last_seen": old_ts,
    })

    deleted = s.prune_wan()

    assert deleted == 1
    assert s.get(pid("wan", "1.1.1.1")) is None
    assert s.get(pid("wan", "2.2.2.2")) is not None
    assert s.get(pid("wan", "3.3.3.3")) is not None
    assert s.get(pid("lan", "aa:bb:cc:00:00:01")) is not None
    assert s.get(pid("wg", "aa:bb:cc:00:00:02")) is not None


def test_alerts(tmp_path):
    from api.presence.store import PresenceStore
    s = PresenceStore(str(tmp_path / "devices.db"))
    assert s.alerts() == []
    s.record_alert("wan", "warn", "bot surge")
    rows = s.alerts()
    assert len(rows) == 1
    assert rows[0]["plane"] == "wan"
    assert rows[0]["tier"] == "warn"
    assert rows[0]["detail"] == "bot surge"
