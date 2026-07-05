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
