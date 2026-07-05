# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for `presence.local.collect_local` and
`presence.kbin.collect_kbin` (Project B, Task 4, #820).
"""

import json


class _FakeDeviceStore:
    """Mimics `api.store.DeviceStore.list()`'s return shape only."""

    def __init__(self, rows):
        self._rows = rows

    def list(self, *, limit=5000):
        return self._rows


class _RaisingDeviceStore:
    def list(self, *, limit=5000):
        raise RuntimeError("device store unavailable")


def test_collect_local(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.local import collect_local

    devices = [
        {
            "mac": "aa:bb:cc:00:00:01", "source": "dnsmasq",
            "hostname": "laptop", "ip": "192.168.1.10",
            "device_type": "laptop", "risk_level": "low",
            "last_seen": 1000,
        },
        {
            "mac": "aa:bb:cc:00:00:02", "source": "mesh",
            "hostname": "c3box", "ip": "10.10.0.2",
            "device_type": "mesh_node", "risk_level": "unknown",
            "last_seen": 2000,
        },
    ]
    store = PresenceStore(str(tmp_path / "devices.db"))
    dstore = _FakeDeviceStore(devices)

    n = collect_local(store, dstore)

    assert n == 2

    lan_row = store.get("lan:aa:bb:cc:00:00:01")
    assert lan_row is not None
    assert lan_row["provenance"] == "lan"
    assert lan_row["device_mac"] == "aa:bb:cc:00:00:01"
    assert lan_row["client_type"] == "laptop"
    assert lan_row["last_seen"] == 1000
    extra = json.loads(lan_row["extra"])
    assert extra["hostname"] == "laptop"
    assert extra["risk_level"] == "low"

    wg_row = store.get("wg:aa:bb:cc:00:00:02")
    assert wg_row is not None
    assert wg_row["provenance"] == "tunnel"
    assert wg_row["device_mac"] == "aa:bb:cc:00:00:02"
    assert wg_row["client_type"] == "mesh_node"
    assert wg_row["last_seen"] == 2000

    assert store.count() == 2


def test_collect_local_failsafe(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.local import collect_local

    store = PresenceStore(str(tmp_path / "devices.db"))
    n = collect_local(store, _RaisingDeviceStore())

    assert n == 0
    assert store.count() == 0


def test_collect_local_missing_mac_skipped(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.local import collect_local

    store = PresenceStore(str(tmp_path / "devices.db"))
    dstore = _FakeDeviceStore([{"mac": "", "source": "arp"}])

    n = collect_local(store, dstore)

    assert n == 0
    assert store.count() == 0


def _catch_line(client, host="example.com", kind="video", ts=1700000000):
    return json.dumps({
        "ts": ts, "client": client, "host": host, "url": "https://example.com/x",
        "kind": kind, "ctype": "video/mp4", "bytes": 12345,
    })


def test_collect_kbin(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.kbin import collect_kbin

    catch = tmp_path / "media-catch.jsonl"
    catch.write_text(
        _catch_line("hash-aaa", ts=100) + "\n" +
        _catch_line("hash-bbb", ts=200) + "\n" +
        _catch_line("hash-aaa", ts=300) + "\n"
    )

    store = PresenceStore(str(tmp_path / "devices.db"))
    n = collect_kbin(store, personas_source=str(catch))

    assert n == 2
    rows = store.list(plane="kbin")
    assert len(rows) == 2

    by_identity = {r["identity"]: r for r in rows}
    assert by_identity["hash-aaa"]["provenance"] == "tunnel"
    assert by_identity["hash-aaa"]["client_type"] == "persona"
    # Last occurrence in tail order wins last_seen.
    assert by_identity["hash-aaa"]["last_seen"] == 300
    assert by_identity["hash-bbb"]["last_seen"] == 200

    # No token source given -> no report_token key stored.
    extra = json.loads(by_identity["hash-aaa"]["extra"])
    assert "report_token" not in extra or not extra["report_token"]


def test_collect_kbin_with_report_token(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.kbin import collect_kbin

    catch = tmp_path / "media-catch.jsonl"
    catch.write_text(_catch_line("hash-ccc", ts=100) + "\n")

    store = PresenceStore(str(tmp_path / "devices.db"))
    tokens = {"hash-ccc": "tok-xyz"}

    n = collect_kbin(store, personas_source=str(catch), report_token_source=tokens)

    assert n == 1
    row = store.get("kbin:hash-ccc")
    extra = json.loads(row["extra"])
    assert extra["report_token"] == "tok-xyz"


def test_collect_kbin_missing(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.kbin import collect_kbin

    store = PresenceStore(str(tmp_path / "devices.db"))
    n = collect_kbin(store, personas_source=str(tmp_path / "does-not-exist.jsonl"))

    assert n == 0
    assert store.count() == 0


def test_collect_kbin_bad_lines(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.kbin import collect_kbin

    catch = tmp_path / "media-catch.jsonl"
    catch.write_text(
        _catch_line("hash-ddd", ts=100) + "\n" +
        "not valid json {{{\n" +
        "\n" +
        json.dumps({"no_client_field": True}) + "\n"
    )

    store = PresenceStore(str(tmp_path / "devices.db"))
    n = collect_kbin(store, personas_source=str(catch))

    assert n == 1
    assert store.get("kbin:hash-ddd") is not None
