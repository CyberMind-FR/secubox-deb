# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for the canonical SQLite device store.

Covers `canon_mac`, `DeviceStore` best-value upsert, and idempotent
`migrate_legacy` import from the mac-guard/device-intel/iot-guard legacy
shapes (#817 Device Guardian consolidation, Task 1).
"""


def test_canon_mac():
    from api.store import canon_mac
    assert canon_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert canon_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert canon_mac("not-a-mac") == ""


def test_upsert_best_value(tmp_path):
    from api.store import DeviceStore, canon_mac
    s = DeviceStore(str(tmp_path/"d.db"))
    s.upsert({"mac": canon_mac("AA:BB:CC:00:00:01"), "ip":"10.0.0.5","hostname":"h","oui_vendor":"Acme","first_seen":1,"last_seen":1,"source":"arp"})
    # a later sighting with no vendor must NOT wipe the stored vendor, but must update last_seen/ip
    s.upsert({"mac": "aa:bb:cc:00:00:01", "ip":"10.0.0.6","last_seen":2,"source":"dnsmasq"})
    d = s.get("aa:bb:cc:00:00:01")
    assert d["oui_vendor"] == "Acme" and d["ip"] == "10.0.0.6" and d["last_seen"] == 2
    assert s.count() == 1


def test_migrate_idempotent(tmp_path):
    import json, sqlite3
    from api.store import DeviceStore, migrate_legacy
    mg = tmp_path/"mg.json"; mg.write_text(json.dumps({"AA:BB:CC:00:00:02":{"ip":"10.0.0.7","vendor":"V","hostname":"m","first_seen":10,"last_seen":11}}))
    di = tmp_path/"di.json"; di.write_text(json.dumps({"AA:BB:CC:00:00:03":{"ip":"10.0.0.8","is_openwrt":True,"model":"X"}}))
    iot = tmp_path/"iot.db"; c=sqlite3.connect(iot); c.execute("CREATE TABLE devices(mac_address TEXT, ip TEXT, device_type TEXT, risk_score INT)"); c.execute("INSERT INTO devices VALUES('aa:bb:cc:00:00:02','10.0.0.7','phone',30)"); c.commit(); c.close()
    s = DeviceStore(str(tmp_path/"d.db"))
    r1 = migrate_legacy(s, macguard_json=str(mg), deviceintel_json=str(di), iot_db=str(iot))
    assert r1 == {"imported": 3, "skipped": 0}
    assert s.count() == 2  # :02 (merged mg+iot) and :03
    d = s.get("aa:bb:cc:00:00:02")
    assert d["oui_vendor"] == "V" and d["device_type"] == "phone"  # cross-source merge
    r2 = migrate_legacy(s, macguard_json=str(mg), deviceintel_json=str(di), iot_db=str(iot))
    assert r2 == {"imported": 3, "skipped": 0}
    assert s.count() == 2  # re-run no-op


def test_first_seen_preserved(tmp_path):
    """`first_seen` is set-once: a later sighting must never overwrite it,
    regardless of whether the incoming value is smaller, larger, or just
    different from the stored one."""
    from api.store import DeviceStore
    s = DeviceStore(str(tmp_path/"d.db"))
    s.upsert({"mac":"aa:bb:cc:00:00:99","first_seen":100,"last_seen":100,"source":"arp"})
    s.upsert({"mac":"aa:bb:cc:00:00:99","first_seen":999,"last_seen":200,"source":"dnsmasq"})
    d = s.get("aa:bb:cc:00:00:99")
    assert d["first_seen"] == 100
    assert d["last_seen"] == 200
    assert d["source"] == "dnsmasq"


def test_migrate_skips_corrupt_sources(tmp_path):
    """A truncated/invalid-JSON legacy file, a non-SQLite garbage file, and
    a missing path must each be logged and skipped — migrate_legacy must
    never raise, and must not leave any stray file behind for a source
    that was never present."""
    import os
    from api.store import DeviceStore, migrate_legacy

    mg = tmp_path/"mg.json"; mg.write_text("{not valid json")
    di = tmp_path/"di.json"; di.write_text("also { not json")
    iot_garbage = tmp_path/"iot_garbage.db"; iot_garbage.write_text("not a sqlite file at all")
    missing_iot = tmp_path/"does_not_exist.db"

    s = DeviceStore(str(tmp_path/"d.db"))

    # Case A: corrupt JSON + garbage sqlite file (both exist on disk already)
    result = migrate_legacy(
        s, macguard_json=str(mg), deviceintel_json=str(di), iot_db=str(iot_garbage)
    )
    assert result == {"imported": 0, "skipped": 3}
    assert s.count() == 0

    # Case B: same corrupt JSON sources, but the iot path is simply absent
    result2 = migrate_legacy(
        s, macguard_json=str(mg), deviceintel_json=str(di), iot_db=str(missing_iot)
    )
    assert result2 == {"imported": 0, "skipped": 3}
    assert s.count() == 0
    assert not os.path.exists(missing_iot)
