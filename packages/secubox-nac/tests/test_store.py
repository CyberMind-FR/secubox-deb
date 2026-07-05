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
    assert s.count() == 2  # :02 (merged mg+iot) and :03
    d = s.get("aa:bb:cc:00:00:02")
    assert d["oui_vendor"] == "V" and d["device_type"] == "phone"  # cross-source merge
    r2 = migrate_legacy(s, macguard_json=str(mg), deviceintel_json=str(di), iot_db=str(iot))
    assert s.count() == 2  # re-run no-op
