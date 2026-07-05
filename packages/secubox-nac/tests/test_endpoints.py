# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for the absorbed endpoints (#817 Task 6):
vendors, scan, probe, mDNS, groups, export.

All the mac-guard/device-intel subprocess calls (nmap, curl, avahi-browse)
are monkeypatched at their factored-out call points (`_scan_subprocess`,
`_probe_ip`, `_mdns_subprocess`) — no test ever shells out for real. `nft`
is faked the same way `test_actions.py` does, since `/clients` still
resolves zones via `_nft_list_set`.
"""


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
    sets = _fake_nft(monkeypatch, main)
    # Never let a leftover cache entry from another test leak in here.
    main.stats_cache.clear()
    return main, sets


USER = {"sub": "tester"}


# --- /clients?device_type=&risk_min= ---


def test_clients_filters_by_device_type(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)

    main.store.upsert({
        "mac": "aa:bb:cc:00:01:01", "ip": "10.0.0.101", "hostname": "cam1",
        "device_type": "camera", "last_seen": 100, "source": "arp",
    })
    main.store.upsert({
        "mac": "aa:bb:cc:00:01:02", "ip": "10.0.0.102", "hostname": "phone1",
        "device_type": "phone", "last_seen": 100, "source": "arp",
    })

    result = main.clients(device_type="camera", user=USER)

    assert result["count"] == 1
    assert result["clients"][0]["mac"] == "aa:bb:cc:00:01:01"
    assert result["clients"][0]["device_type"] == "camera"


def test_clients_filters_by_risk_min(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)

    main.store.upsert({
        "mac": "aa:bb:cc:00:01:03", "ip": "10.0.0.103", "risk_score": 80,
        "last_seen": 100, "source": "arp",
    })
    main.store.upsert({
        "mac": "aa:bb:cc:00:01:04", "ip": "10.0.0.104", "risk_score": 10,
        "last_seen": 100, "source": "arp",
    })

    result = main.clients(risk_min=50, user=USER)

    assert result["count"] == 1
    assert result["clients"][0]["mac"] == "aa:bb:cc:00:01:03"


# --- /export/json + /export/csv ---


def test_export_json_dumps_all_devices(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)
    main.store.upsert({"mac": "aa:bb:cc:00:02:01", "ip": "10.0.0.1", "last_seen": 1, "source": "arp"})
    main.store.upsert({"mac": "aa:bb:cc:00:02:02", "ip": "10.0.0.2", "last_seen": 2, "source": "arp"})

    result = main.export_json(user=USER)

    assert result["device_count"] == 2
    macs = {d["mac"] for d in result["devices"]}
    assert macs == {"aa:bb:cc:00:02:01", "aa:bb:cc:00:02:02"}


def test_export_csv_header_plus_one_row_per_device(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)
    main.store.upsert({"mac": "aa:bb:cc:00:02:03", "ip": "10.0.0.3", "last_seen": 1, "source": "arp"})
    main.store.upsert({"mac": "aa:bb:cc:00:02:04", "ip": "10.0.0.4", "last_seen": 2, "source": "arp"})

    response = main.export_csv(user=USER)
    body = response.body.decode() if isinstance(response.body, bytes) else response.body
    lines = [l for l in body.splitlines() if l]

    assert lines[0].split(",")[0] == "mac"
    assert len(lines) == 3  # header + 2 devices
    assert "aa:bb:cc:00:02:03" in lines[1] or "aa:bb:cc:00:02:03" in lines[2]


# --- /groups CRUD ---


def test_groups_crud_roundtrip(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)
    main.store.upsert({"mac": "aa:bb:cc:00:03:01", "ip": "10.0.0.10", "last_seen": 1, "source": "arp"})

    created = main.create_group(main.GroupRequest(name="Cameras", color="#ff0000"), user=USER)
    assert created["success"] is True
    group_id = created["group"]["id"]

    listed = main.list_groups(user=USER)
    assert any(g["id"] == group_id and g["name"] == "Cameras" for g in listed["groups"])

    added = main.add_group_member(group_id, main.GroupMemberRequest(mac="AA:BB:CC:00:03:01"), user=USER)
    assert added["success"] is True

    listed2 = main.list_groups(user=USER)
    group = next(g for g in listed2["groups"] if g["id"] == group_id)
    assert "aa:bb:cc:00:03:01" in group["members"]

    deleted = main.delete_group(group_id, user=USER)
    assert deleted["success"] is True

    listed3 = main.list_groups(user=USER)
    assert not any(g["id"] == group_id for g in listed3["groups"])


# --- /vendors ---


def test_vendors_map_size_and_lookup(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "oui_map", {"aa:bb:cc": "Acme Corp"})

    summary = main.vendors(user=USER)
    assert summary["oui_entries"] == 1

    looked_up = main.vendors(mac="AA:BB:CC:00:00:99", user=USER)
    assert looked_up["vendor"] == "Acme Corp"
    assert looked_up["mac"] == "aa:bb:cc:00:00:99"


# --- /scan (nmap mocked, falls back to ARP) ---


def test_scan_merges_nmap_hit_into_store(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)

    monkeypatch.setattr(main, "_scan_subprocess", lambda subnet=main.DEFAULT_SCAN_SUBNET: "Host: 10.0.0.50 ()\tStatus: Up\n")
    monkeypatch.setattr(main, "_parse_arp", lambda: [
        {"mac": "aa:bb:cc:00:04:01", "ip": "10.0.0.50", "hostname": "", "source": "arp"},
        {"mac": "aa:bb:cc:00:04:02", "ip": "10.0.0.51", "hostname": "", "source": "arp"},
    ])

    result = main.scan(user=USER)

    assert result["success"] is True
    assert result["devices_found"] == 1  # only the nmap-confirmed IP
    d = main.store.get("aa:bb:cc:00:04:01")
    assert d is not None and d["ip"] == "10.0.0.50"
    assert main.store.get("aa:bb:cc:00:04:02") is None  # not in the nmap hit set


def test_scan_falls_back_to_arp_when_nmap_empty(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)

    monkeypatch.setattr(main, "_scan_subprocess", lambda subnet=main.DEFAULT_SCAN_SUBNET: "")
    monkeypatch.setattr(main, "_parse_arp", lambda: [
        {"mac": "aa:bb:cc:00:04:03", "ip": "10.0.0.52", "hostname": "", "source": "arp"},
    ])

    result = main.scan(user=USER)

    assert result["devices_found"] == 1
    assert main.store.get("aa:bb:cc:00:04:03") is not None


def test_scan_enriches_before_upsert(tmp_path, monkeypatch):
    """#817 Task 6 review fix 1: a `/scan`-discovered device must land in
    the store with a non-NULL device_type/risk_level — not just the raw
    mac/ip/hostname/last_seen/source columns."""
    main, _ = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "oui_map", {})

    monkeypatch.setattr(main, "_scan_subprocess", lambda subnet=main.DEFAULT_SCAN_SUBNET: "Host: 10.0.0.80 ()\tStatus: Up\n")
    monkeypatch.setattr(main, "_parse_arp", lambda: [
        {"mac": "aa:bb:cc:00:06:01", "ip": "10.0.0.80", "hostname": "hikvision-cam", "source": "arp"},
    ])

    result = main.scan(user=USER)

    assert result["success"] is True
    d = main.store.get("aa:bb:cc:00:06:01")
    assert d is not None
    assert d["device_type"] == "camera"
    assert d["risk_level"] is not None


def test_scan_rejects_invalid_subnet(tmp_path, monkeypatch):
    """#817 Task 6 review fix 2: an argv-injection-shaped or otherwise
    invalid `subnet` must be rejected with 400 before ever reaching the
    `nmap` argv."""
    main, _ = _setup(tmp_path, monkeypatch)

    def _boom(subnet=main.DEFAULT_SCAN_SUBNET):
        raise AssertionError("nmap must never be invoked with an invalid subnet")

    monkeypatch.setattr(main, "_scan_subprocess", _boom)

    try:
        main.scan(subnet="--script=x", user=USER)
        assert False, "expected HTTPException(400)"
    except main.HTTPException as exc:
        assert exc.status_code == 400


# --- /probe/openwrt[/{ip}] (curl mocked) ---


def test_probe_openwrt_updates_matched_devices(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)
    main.store.upsert({"mac": "aa:bb:cc:00:05:01", "ip": "10.0.0.60", "last_seen": 1, "source": "arp"})
    main.store.upsert({"mac": "aa:bb:cc:00:05:02", "ip": "10.0.0.61", "last_seen": 1, "source": "arp"})

    def fake_probe(ip, timeout=2.0):
        if ip == "10.0.0.60":
            return {"luci_detected": True, "secubox_detected": True, "model": "MOCHAbin", "version": "26.0"}
        return {"luci_detected": False, "secubox_detected": False, "model": None, "version": None}

    monkeypatch.setattr(main, "_probe_ip", fake_probe)

    result = main.probe_openwrt(user=USER)

    assert result["total_probed"] == 2
    assert result["openwrt_detected"] == 1
    d = main.store.get("aa:bb:cc:00:05:01")
    assert d["is_openwrt"] == 1 and d["model"] == "MOCHAbin" and d["luci_version"] == "26.0"
    d2 = main.store.get("aa:bb:cc:00:05:02")
    assert d2["is_openwrt"] != 1  # never wrongly set for a non-matching probe


def test_probe_openwrt_single_ip(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)
    main.store.upsert({"mac": "aa:bb:cc:00:05:03", "ip": "10.0.0.62", "last_seen": 1, "source": "arp"})

    monkeypatch.setattr(
        main, "_probe_ip",
        lambda ip, timeout=2.0: {"luci_detected": True, "secubox_detected": False, "model": "GL-MT3000", "version": "23.05"},
    )

    result = main.probe_openwrt_single("10.0.0.62", user=USER)

    assert result["mac"] == "aa:bb:cc:00:05:03"
    assert result["luci_detected"] is True
    d = main.store.get("aa:bb:cc:00:05:03")
    assert d["is_openwrt"] == 1 and d["model"] == "GL-MT3000"


def test_probe_openwrt_single_rejects_non_ip(tmp_path, monkeypatch):
    """#817 Task 6 review fix 3 (SSRF): a non-IP `ip` path param must be
    rejected with 400 before it ever reaches `_probe_ip` -> `curl`."""
    main, _ = _setup(tmp_path, monkeypatch)

    def _boom(ip, timeout=2.0):
        raise AssertionError("curl must never be invoked with a non-IP target")

    monkeypatch.setattr(main, "_probe_ip", _boom)

    try:
        main.probe_openwrt_single("{ip}", user=USER)
        assert False, "expected HTTPException(400)"
    except main.HTTPException as exc:
        assert exc.status_code == 400


# --- /mdns (avahi-browse mocked) ---


def test_mdns_parses_avahi_browse_output(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)
    canned = "=;eth0;IPv4;My Printer;_http._tcp;local;printer.local;10.0.0.70;80;\n"
    monkeypatch.setattr(main, "_mdns_subprocess", lambda: canned)

    result = main.mdns(user=USER)

    assert result["total"] == 1
    assert result["services"][0]["hostname"] == "printer.local"
    assert result["services"][0]["ip"] == "10.0.0.70"


# --- /export/csv formula-injection guard ---


def test_export_csv_neutralizes_formula_injection(tmp_path, monkeypatch):
    """#817 Task 6 review fix 4: a device whose hostname is attacker-chosen
    (e.g. `=cmd()`) must not export as a bare spreadsheet formula."""
    import csv as _csv
    import io as _io

    main, _ = _setup(tmp_path, monkeypatch)
    main.store.upsert({
        "mac": "aa:bb:cc:00:07:01", "ip": "10.0.0.90",
        "hostname": "=cmd()", "last_seen": 1, "source": "arp",
    })

    response = main.export_csv(user=USER)
    body = response.body.decode() if isinstance(response.body, bytes) else response.body

    rows = list(_csv.reader(_io.StringIO(body)))
    header = rows[0]
    hostname_idx = header.index("hostname")
    device_row = next(r for r in rows[1:] if r[header.index("mac")] == "aa:bb:cc:00:07:01")

    assert not device_row[hostname_idx].startswith("=")
    assert device_row[hostname_idx] == "'=cmd()"
