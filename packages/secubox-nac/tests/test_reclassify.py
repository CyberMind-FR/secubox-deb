# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for the `reclassify_all()` backfill
(#820, ref #817 Task 2/2b): re-runs `classify_device_type`/`risk_score`
for every stored device and resolves `source` from a live discovery
merge, replacing stale legacy-module tags.
"""


def test_reclassify_backfills_unknown_devices(tmp_path, monkeypatch):
    from api.store import DeviceStore
    import api.enrich as E

    monkeypatch.setattr(E, "discover", lambda **k: [])

    s = DeviceStore(str(tmp_path / "d.db"))
    s.upsert({
        "mac": "aa:bb:cc:00:10:01", "hostname": "living-room-camera",
        "oui_vendor": "Hikvision", "last_seen": 1, "source": "mac-guard",
    })
    s.upsert({
        "mac": "aa:bb:cc:00:10:02", "hostname": "random-host",
        "oui_vendor": "NoVendor", "last_seen": 1, "source": "mac-guard",
    })

    result = E.reclassify_all(s)
    assert result["total"] == 2
    # Both rows change: the camera gets device_type/risk backfilled, and
    # BOTH legacy-tagged rows get source relabelled 'mac-guard' -> 'imported'
    # (neither is visible in this cycle's empty discovery merge).
    assert result["changed"] == 2
    assert result["skipped"] == 0

    cam = s.get("aa:bb:cc:00:10:01")
    assert cam["device_type"] == "camera"
    assert cam["risk_score"] is not None
    assert cam["risk_level"] in {"low", "medium", "high"}

    unk = s.get("aa:bb:cc:00:10:02")
    assert unk["device_type"] == "unknown"  # no hostname/vendor signal -> stays unknown


def test_reclassify_idempotent(tmp_path, monkeypatch):
    from api.store import DeviceStore
    import api.enrich as E

    monkeypatch.setattr(E, "discover", lambda **k: [])

    s = DeviceStore(str(tmp_path / "d.db"))
    s.upsert({
        "mac": "aa:bb:cc:00:10:03", "hostname": "kitchen-echo",
        "oui_vendor": "Amazon", "last_seen": 1, "source": "device-intel",
    })

    r1 = E.reclassify_all(s)
    assert r1["changed"] == 1

    r2 = E.reclassify_all(s)
    assert r2["changed"] == 0  # re-run with no new data is a no-op

    d = s.get("aa:bb:cc:00:10:03")
    assert d["device_type"] == "smart_speaker"
    assert d["source"] == "imported"  # legacy tag, not seen live -> imported


def test_reclassify_never_regresses_good_classification_to_unknown(tmp_path, monkeypatch):
    """A device already classified by legacy migration (e.g. iot-guard's
    device_type='phone') whose hostname/vendor no longer match any
    indicator must NOT be downgraded to 'unknown' — the omit-on-unknown
    rule (mirroring Collector/upsert) must preserve it."""
    from api.store import DeviceStore
    import api.enrich as E

    monkeypatch.setattr(E, "discover", lambda **k: [])

    s = DeviceStore(str(tmp_path / "d.db"))
    s.upsert({
        "mac": "aa:bb:cc:00:10:04", "hostname": "opaque-hostname",
        "device_type": "phone", "risk_score": 40, "risk_level": "low",
        "last_seen": 1, "source": "iot-guard",
    })

    result = E.reclassify_all(s)
    d = s.get("aa:bb:cc:00:10:04")
    assert d["device_type"] == "phone"  # preserved, not clobbered to unknown
    assert result["skipped"] == 0


def test_reclassify_resolves_source_from_live_discovery(tmp_path, monkeypatch):
    """A device present in the live dnsmasq/isc/arp merge gets its
    `source` updated to the live value, even if it carries a legacy tag."""
    from api.store import DeviceStore
    import api.enrich as E

    monkeypatch.setattr(E, "discover", lambda **k: [
        {"mac": "aa:bb:cc:00:10:05", "ip": "10.0.0.5", "hostname": "office-printer", "source": "dnsmasq"},
    ])

    s = DeviceStore(str(tmp_path / "d.db"))
    s.upsert({
        "mac": "aa:bb:cc:00:10:05", "hostname": "office-printer",
        "oui_vendor": "HP", "last_seen": 1, "source": "mac-guard",
    })

    result = E.reclassify_all(s)
    assert result["changed"] == 1
    d = s.get("aa:bb:cc:00:10:05")
    assert d["source"] == "dnsmasq"
    assert d["device_type"] == "printer"


def test_reclassify_legacy_tag_absent_from_discovery_becomes_imported(tmp_path, monkeypatch):
    """A legacy-tagged device NOT seen in the live discovery merge is
    relabelled 'imported' — it can no longer be attributed a live source."""
    from api.store import DeviceStore
    import api.enrich as E

    monkeypatch.setattr(E, "discover", lambda **k: [])

    s = DeviceStore(str(tmp_path / "d.db"))
    s.upsert({
        "mac": "aa:bb:cc:00:10:06", "hostname": "old-device",
        "last_seen": 1, "source": "iot-guard",
    })

    E.reclassify_all(s)
    d = s.get("aa:bb:cc:00:10:06")
    assert d["source"] == "imported"


def test_reclassify_non_legacy_source_absent_from_discovery_unchanged(tmp_path, monkeypatch):
    """A device already carrying a live-style source (e.g. 'arp') that is
    simply not seen in THIS discovery cycle must be left alone — only
    legacy-module tags get relabelled 'imported' on a miss."""
    from api.store import DeviceStore
    import api.enrich as E

    monkeypatch.setattr(E, "discover", lambda **k: [])

    s = DeviceStore(str(tmp_path / "d.db"))
    s.upsert({
        "mac": "aa:bb:cc:00:10:07", "hostname": "old-device",
        "last_seen": 1, "source": "arp",
    })

    result = E.reclassify_all(s)
    d = s.get("aa:bb:cc:00:10:07")
    assert d["source"] == "arp"  # unchanged


def test_reclassify_failsafe_discover_raising(tmp_path, monkeypatch):
    """`discover()` raising must never abort the backfill — legacy tags
    still resolve to 'imported', exactly as if discovery had returned []."""
    from api.store import DeviceStore
    import api.enrich as E

    def _boom(**k):
        raise OSError("no ip binary")

    monkeypatch.setattr(E, "discover", _boom)

    s = DeviceStore(str(tmp_path / "d.db"))
    s.upsert({
        "mac": "aa:bb:cc:00:10:08", "hostname": "hall-thermostat",
        "last_seen": 1, "source": "mac-guard",
    })

    result = E.reclassify_all(s)
    assert result["skipped"] == 0
    d = s.get("aa:bb:cc:00:10:08")
    assert d["device_type"] == "smart_home"
    assert d["source"] == "imported"


def test_reclassify_router_known_true_scores_low(tmp_path, monkeypatch):
    """#817 addendum (Task 10) mirrored in the backfill: every row is
    already IN the store, so `is_known=True` -> a router backfilled here
    is trusted infra, LOW risk (never the rogue-AP HIGH path)."""
    from api.store import DeviceStore
    import api.enrich as E

    monkeypatch.setattr(E, "discover", lambda **k: [])

    s = DeviceStore(str(tmp_path / "d.db"))
    s.upsert({
        "mac": "aa:bb:cc:00:10:09", "hostname": "edgerouter-x",
        "last_seen": 1, "source": "mac-guard",
    })

    E.reclassify_all(s)
    d = s.get("aa:bb:cc:00:10:09")
    assert d["device_type"] == "router"
    assert d["risk_level"] == "low"
