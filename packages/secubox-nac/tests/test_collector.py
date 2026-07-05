# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for the background collector (#817 Task 4).
"""


def test_collector_cycle(tmp_path, monkeypatch):
    from api.store import DeviceStore
    from api.collector import Collector
    s = DeviceStore(str(tmp_path / "d.db"))
    import api.collector as C
    monkeypatch.setattr(C, "discover", lambda **k: [{"mac": "aa:bb:cc:00:00:30", "ip": "10.0.0.30", "hostname": "cam", "source": "arp"}])
    events = []
    col = Collector(s, oui_map={}, interval=0)
    col._emit = lambda ev, d: events.append(ev)
    col.cycle_once()
    assert s.count() == 1 and "client_joined" in events
    d = s.get("aa:bb:cc:00:00:30")
    assert d["device_type"] in {"camera", "unknown"}  # classified during enrich
    assert col.snapshot()[0]["mac"] == "aa:bb:cc:00:00:30"


def test_collector_no_dup_join(tmp_path, monkeypatch):
    """A MAC already present in the store on a later cycle must not
    re-fire `client_joined` — only a genuinely new sighting should."""
    from api.store import DeviceStore
    from api.collector import Collector
    s = DeviceStore(str(tmp_path / "d.db"))
    import api.collector as C
    monkeypatch.setattr(C, "discover", lambda **k: [{"mac": "aa:bb:cc:00:00:31", "ip": "10.0.0.31", "hostname": "printer", "source": "dnsmasq"}])
    events = []
    col = Collector(s, oui_map={}, interval=0)
    col._emit = lambda ev, d: events.append(ev)

    col.cycle_once()
    assert events.count("client_joined") == 1

    col.cycle_once()
    assert events.count("client_joined") == 1  # unchanged on the second cycle
    assert s.count() == 1
    assert col.snapshot()[0]["mac"] == "aa:bb:cc:00:00:31"
