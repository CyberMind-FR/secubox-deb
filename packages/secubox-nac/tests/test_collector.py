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
    assert d["first_seen"] is not None  # freshly discovered device gets first_seen set (#817 minor fix 1)


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


def test_run_forever_offloads_cycle_off_the_loop(tmp_path, monkeypatch):
    """#817 whole-branch fix (I2): `run_forever` must run the blocking
    `cycle_once()` in a threadpool executor, NEVER inline on the event
    loop thread — otherwise the shared aggregator loop stalls for every
    cycle (#808). Assert it ran, and always on a thread other than the
    loop thread."""
    import asyncio
    import threading
    from api.store import DeviceStore
    from api.collector import Collector
    import api.collector as C

    s = DeviceStore(str(tmp_path / "d.db"))
    monkeypatch.setattr(C, "discover", lambda **k: [])
    col = Collector(s, oui_map={}, interval=0.01)

    cycle_threads: list[int] = []
    orig_cycle = col.cycle_once

    def tracking_cycle():
        cycle_threads.append(threading.get_ident())
        orig_cycle()

    col.cycle_once = tracking_cycle

    async def drive():
        loop_thread = threading.get_ident()
        task = asyncio.create_task(col.run_forever())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return loop_thread

    loop_thread = asyncio.run(drive())
    assert cycle_threads, "cycle_once never ran"
    assert all(t != loop_thread for t in cycle_threads), "cycle_once ran on the loop thread (not offloaded)"
