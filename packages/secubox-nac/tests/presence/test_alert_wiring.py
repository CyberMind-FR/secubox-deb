# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for wiring `presence.alerts.evaluate()`/
`load_config()` into the off-loop `Collector.cycle_once()` (#820 whole-branch
review fix C1).

Before this fix, `evaluate`/`load_config` were dead code: nothing in the
production code path (the aggregator-mounted `Collector.run_forever()` ->
`cycle_once()`) ever called them, so the tiered alert engine could never
fire regardless of an operator's `presence-alerts.toml` thresholds. These
tests drive a real `Collector.cycle_once()` (not `alerts.evaluate()` in
isolation, which Task 6's own tests already cover) and assert (a) a fired
condition reaches the mailer/`presence_alerts` table through the real
collector cycle, and (b) the collector's persistent `self._alert_state`
dedup window survives across cycles (a second immediate cycle must not
re-email).
"""
import time


def _seed_bot_surge(presence_store, *, n=3, last_seen=None):
    last_seen = last_seen if last_seen is not None else int(time.time())
    for i in range(n):
        presence_store.upsert({
            "id": f"wan:10.9.0.{i}",
            "plane": "wan",
            "identity": f"10.9.0.{i}",
            "client_type": "bot",
            "last_seen": last_seen,
        })


def test_cycle_once_fires_alert_engine_and_dedupes_across_cycles(tmp_path, monkeypatch):
    from api.store import DeviceStore
    from api.presence.store import PresenceStore
    from api.collector import Collector
    import api.collector as C

    # No real device discovery / wan-log / kbin-catch I/O in this test —
    # only the alert-engine wiring is under test here.
    monkeypatch.setattr(C, "discover", lambda **k: [])

    db_path = str(tmp_path / "devices.db")
    dstore = DeviceStore(db_path)
    pstore = PresenceStore(db_path)
    _seed_bot_surge(pstore)

    config = {
        "recipient": "admin@example.com",
        "window_seconds": 3600,
        "wan": {"bot_surge": 2},
    }
    monkeypatch.setattr(C, "load_config", lambda *a, **k: config)

    sent = []

    def fake_send(subject, body, *, to):
        sent.append((subject, body, to))
        return True

    monkeypatch.setattr(C, "send_alert", fake_send)

    col = Collector(dstore, oui_map={}, interval=0, presence_store=pstore)
    col.cycle_once()

    # (a) the alert reached the real mailer AND was recorded.
    assert len(sent) == 1
    assert sent[0][2] == "admin@example.com"
    assert len(pstore.alerts()) == 1
    assert pstore.alerts()[0]["plane"] == "wan"

    # (b) a second immediate cycle_once() must NOT re-email — the
    # per-(tier,plane) dedup window lives in `col._alert_state`, which is
    # the SAME dict reused across cycles (not reset to {} every call).
    col.cycle_once()
    assert len(sent) == 1  # still just the one send


def test_cycle_once_no_config_means_no_alerts(tmp_path, monkeypatch):
    """Fail-safe preserved: `load_config()` returning `None` (no file on
    disk, the feature's off-switch) must mean zero alerts/emails even
    though a threshold-tripping condition is present in the store."""
    from api.store import DeviceStore
    from api.presence.store import PresenceStore
    from api.collector import Collector
    import api.collector as C

    monkeypatch.setattr(C, "discover", lambda **k: [])

    db_path = str(tmp_path / "devices.db")
    dstore = DeviceStore(db_path)
    pstore = PresenceStore(db_path)
    _seed_bot_surge(pstore)

    monkeypatch.setattr(C, "load_config", lambda *a, **k: None)

    sent = []
    monkeypatch.setattr(C, "send_alert", lambda *a, **k: sent.append(1) or True)

    col = Collector(dstore, oui_map={}, interval=0, presence_store=pstore)
    col.cycle_once()

    assert sent == []
    assert pstore.alerts() == []


def test_cycle_once_alert_evaluate_exception_does_not_crash_cycle(tmp_path, monkeypatch):
    """A raising `evaluate()` (or a raising `load_config`) must never
    propagate out of `cycle_once()` — the collector loop must never die
    (mirrors the existing per-plane collector fail-safe guarantee)."""
    from api.store import DeviceStore
    from api.presence.store import PresenceStore
    from api.collector import Collector
    import api.collector as C

    monkeypatch.setattr(C, "discover", lambda **k: [])

    db_path = str(tmp_path / "devices.db")
    dstore = DeviceStore(db_path)
    pstore = PresenceStore(db_path)

    def raising_load_config(*a, **k):
        raise RuntimeError("config parse blew up")

    monkeypatch.setattr(C, "load_config", raising_load_config)

    col = Collector(dstore, oui_map={}, interval=0, presence_store=pstore)
    col.cycle_once()  # must not raise
