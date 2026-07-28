# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-antirootkit :: api/alertstore.py tests

api.alertstore.AlertStore must be visible across TWO SEPARATE processes:
sbx-antirootkitd.service (the daemon, writer) and secubox-antirootkit.service
(the API, reader) are distinct systemd units. A plain in-memory Python list
cannot cross that boundary — the fix is a shared SQLite file, exactly like
api.execlog.ExecLog already does. test_cross_process_visibility below is the
assertion an in-memory store could never make: two INDEPENDENT AlertStore
instances (independent sqlite3 connections) pointed at the same db_path,
standing in for the daemon and the API.
"""

from api.alertstore import MAX_ALERTS, AlertStore


def test_append_and_recent_most_recent_first(tmp_path):
    store = AlertStore(str(tmp_path / "alerts.db"))
    store.append({"exe": "/tmp/a"})
    store.append({"exe": "/tmp/b"})
    assert [a["exe"] for a in store.recent()] == ["/tmp/b", "/tmp/a"]


def test_recent_respects_limit(tmp_path):
    store = AlertStore(str(tmp_path / "alerts.db"))
    for i in range(5):
        store.append({"exe": f"/tmp/{i}"})
    assert len(store.recent(limit=2)) == 2


def test_store_is_capped_at_max_alerts(tmp_path):
    store = AlertStore(str(tmp_path / "alerts.db"))
    for i in range(MAX_ALERTS + 10):
        store.append({"exe": f"/tmp/{i}"})
    all_alerts = store.recent(limit=MAX_ALERTS + 10)
    assert len(all_alerts) == MAX_ALERTS
    # oldest entries were dropped; the most recent one is still present
    assert all_alerts[0]["exe"] == f"/tmp/{MAX_ALERTS + 9}"


def test_clear_empties_the_store(tmp_path):
    store = AlertStore(str(tmp_path / "alerts.db"))
    store.append({"exe": "/tmp/a"})
    store.clear()
    assert store.recent() == []


def test_alert_dict_round_trips_full_shape(tmp_path):
    store = AlertStore(str(tmp_path / "alerts.db"))
    alert = {
        "exe": "/tmp/x",
        "pid": 7,
        "score": 2,
        "reasons": ["non-dpkg-egress-jailed"],
        "dest": None,
        "ioc": False,
    }
    store.append(alert)
    assert store.recent()[0] == alert


def test_cross_process_visibility(tmp_path):
    """The regression this file exists to prevent: a plain module-level
    Python list is a no-op across the daemon/API process boundary (each
    process gets its own copy). Two independent AlertStore instances
    (independent sqlite3 connections — exactly what the daemon process and
    the API process each open) pointed at the SAME db_path must see each
    other's writes."""
    db_path = str(tmp_path / "alerts.db")
    daemon_side = AlertStore(db_path)
    api_side = AlertStore(db_path)

    assert api_side.recent() == []

    daemon_side.append(
        {
            "exe": "/usr/local/bin/notwork-monitoring",
            "pid": 999,
            "score": 2,
            "reasons": ["non-dpkg-egress-jailed"],
            "dest": None,
            "ioc": False,
        }
    )

    seen = api_side.recent()
    assert len(seen) == 1
    assert seen[0]["exe"] == "/usr/local/bin/notwork-monitoring"

    # And the reverse direction, for good measure.
    api_side.append({"exe": "/tmp/other"})
    assert [a["exe"] for a in daemon_side.recent()] == [
        "/tmp/other",
        "/usr/local/bin/notwork-monitoring",
    ]
