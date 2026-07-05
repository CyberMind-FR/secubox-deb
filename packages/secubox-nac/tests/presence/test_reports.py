# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — tests for `presence.reports.build_report`/
`run_scheduled` (Project B, Task 7, #820).
"""

import json


def _seed(store):
    store.upsert({
        "id": "wan:1.2.3.4",
        "plane": "wan",
        "identity": "1.2.3.4",
        "provenance": "geo",
        "client_type": "browser",
        "geo_cc": "FR",
        "geo_asn": "AS1234",
        "last_seen": 1_000_000,
        "extra": json.dumps({"host": "<script>alert(1)</script>.example.com", "ua": "curl"}),
    })
    store.upsert({
        "id": "lan:aa:bb:cc:00:00:01",
        "plane": "lan",
        "identity": "aa:bb:cc:00:00:01",
        "device_mac": "aa:bb:cc:00:00:01",
        "provenance": "lan",
        "client_type": "peer",
        "last_seen": 1_000_100,
    })
    store.record_alert("wan", "warn", "bot surge: 3 in last 3600s")


def test_build_report_html(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.reports import build_report

    store = PresenceStore(str(tmp_path / "devices.db"))
    _seed(store)

    out = build_report(store, fmt="html", now=1_000_200)

    assert isinstance(out, bytes)
    assert len(out) > 0
    text = out.decode("utf-8")

    # Per-plane counts present.
    assert "wan" in text and "lan" in text

    # Crafted `<script>` hostname must be ESCAPED, never rendered raw.
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


def test_build_report_empty(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.reports import build_report

    store = PresenceStore(str(tmp_path / "devices.db"))

    out = build_report(store, fmt="html")
    assert isinstance(out, bytes)
    assert len(out) > 0
    assert b"SecuBox Presence Report" in out

    out_text = build_report(store, fmt="text")
    assert isinstance(out_text, bytes)
    assert len(out_text) > 0
    assert b"no presences recorded" in out_text.lower()

    # A None store must never raise either.
    out_none = build_report(None, fmt="html")
    assert isinstance(out_none, bytes)
    assert len(out_none) > 0


class _RecordingMailer:
    def __init__(self, result=True):
        self.result = result
        self.calls = []

    def __call__(self, subject, body, *, to):
        self.calls.append((subject, body, to))
        return self.result


def _write_schedule(path, **kwargs):
    path.write_text(json.dumps(kwargs))


def test_run_scheduled_due_emails(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.reports import run_scheduled

    store = PresenceStore(str(tmp_path / "devices.db"))
    _seed(store)

    schedule_path = tmp_path / "reporter-schedule.json"
    now = 2_000_000
    _write_schedule(
        schedule_path,
        frequency="daily",
        recipient="admin@example.com",
        last_run=now - 90_000,  # > 86400s ago -> due
    )
    mailer = _RecordingMailer(result=True)

    ran = run_scheduled(
        store,
        schedule_path=str(schedule_path),
        mailer_send=mailer,
        now=now,
        state={},
    )

    assert ran is True
    assert len(mailer.calls) == 1
    subject, body, to = mailer.calls[0]
    assert to == "admin@example.com"
    assert "Presence Report" in subject
    assert len(body) > 0

    saved = json.loads(schedule_path.read_text())
    assert saved["last_run"] == now


def test_run_scheduled_not_due(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.reports import run_scheduled

    store = PresenceStore(str(tmp_path / "devices.db"))
    schedule_path = tmp_path / "reporter-schedule.json"
    now = 2_000_000
    _write_schedule(
        schedule_path,
        frequency="daily",
        recipient="admin@example.com",
        last_run=now - 100,  # recent -> not due
    )
    mailer = _RecordingMailer(result=True)

    ran = run_scheduled(
        store, schedule_path=str(schedule_path), mailer_send=mailer, now=now, state={},
    )

    assert ran is False
    assert mailer.calls == []
    saved = json.loads(schedule_path.read_text())
    assert saved["last_run"] == now - 100  # untouched


def test_run_scheduled_missing(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.reports import run_scheduled

    store = PresenceStore(str(tmp_path / "devices.db"))
    schedule_path = tmp_path / "does-not-exist.json"
    mailer = _RecordingMailer(result=True)

    ran = run_scheduled(
        store, schedule_path=str(schedule_path), mailer_send=mailer, now=2_000_000, state={},
    )

    assert ran is False
    assert mailer.calls == []


def test_run_scheduled_mailer_fails_no_advance(tmp_path):
    from api.presence.store import PresenceStore
    from api.presence.reports import run_scheduled

    store = PresenceStore(str(tmp_path / "devices.db"))
    schedule_path = tmp_path / "reporter-schedule.json"
    now = 2_000_000
    original_last_run = now - 90_000
    _write_schedule(
        schedule_path,
        frequency="daily",
        recipient="admin@example.com",
        last_run=original_last_run,
    )
    mailer = _RecordingMailer(result=False)

    ran = run_scheduled(
        store, schedule_path=str(schedule_path), mailer_send=mailer, now=now, state={},
    )

    assert ran is False
    assert len(mailer.calls) == 1  # it DID try to send
    saved = json.loads(schedule_path.read_text())
    assert saved["last_run"] == original_last_run  # NOT advanced -> retries next tick
