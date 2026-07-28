# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-antirootkit :: api/daemon.py tests (ref #915 review)

Covers the poll cursor (each audit record processed exactly once even when
successive ausearch windows overlap or are byte-for-byte identical) and the
daemon -> AlertStore wiring on jail (a real SQLite-backed AlertStore, per
tmp_path, standing in for the real cross-process /var/lib/secubox/
antirootkit/alerts.db — see tests/test_alertstore.py for the dedicated
cross-process proof).
"""

from api import execwatch
from api.alertstore import AlertStore
from api.daemon import make_log_fn, poll_once
from api.execlog import ExecLog

EV1 = (
    'type=SYSCALL msg=audit(1785200000.100:42): arch=c00000b7 syscall=221 '
    'success=yes exit=0 ppid=1 pid=999 uid=0 exe="/tmp/x" key="sbx_exec"\n'
    'type=EXECVE msg=audit(1785200000.100:42): argc=1 a0="x"'
)
EV2 = (
    'type=SYSCALL msg=audit(1785200000.200:43): arch=c00000b7 syscall=221 '
    'success=yes exit=0 ppid=1 pid=1000 uid=0 exe="/tmp/y" key="sbx_exec"\n'
    'type=EXECVE msg=audit(1785200000.200:43): argc=1 a0="y"'
)


def test_poll_once_same_window_twice_processes_new_events_only_once():
    """The old bug: checkpoint reset to "recent" every loop meant the exact
    same ausearch window was re-fetched and re-handled forever. Feeding the
    identical raw text twice must only call handle_fn on the first poll."""
    batches = []

    def fetch(cursor):
        return EV1 + "\n" + EV2  # same fixed window, regardless of cursor

    cursor = None
    cursor = poll_once(fetch, execwatch.parse_ausearch, batches.append, cursor)
    assert len(batches) == 1
    assert {ev.pid for ev in batches[0]} == {999, 1000}

    # Second poll: fetch returns the SAME text again (as a real overlapping
    # ausearch -ts window would). Nothing new must be handled.
    cursor2 = poll_once(fetch, execwatch.parse_ausearch, batches.append, cursor)
    assert len(batches) == 1  # handle_fn was NOT called again
    assert cursor2 == cursor


def test_poll_once_overlapping_window_only_handles_the_new_event():
    def fetch_first(cursor):
        return EV1

    def fetch_second(cursor):
        # Overlapping window: repeats EV1, adds EV2.
        return EV1 + "\n" + EV2

    batches = []
    cursor = poll_once(fetch_first, execwatch.parse_ausearch, batches.append, None)
    assert len(batches) == 1
    assert [ev.pid for ev in batches[0]] == [999]

    cursor = poll_once(fetch_second, execwatch.parse_ausearch, batches.append, cursor)
    assert len(batches) == 2
    assert [ev.pid for ev in batches[1]] == [1000]  # only the NEW event


def test_poll_once_no_events_keeps_cursor_and_never_calls_handle():
    calls = []
    cursor = poll_once(lambda c: "", execwatch.parse_ausearch, calls.append, None)
    assert calls == []
    assert cursor is None


def test_poll_once_advances_cursor_to_latest_ts_serial():
    cursor = poll_once(
        lambda c: EV1 + "\n" + EV2, execwatch.parse_ausearch, lambda evs: None, None
    )
    assert cursor == (1785200000.200, 43)


def test_make_log_fn_records_and_alerts_on_jail(tmp_path):
    log = ExecLog(str(tmp_path / "execlog.db"))
    astore = AlertStore(str(tmp_path / "alerts.db"))
    log_fn = make_log_fn(log, astore)

    ev = execwatch.ExecEvent(pid=7, ppid=1, uid=0, exe="/tmp/evil", argv=[], success=True)
    log_fn(ev, "jail")

    assert log.count() == 1
    alerts = astore.recent()
    assert len(alerts) == 1
    assert alerts[0]["exe"] == "/tmp/evil"


def test_make_log_fn_does_not_alert_on_allow(tmp_path):
    log = ExecLog(str(tmp_path / "execlog.db"))
    astore = AlertStore(str(tmp_path / "alerts.db"))
    log_fn = make_log_fn(log, astore)

    ev = execwatch.ExecEvent(pid=1, ppid=1, uid=0, exe="/usr/bin/yacy", argv=[], success=True)
    log_fn(ev, "allow")

    assert log.count() == 1
    assert astore.recent() == []


def test_daemon_jails_unknown_proc_and_alert_names_its_exe(tmp_path):
    """End-to-end (minus subprocess/cgroup): run_once() over a batch
    produced by poll_once() must both log the jail AND leave an alert in
    the shared AlertStore naming the jailed exe — closing the /alerts
    stub (see test_alertstore.py for proof this store is visible across
    two independent connections, i.e. across the daemon/API process
    boundary)."""
    log = ExecLog(str(tmp_path / "execlog.db"))
    astore = AlertStore(str(tmp_path / "alerts.db"))
    log_fn = make_log_fn(log, astore)

    jailed = []

    def handle(events):
        execwatch.run_once(events, set(), lambda p: False, jailed.append, log_fn)

    poll_once(lambda c: EV1, execwatch.parse_ausearch, handle, None)

    assert jailed == [999]
    names = [a["exe"] for a in astore.recent()]
    assert "/tmp/x" in names
