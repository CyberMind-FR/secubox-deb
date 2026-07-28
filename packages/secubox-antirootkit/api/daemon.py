# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit exec-watch daemon runner (thin runner, v1)

Tails `ausearch -k sbx_exec` for the sbx_exec-tagged audit records (see
conf/99-sbx-procwatch.rules), parses them via api.execwatch.parse_ausearch,
and feeds each NEW batch to api.execwatch.run_once() which jails any
unknown/unbacked executable via `sudo -n secubox-antirootkitctl jail <pid>`
(cgroup.jail_pid) and appends every decision to the forensic ExecLog.

Cursor (ref #915 review fix): each polled event carries the audit record's
own (ts, serial) identity (see api.execwatch.ExecEvent / parse_ausearch).
poll_once() tracks the (ts, serial) of the latest event it has handed to
handle_fn and drops anything at-or-before it BEFORE handle_fn ever sees it.
This guarantees each audit record is processed exactly once no matter how
much two successive `ausearch -ts ...` windows overlap — the previous
version reset the checkpoint to the literal string "recent" every loop,
re-fetching (and therefore re-parsing, re-logging and re-jailing) the same
~10-minute window on every single poll.

This module intentionally stays minimal: the decision/parsing logic lives in
api/execwatch.py (Task 4/5/6); this file only wires stdlib polling around it
so it can run as a systemd service (systemd/sbx-antirootkitd.service).
"""

from __future__ import annotations

import subprocess
import time

from api import alertstore, execwatch
from api.alerts import build_alert
from api.allowlist import load as load_allowlist
from api.cgroup import jail_pid
from api.dpkg_backing import is_backed_cached
from api.execlog import ExecLog

CONF_PATH = "/etc/secubox/antirootkit.toml"
DB_PATH = "/var/lib/secubox/antirootkit/execlog.db"
POLL_SECONDS = 5


def _ausearch_since(cursor) -> str:
    """Return raw ausearch text for sbx_exec events since `cursor`.

    `cursor` is either None (first ever poll: use ausearch's "recent"
    keyword, i.e. its default ~10-minute window) or a (ts, serial) tuple —
    the latest event already handled — in which case we re-query from that
    timestamp. Never raises — degrades to empty output on any ausearch
    failure (missing binary, no perms, etc).

    Note: ausearch's -ts granularity is whole seconds, so the returned
    window may still overlap with the previous poll. That's fine: poll_once
    below is the layer that guarantees each (ts, serial) audit record is
    only ever handled once, regardless of how much these raw windows
    overlap.
    """
    ts_arg = "recent" if cursor is None else str(int(cursor[0]))
    try:
        r = subprocess.run(
            ["ausearch", "-k", "sbx_exec", "-ts", ts_arg, "-i"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return r.stdout or ""
    except Exception:
        return ""


def poll_once(fetch_fn, parse_fn, handle_fn, cursor):
    """Fetch + parse one ausearch batch and hand only NEW events to handle_fn.

    Args:
        fetch_fn: callable(cursor) -> raw ausearch text (injectable; see
            _ausearch_since / tests/test_daemon.py's fake runner)
        parse_fn: callable(text) -> list[ExecEvent] (execwatch.parse_ausearch)
        handle_fn: callable(list[ExecEvent]) -> None, called ONLY with
            events strictly newer than `cursor`; never called with an
            empty list
        cursor: None on the very first poll, else the (ts, serial) tuple
            of the latest event previously handed to handle_fn

    Returns:
        the advanced cursor (unchanged if no new events were found this
        poll — e.g. the fetch returned the exact same window as last time)
    """
    text = fetch_fn(cursor)
    events = parse_fn(text) if text else []

    if cursor is None:
        new_events = list(events)
    else:
        new_events = [
            ev for ev in events if ev.ts is None or (ev.ts, ev.serial or 0) > cursor
        ]

    if not new_events:
        return cursor

    handle_fn(new_events)

    keyed = [(ev.ts, ev.serial or 0) for ev in new_events if ev.ts is not None]
    if not keyed:
        return cursor
    newest = max(keyed)
    return newest if cursor is None else max(cursor, newest)


def make_log_fn(log: ExecLog):
    """Build the run_once `log_fn`: records every decision to the forensic
    ExecLog (unchanged v1 behaviour) and, additionally, appends a
    lightweight alert to the shared alert store whenever a process is
    jailed — so GET /alerts (api/main.py) reflects real anti-escape events
    instead of a permanently-empty stub. Alert scoring is intentionally
    minimal here (the daemon has none of heuristics.score()'s inputs —
    unit_flags, failed_count — cheaply on hand); the durable, detailed
    record stays the ExecLog row itself.
    """

    def _log_fn(ev, verdict: str) -> None:
        log.record(ev, verdict, pkg=None if verdict == "jail" else "dpkg")
        if verdict == "jail":
            alert = build_alert(ev, score=2, reasons=["non-dpkg-egress-jailed"])
            alertstore.append(alert)

    return _log_fn


def main() -> None:
    allow = load_allowlist(CONF_PATH)
    log = ExecLog(DB_PATH, check_same_thread=True)
    log_fn = make_log_fn(log)
    cursor = None

    def handle(events) -> None:
        execwatch.run_once(events, allow, is_backed_cached, jail_pid, log_fn)

    while True:
        cursor = poll_once(_ausearch_since, execwatch.parse_ausearch, handle, cursor)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
