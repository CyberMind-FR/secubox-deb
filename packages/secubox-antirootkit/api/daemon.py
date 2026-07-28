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

import os
import subprocess
import time

from api import execwatch
from api.alerts import build_alert
from api.alertstore import AlertStore
from api.allowlist import load as load_allowlist
from api.cgroup import jail_pid
from api.dpkg_backing import is_backed_cached
from api.execlog import ExecLog
from api.policy import load_policy, should_jail

CONF_PATH = "/etc/secubox/antirootkit.toml"
DB_PATH = "/var/lib/secubox/antirootkit/execlog.db"
ALERTS_DB_PATH = "/var/lib/secubox/antirootkit/alerts.db"
CHECKPOINT_PATH = "/var/lib/secubox/antirootkit/ausearch.checkpoint"
POLL_SECONDS = 5

# The daemon reads the audit trail through the scoped-sudo ctl (execscan verb),
# NOT ausearch directly: ausearch must read /etc/audit/auditd.conf (root:root)
# to resolve the rotated log set, so it MUST run as root. A non-root ausearch
# falls back to a single "built-in" log path and silently breaks --checkpoint
# continuity (verified on gk2, 2026-07-28). Same delegation pattern as jail
# (api/cgroup.jail_pid -> sudo ctl). The ctl runs:
#   ausearch --input-logs --checkpoint <CHECKPOINT_PATH> -k sbx_exec -i
CTL = "/usr/sbin/secubox-antirootkitctl"
_EXECSCAN = ["sudo", "-n", CTL, "execscan"]


def _ausearch_since(cursor=None) -> str:
    """Return raw ausearch text for the sbx_exec events NEW since last call.

    Delegates to `sudo -n secubox-antirootkitctl execscan`, which runs
    `ausearch --checkpoint` as root — the purpose-built incremental mode for a
    polling consumer: each call emits only records that appeared since the
    previous call (the checkpoint records the last-seen event + inode) and it
    transparently follows log rotation. This replaced a `-ts` time-window
    approach that proved unworkable on the target (auditd 3.0.9, gk2):
      * plain `ausearch -k` reads nothing — `--input-logs` is mandatory;
      * `-ts <epoch>` is rejected ("Invalid start date");
      * `-ts recent` returns the whole ~10-min window (~30k events at 150/s);
      * running ausearch as the non-root daemon user breaks --checkpoint
        (can't read auditd.conf -> single-log fallback) -> hence the ctl.
    `cursor` is accepted (poll_once passes it) but unused — the checkpoint
    file, not an in-memory cursor, is the durable position and survives daemon
    restarts. poll_once's (ts,serial) de-dup remains a harmless second layer.
    Never raises — degrades to empty output on any failure. rc 10 = "no new
    events" (normal) surfaces as empty stdout, not an error.
    """
    try:
        r = subprocess.run(_EXECSCAN, capture_output=True, text=True, timeout=25)
        return r.stdout or ""
    except Exception:
        return ""


def _seed_checkpoint() -> None:
    """On the very first daemon start (no checkpoint yet), prime the checkpoint
    from ~now so we do NOT replay pre-daemon exec history (up to tens of
    thousands of records). A live scanner is forward-looking; historical execs
    are already in the audit trail. The checkpoint then persists across
    restarts, so this one-time discard never repeats."""
    if os.path.exists(CHECKPOINT_PATH):
        return
    try:
        subprocess.run(_EXECSCAN, capture_output=True, text=True, timeout=30)
    except Exception:
        pass


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


def make_log_fn(log: ExecLog, alert_store: AlertStore):
    """Build the run_once `log_fn`: persists FLAGGED execs (verdict "jail" =
    non-dpkg, non-allowlisted) to the forensic append-only ExecLog and appends
    a lightweight alert to the shared (SQLite-backed, cross-process)
    alert_store — so GET /alerts, served by a SEPARATE process
    (secubox-antirootkit.service, api/main.py), reflects real scanner hits.

    "allow" decisions (dpkg-backed or allowlisted) are NOT persisted: under
    the broad execve audit rule the daemon observes ~150 execs/s, almost all
    legitimate, and recording every one would balloon the ExecLog to millions
    of rows/day with zero forensic value. The ExecLog is the record of
    SUSPICIOUS execs, not a full-system exec journal (auditd keeps the raw
    trail). Alert scoring is intentionally minimal here (the daemon lacks
    heuristics.score()'s inputs); the durable detail is the ExecLog row.

    Note "jail" verdict means FLAGGED, not necessarily jailed: whether a
    flagged exec is actually jailed is the enforcement policy's call
    (api/policy, applied in main()'s jail_fn), independent of this record.
    """

    def _log_fn(ev, verdict: str) -> None:
        if verdict != "jail":
            return
        log.record(ev, verdict, pkg=None)
        alert = build_alert(ev, score=2, reasons=["non-dpkg-exec-flagged"])
        alert_store.append(alert)

    return _log_fn


def make_jail_fn(enforce: bool, jail_dirs):
    """Build run_once's `jail_fn` from the enforcement policy.

    Called (by run_once) with the whole ExecEvent for every FLAGGED exec.
    Actually jails (cgroup + nft egress drop, via api.cgroup.jail_pid) ONLY
    when policy says so — enforce=true AND the executable under a jail_dir.
    In the default alert-only mode this is a no-op: the exec was already
    logged + alerted by log_fn, so the scanner still sees it, but no egress
    is cut. This is what keeps enabling the broad execve rule safe on a
    populated host full of legitimate non-dpkg binaries.
    """

    def _jail_fn(ev) -> None:
        if should_jail(ev.exe, enforce, jail_dirs):
            jail_pid(ev.pid)

    return _jail_fn


def main() -> None:
    allow = load_allowlist(CONF_PATH)
    enforce, jail_dirs = load_policy(CONF_PATH)
    log = ExecLog(DB_PATH, check_same_thread=True)
    alert_store = AlertStore(ALERTS_DB_PATH)
    log_fn = make_log_fn(log, alert_store)
    jail_fn = make_jail_fn(enforce, jail_dirs)
    cursor = None

    _seed_checkpoint()

    def handle(events) -> None:
        execwatch.run_once(events, allow, is_backed_cached, jail_fn, log_fn)

    while True:
        cursor = poll_once(_ausearch_since, execwatch.parse_ausearch, handle, cursor)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
