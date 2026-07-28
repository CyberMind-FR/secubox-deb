# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit exec-watch daemon runner (thin runner, v1)

Tails `ausearch -k sbx_exec` for the sbx_exec-tagged audit records (see
conf/99-sbx-procwatch.rules), parses them via api.execwatch.parse_ausearch,
and feeds each batch to api.execwatch.run_once() which jails any
unknown/unbacked executable via `sudo -n secubox-antirootkitctl jail <pid>`
(cgroup.jail_pid) and appends every decision to the forensic ExecLog.

This module intentionally stays minimal: the decision/parsing logic lives in
api/execwatch.py (Task 4/5/6); this file only wires stdlib polling around it
so it can run as a systemd service (systemd/sbx-antirootkitd.service).
"""

from __future__ import annotations

import subprocess
import time

from api import execwatch
from api.allowlist import load as load_allowlist
from api.cgroup import jail_pid
from api.dpkg_backing import is_backed_cached
from api.execlog import ExecLog

CONF_PATH = "/etc/secubox/antirootkit.toml"
DB_PATH = "/var/lib/secubox/antirootkit/execlog.db"
POLL_SECONDS = 5


def _ausearch_since(checkpoint: str) -> str:
    """Return raw ausearch text for sbx_exec events since `checkpoint`
    (an ausearch -ts value); never raises — degrades to empty output."""
    try:
        r = subprocess.run(
            ["ausearch", "-k", "sbx_exec", "-ts", checkpoint, "-i"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return r.stdout or ""
    except Exception:
        return ""


def main() -> None:
    allow = load_allowlist(CONF_PATH)
    log = ExecLog(DB_PATH, check_same_thread=True)
    checkpoint = "recent"

    while True:
        text = _ausearch_since(checkpoint)
        events = execwatch.parse_ausearch(text) if text else []
        if events:
            execwatch.run_once(
                events,
                allow,
                is_backed_cached,
                jail_pid,
                lambda ev, verdict: log.record(
                    ev, verdict, pkg=None if verdict == "jail" else "dpkg"
                ),
            )
        checkpoint = "recent"
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
