# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit heuristics scoring

Pure function to score an exec event for suspicion based on:
- non-dpkg execution paths
- repeated failures (crash-loop pattern)
- silenced restart-always services (notwork-like profile)
"""


SUSPECT_DIRS = ("/usr/local/bin", "/usr/local/sbin", "/tmp", "/dev/shm", "/opt", "/home")


def score(ev, pkg: str | None, unit_flags: dict, failed_count: int) -> tuple[int, list[str]]:
    """
    Score an exec event for suspicion.

    Args:
        ev: ExecEvent (pid, ppid, uid, exe, argv, success)
        pkg: Package name (from dpkg query) or None if not backed
        unit_flags: dict with "restart_always" and "logs_silenced" bools
        failed_count: Number of recent failed execs

    Returns:
        (score: int, reasons: list[str])

    Signals:
        - non-dpkg exec in suspect dirs (+2, "non-dpkg-exec-path")
        - failed_count >= 3 (+2, "crash-loop")
        - restart_always + logs_silenced (+2, "silenced-restart-always")
    """
    s = 0
    reasons = []

    # Signal 1: non-dpkg executable in suspect paths
    if pkg is None and ev.exe.startswith(SUSPECT_DIRS):
        s += 2
        reasons.append("non-dpkg-exec-path")

    # Signal 2: crash-loop (repeated failures)
    if failed_count >= 3:
        s += 2
        reasons.append("crash-loop")

    # Signal 3: silenced restart-always (notwork-like hiding pattern)
    if unit_flags.get("restart_always") and unit_flags.get("logs_silenced"):
        s += 2
        reasons.append("silenced-restart-always")

    return s, reasons
