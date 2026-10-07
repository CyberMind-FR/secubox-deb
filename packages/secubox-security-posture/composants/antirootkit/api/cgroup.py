# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import subprocess

CTL = "/usr/sbin/secubox-antirootkitctl"


def jail_pid(pid: int, runner=subprocess.run) -> bool:
    try:
        r = runner(["sudo", "-n", CTL, "jail", str(pid)], timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def in_jail(pid: int, proc_root: str = "/proc") -> bool:
    try:
        with open(f"{proc_root}/{pid}/cgroup") as fh:
            return "sbx-untrusted.slice" in fh.read()
    except OSError:
        return False
