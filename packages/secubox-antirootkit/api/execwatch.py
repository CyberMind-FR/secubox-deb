# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit auditd execve watcher

Parses auditd SYSCALL+EXECVE record blocks into ExecEvents, decides
jail-vs-allow using the dpkg-backing resolver and the allowlist, and
processes a batch of events (jailing unknown/unbacked executables).
"""

import re
from dataclasses import dataclass, field

from api.allowlist import allowed


@dataclass
class ExecEvent:
    pid: int
    ppid: int
    uid: int
    exe: str
    argv: list = field(default_factory=list)
    success: bool = True


_SYS = re.compile(r'type=SYSCALL .*?ppid=(\d+) pid=(\d+) .*?uid=(\d+) .*?exe="([^"]+)"')
_SUC = re.compile(r'success=(yes|no)')
_A = re.compile(r'a\d+="([^"]*)"')


def parse_ausearch(text: str) -> list:
    """Parse ausearch/auditd raw text into a list of ExecEvent."""
    out = []
    blocks = re.split(r'(?=type=SYSCALL )', text)
    for b in blocks:
        m = _SYS.search(b)
        if not m:
            continue
        suc = _SUC.search(b)
        argv = _A.findall(b)
        out.append(
            ExecEvent(
                pid=int(m.group(2)),
                ppid=int(m.group(1)),
                uid=int(m.group(3)),
                exe=m.group(4),
                argv=argv,
                success=(suc.group(1) == "yes" if suc else True),
            )
        )
    return out


def decide(ev: ExecEvent, allow: set, is_backed_fn) -> str:
    """Decide jail-vs-allow for an ExecEvent: dpkg-backed or allowlisted -> allow, else jail."""
    if is_backed_fn(ev.exe) or allowed(ev.exe, allow):
        return "allow"
    return "jail"


def run_once(events, allow, is_backed_fn, jail_fn, log_fn) -> int:
    """Process a batch of ExecEvents; jail unknowns; return #jailed."""
    n = 0
    for ev in events:
        d = decide(ev, allow, is_backed_fn)
        log_fn(ev, d)
        if d == "jail" and ev.success:
            jail_fn(ev.pid)
            n += 1
    return n
