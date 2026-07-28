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


# auditd emits any field containing a space/quote/control byte UNQUOTED and
# hex-encoded instead of double-quoted (e.g. exe=2F746D702F2E78206576696C for
# "/tmp/.x evil"). Both exe= and aN= must accept EITHER form, or an attacker
# can bypass jailing simply by naming their binary with a space.
_SYS = re.compile(
    r'type=SYSCALL .*?ppid=(\d+) pid=(\d+) .*?uid=(\d+) .*?'
    r'exe=(?:"([^"]*)"|([0-9A-Fa-f]+))'
)
_SUC = re.compile(r'success=(yes|no)')
_A = re.compile(r'a\d+=(?:"([^"]*)"|([0-9A-Fa-f]+))')


def _auditd_field(quoted, hexval):
    """Decode an auditd field that may be double-quoted or hex-encoded."""
    if quoted is not None:
        return quoted
    if hexval:
        try:
            return bytes.fromhex(hexval).decode("utf-8", "surrogateescape")
        except ValueError:
            return hexval
    return None


def parse_ausearch(text: str) -> list:
    """Parse ausearch/auditd raw text into a list of ExecEvent."""
    out = []
    blocks = re.split(r'(?=type=SYSCALL )', text)
    for b in blocks:
        m = _SYS.search(b)
        if not m:
            continue
        suc = _SUC.search(b)
        exe = _auditd_field(m.group(4), m.group(5))
        argv = [_auditd_field(am.group(1), am.group(2)) for am in _A.finditer(b)]
        out.append(
            ExecEvent(
                pid=int(m.group(2)),
                ppid=int(m.group(1)),
                uid=int(m.group(3)),
                exe=exe,
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
    """Process a batch of ExecEvents; jail unknowns; return #jailed.

    Fail-closed: if deciding an event raises (e.g. is_backed_fn blows up),
    the event is treated as unknown ("jail") rather than silently skipped.
    A single event's failure never aborts the rest of the batch.
    """
    n = 0
    for ev in events:
        try:
            d = decide(ev, allow, is_backed_fn)
            log_fn(ev, d)
        except Exception:
            d = "jail"
            log_fn(ev, d)
        if d == "jail" and ev.success:
            jail_fn(ev.pid)
            n += 1
    return n
