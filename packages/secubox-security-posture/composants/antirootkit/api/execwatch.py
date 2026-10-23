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
    # Audit record identity (msg=audit(ts:serial)) — None for hand-built
    # events (tests, etc). Used by the daemon's poll cursor (Task 915 fix)
    # to tell exactly which events were already processed, independent of
    # how much two successive ausearch windows overlap.
    ts: float | None = None
    serial: int | None = None
    # auid (uid de connexion, 4294967295 = « unset » pour un démon) et étiquette AppArmor du processus (`subj=`) :
    # c'est l'étiquette qui dit qu'une exécution vient d'un conteneur LXC (#3058).
    auid: int | None = None
    subj: str | None = None

    @property
    def conteneur(self) -> bool:
        """Exécution vue DEPUIS un conteneur LXC : son chemin (`/usr/bin/php8.2`) n'existe pas sur l'hôte, dpkg ne
        peut donc rien en dire. Reconnue à l'étiquette AppArmor `lxc-container-default…` ou `lxc-<nom>_<…>` ; les
        outils de l'hôte (`lxc-attach`, `lxc-start`…) portent un profil nommé d'après eux, sans suffixe : exclus."""
        return bool(self.subj and _CONTENEUR.match(self.subj))


# auditd emits any field containing a space/quote/control byte UNQUOTED and
# hex-encoded instead of double-quoted (e.g. exe=2F746D702F2E78206576696C for
# "/tmp/.x evil"). Both exe= and aN= must accept EITHER form, or an attacker
# can bypass jailing simply by naming their binary with a space.
# `\buid=` et non `uid=` : l'expression `.*?uid=` s'arrêtait sur `auid=` (4294967295, « unset ») et le journal
# affichait cette valeur à la place de l'uid réel (#3058).
_SYS = re.compile(
    r'type=SYSCALL .*?ppid=(\d+) pid=(\d+) (?:.*?\bauid=(\d+) )?.*?\buid=(\d+) .*?'
    r'exe=(?:"([^"]*)"|([0-9A-Fa-f]+))'
)
_SUBJ = re.compile(r'\bsubj=(\S+)')
_CONTENEUR = re.compile(r'^lxc-(?:container-default\S*|[^\s_]+_<\S*)$')
_SUC = re.compile(r'success=(yes|no)')
_A = re.compile(r'a\d+=(?:"([^"]*)"|([0-9A-Fa-f]+))')
# msg=audit(TS:SERIAL) is the audit record's unique identity. Each block
# (split on `(?=type=SYSCALL )`) starts with the SYSCALL line, so the FIRST
# match in the block is always the SYSCALL record's own timestamp:serial,
# even though the EXECVE line further down repeats the same audit(...) pair.
_TS = re.compile(r'msg=audit\((\d+(?:\.\d+)?):(\d+)\)')


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
        exe = _auditd_field(m.group(5), m.group(6))
        sj = _SUBJ.search(b)
        argv = [_auditd_field(am.group(1), am.group(2)) for am in _A.finditer(b)]
        tsm = _TS.search(b)
        out.append(
            ExecEvent(
                pid=int(m.group(2)),
                ppid=int(m.group(1)),
                uid=int(m.group(4)),
                exe=exe,
                argv=argv,
                success=(suc.group(1) == "yes" if suc else True),
                ts=float(tsm.group(1)) if tsm else None,
                serial=int(tsm.group(2)) if tsm else None,
                auid=int(m.group(3)) if m.group(3) else None,
                subj=sj.group(1) if sj else None,
            )
        )
    return out


def decide(ev: ExecEvent, allow: set, is_backed_fn) -> str:
    """Decide for an ExecEvent: container -> conteneur (ni signalé ni jailé, compté par le pouls); dpkg-backed or
    allowlisted -> allow, else jail."""
    if ev.conteneur:
        return "conteneur"
    if is_backed_fn(ev.exe) or allowed(ev.exe, allow):
        return "allow"
    return "jail"


def run_once(events, allow, is_backed_fn, jail_fn, log_fn) -> int:
    """Process a batch of ExecEvents; hand flagged ones to jail_fn; return
    the count handed over.

    jail_fn is called with the whole ExecEvent (not just the pid) so the
    caller's enforcement policy (api/policy: enforce flag + jail_dirs) can
    decide, from the executable path, whether to actually jail. A jail_fn
    that alert-only-mode passes may choose to do nothing; the count returned
    still reflects how many events reached the "jail" verdict.

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
            jail_fn(ev)
            n += 1
    return n
