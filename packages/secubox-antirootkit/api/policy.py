# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit enforcement policy

Governs whether the daemon merely ALERTS on a flagged (non-dpkg,
non-allowlisted) exec or actually AUTO-JAILS it (cgroup + nft egress drop).

Rationale (verified on gk2, aarch64, audit 1.0.6, 2026-07-28): the only
auditd rule form that reliably records execs is a broad `-S execve` syscall
rule — targeted `-w <dir> -p x` watches do NOT fire on execs of files *within*
the dir, and `-F dir= -S execve` does not filter execve by target path. So the
watcher sees EVERY exec (~150/s on a populated board) and userspace is the
only place scope can be enforced.

Because a populated SecuBox host runs many *legitimate* non-dpkg binaries
(secubox-* helpers in /usr/local, Go tools, …), auto-jailing every non-dpkg
exec would cut their egress and self-inflict an outage. Therefore:

  * enforce = false (DEFAULT)  -> alert-only "process scanner": flagged execs
    are logged + alerted, never jailed. Zero egress risk. Use this to build
    the allowlist from real observed traffic before turning on enforcement.
  * enforce = true             -> auto-jail, but ONLY for flagged execs whose
    executable lives under one of `jail_dirs` (a deliberately narrow set of
    locations where an unknown binary is genuinely suspicious). An exe outside
    every jail_dir is still logged + alerted, never jailed.
"""

import tomllib

# Conservative default jail scope used when the TOML omits `policy.jail_dirs`.
# These are locations where an unknown, non-dpkg executable is genuinely
# suspicious. `/tmp`, `/dev/shm`, `/var/tmp`, `/run` should never host a
# legitimate long-lived binary; `/usr/local/bin`,`/usr/local/sbin`,`/opt` are
# where drop-in malware (e.g. #914 notwork) landed — legitimate SecuBox tools
# there must be covered by the allowlist before enforce is turned on.
DEFAULT_JAIL_DIRS = [
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",
    "/usr/lib/jvm",
    "/home",
]


def load_policy(toml_path: str) -> tuple[bool, list[str]]:
    """Load (enforce, jail_dirs) from the module TOML.

    Fail-safe: any read/parse error, or a missing [policy] table, yields the
    SAFE default (enforce=False, DEFAULT_JAIL_DIRS) — a corrupt config must
    never silently enable auto-jailing.
    """
    try:
        with open(toml_path, "rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return (False, list(DEFAULT_JAIL_DIRS))
    pol = data.get("policy", {})
    enforce = bool(pol.get("enforce", False))
    jail_dirs = pol.get("jail_dirs") or list(DEFAULT_JAIL_DIRS)
    # normalise: strip trailing slashes so prefix matching is unambiguous
    jail_dirs = [d.rstrip("/") for d in jail_dirs if isinstance(d, str) and d]
    return (enforce, jail_dirs)


def under_jail_dir(exe: str, jail_dirs: list[str]) -> bool:
    """True if `exe` resides directly-or-transitively under a jail_dir.

    Uses a path-boundary check ("/usr/local/bin/x" is under "/usr/local/bin"
    but "/usr/local/binary" is NOT under "/usr/local/bin"). A None/empty exe
    is treated as not-under (nothing to jail on).
    """
    if not exe:
        return False
    for d in jail_dirs:
        if exe == d or exe.startswith(d + "/"):
            return True
    return False


def should_jail(exe: str, enforce: bool, jail_dirs: list[str]) -> bool:
    """Whether a flagged exec should be AUTO-JAILED under the active policy.

    Only reached for execs already decided as "jail" (non-dpkg,
    non-allowlisted) by execwatch.decide(). Returns True iff enforcement is on
    AND the executable is under the jail scope.
    """
    return bool(enforce) and under_jail_dir(exe, jail_dirs)
