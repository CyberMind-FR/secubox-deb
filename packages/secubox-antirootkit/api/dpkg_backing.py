# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: antirootkit dpkg backing resolver
"""

import subprocess
from functools import lru_cache

# merged-usr (bookworm): /bin,/sbin,/lib,/lib64 are symlinks into /usr, but
# dpkg records file ownership under the OLD path (e.g. it owns /bin/grep, not
# /usr/bin/grep). The kernel/audit reports the REAL resolved path
# (/usr/bin/grep), so `dpkg -S /usr/bin/grep` returns "no path found" and a
# perfectly legitimate system binary looks non-dpkg-backed. We must therefore
# try BOTH aliased forms before concluding a path is unbacked. Without this
# the scanner floods with false positives on ordinary /usr/bin execs.
_USR_ALIASES = (
    ("/usr/bin/", "/bin/"),
    ("/usr/sbin/", "/sbin/"),
    ("/usr/lib/", "/lib/"),
    ("/usr/lib64/", "/lib64/"),
)


def _merged_usr_candidates(path: str):
    """Yield `path` and its merged-usr alias (both /usr and non-/usr forms)."""
    yield path
    for usr, plain in _USR_ALIASES:
        if path.startswith(usr):
            yield plain + path[len(usr):]
            return
        if path.startswith(plain):
            yield usr + path[len(plain):]
            return


def _dpkg_search(path: str, runner) -> str | None:
    try:
        r = runner(["dpkg", "-S", path], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    if r.returncode != 0 or not r.stdout:
        return None
    # "pkg: /path"  (diversions -> "pkg, other: /path"; take first pkg token)
    head = r.stdout.splitlines()[0].split(":", 1)[0]
    return head.split(",", 1)[0].strip() or None


def resolve_pkg(path: str, runner=subprocess.run) -> str | None:
    """Return the dpkg package owning `path`, or None if not dpkg-backed.

    Tries the path and its merged-usr alias so that /usr/bin/grep resolves via
    dpkg's recorded /bin/grep (and vice versa).
    """
    if not path:
        return None
    for candidate in _merged_usr_candidates(path):
        pkg = _dpkg_search(candidate, runner)
        if pkg is not None:
            return pkg
    return None


def is_backed(path: str, runner=subprocess.run) -> bool:
    """Check if a path is owned by a dpkg package."""
    return resolve_pkg(path, runner=runner) is not None


@lru_cache(maxsize=4096)
def is_backed_cached(path: str) -> bool:
    """Cached version of is_backed using default subprocess.run."""
    return is_backed(path)
